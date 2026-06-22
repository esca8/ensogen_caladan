use crate::AppConfig;
use arrayvec::ArrayVec;
use shenango::udp::UdpSpawner;
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddrV4;
use std::slice;
use std::sync::Arc;

use crate::Connection;
use crate::FakeWorker;
use crate::Payload;
use crate::KBUFSIZE;
use crate::PAYLOAD_SIZE;

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

static SERVER_STATS_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn run_linux_udp_server(config: AppConfig) {
    let worker = config.fakeworker();
    let backend = config.backend;
    let addr = config.addrs[0];
    let join_handles: Vec<_> = (0..config.nthreads)
        .map(|_| {
            let worker = worker.clone();
            backend.spawn_thread(move || {
                let socket = backend.create_udp_connection(Some(addr), None).unwrap();
                println!("Bound to address {}", socket.local_addr());
                let mut buf = vec![0; KBUFSIZE];
                loop {
                    let (len, remote_addr) = socket.recv_from(&mut buf[..]).unwrap();
                    let payload = Payload::deserialize(&mut &buf[..len]).unwrap();
                    worker.work(payload.work_iterations, shenango::rdtsc());
                    socket.send_to(&buf[..len], remote_addr).unwrap();
                }
            })
        })
        .collect();

    for j in join_handles {
        j.join().unwrap();
    }
}

fn socket_worker(socket: &mut Connection, worker: Arc<FakeWorker>) {
    // Note: socket_worker is not on UDP path (TCP only)
    let mut v = vec![0; PAYLOAD_SIZE];
    let mut r = || {
        socket.read_exact(&mut v[..PAYLOAD_SIZE])?;
        let mut payload = Payload::deserialize(&mut &v[..PAYLOAD_SIZE])?;
        v.clear();
        worker.work(payload.work_iterations, shenango::rdtsc());
        payload.randomness = shenango::rdtsc();
        payload.serialize_into(&mut v)?;
        Ok(socket.write_all(&v[..])?)
    };
    loop {
        if let Err(e) = r() as io::Result<()> {
            match e.raw_os_error() {
                Some(-104) | Some(104) => break,
                _ => {}
            }
            if e.kind() != ErrorKind::UnexpectedEof {
                println!("Receive thread: {}", e);
            }
            break;
        }
    }
}

pub fn run_tcp_server(config: AppConfig) {
    let backend = config.backend;
    let addr = config.addrs[0];
    let worker = config.fakeworker();
    let tcpq = backend.create_tcp_listener(addr).unwrap();
    println!("Bound to address {}", addr);
    loop {
        match tcpq.accept() {
            Ok(mut c) => {
                let worker = worker.clone();
                backend.spawn_thread(move || socket_worker(&mut c, worker));
            }
            Err(e) => {
                println!("Listener: {}", e);
            }
        }
    }
}

pub fn run_spawner_server(
    addr: SocketAddrV4,
    workerspec: &str,
    num_spawners: usize,
    server_stats: bool,
    log_runtime_stats: bool,
    log_runtime_bursts: bool,
) {
    println!(
        "running spawner server | addr={} num_spawners={} server_stats={} log_runtime_stats={} log_runtime_bursts={}",
        addr, num_spawners, server_stats, log_runtime_stats, log_runtime_bursts
    );
    SERVER_STATS_ENABLED.store(server_stats, Relaxed);
    unsafe { shenango::ffi::runtime_set_log_runtime_stats(log_runtime_stats); }
    unsafe { shenango::ffi::runtime_set_log_runtime_bursts(log_runtime_bursts); }
    static mut SPAWNER_WORKER: Option<FakeWorker> = None;
    static WORK_COUNT: AtomicU64 = AtomicU64::new(0);
    static WORK_TOTAL_CYCLES: AtomicU64 = AtomicU64::new(0);
    static WORK_MIN_CYCLES: AtomicU64 = AtomicU64::new(u64::MAX);
    static WORK_MAX_CYCLES: AtomicU64 = AtomicU64::new(0);
    unsafe {
        SPAWNER_WORKER = Some(FakeWorker::create(workerspec).unwrap());
    }
    extern "C" fn echo(d: *mut shenango::ffi::udp_spawn_data) {
        unsafe {
            let buf = slice::from_raw_parts((*d).buf as *mut u8, (*d).len as usize);
            let mut payload = Payload::deserialize(&mut &buf[..]).unwrap();
            #[allow(static_mut_refs)]
            let worker = SPAWNER_WORKER.as_ref().unwrap();
            if SERVER_STATS_ENABLED.load(Relaxed) {
                let start = shenango::rdtsc();
                worker.work(payload.work_iterations, payload.randomness);
                let elapsed = shenango::rdtsc() - start;
                WORK_TOTAL_CYCLES.fetch_add(elapsed, Relaxed);
                WORK_MIN_CYCLES.fetch_min(elapsed, Relaxed);
                WORK_MAX_CYCLES.fetch_max(elapsed, Relaxed);
                let count = WORK_COUNT.fetch_add(1, Relaxed) + 1;
                if count % 100000 == 0 {
                    println!("work stats: count={} mean={} min={} max={} last={} last_iters={}, rand={}",
                        count, WORK_TOTAL_CYCLES.load(Relaxed) / count,
                        WORK_MIN_CYCLES.load(Relaxed), WORK_MAX_CYCLES.load(Relaxed),
                        elapsed, payload.work_iterations, payload.randomness);
                }
            } else {
                worker.work(payload.work_iterations, payload.randomness);
            }
            let mut array = ArrayVec::<_, PAYLOAD_SIZE>::new();
            payload.serialize_into(&mut array).unwrap();
            let _ = UdpSpawner::reply(d, array.as_slice()); // TODO: why is d's ip addr 0.0.0.1 inside reply()
            UdpSpawner::release_data(d);
        }
    }

    let mut spawners = Vec::new();
    let base_port = addr.port();
    let ip = addr.ip();
    for i in 0..num_spawners {
        let port = base_port + i as u16;
        let spawner_addr = SocketAddrV4::new(*ip, port);
        println!("Creating spawner {} on port {}", i, port);
        let s = unsafe { UdpSpawner::new(spawner_addr, echo).unwrap() };
        spawners.push(s);
    }
    println!("All {} spawners created on ports {}-{}", num_spawners, base_port, base_port + (num_spawners as u16 - 1));

    let wg = shenango::WaitGroup::new();
    wg.add(1);
    wg.wait();
}
