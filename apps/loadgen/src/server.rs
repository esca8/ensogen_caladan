use crate::AppConfig;
use arrayvec::ArrayVec;
use shenango::udp::{UdpConnection, UdpSpawner};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
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

/// Processes one received request: runs the fake work and echoes the reply back
/// to the sender. Mirrors the spawner's `echo`:
/// deserialize -> work -> re-serialize -> reply.
fn process_packet(c: &UdpConnection, req: &[u8], from: SocketAddrV4, worker: &FakeWorker) {
    static WORK_COUNT: AtomicU64 = AtomicU64::new(0);
    static WORK_TOTAL_CYCLES: AtomicU64 = AtomicU64::new(0);
    static WORK_MIN_CYCLES: AtomicU64 = AtomicU64::new(u64::MAX);
    static WORK_MAX_CYCLES: AtomicU64 = AtomicU64::new(0);

    let payload = Payload::deserialize(&mut &req[..]).unwrap();
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
    let _ = c.write_to(array.as_slice(), from);
}

/// One persistent worker uthread owning exactly one UDP socket (one
/// connection), bound to `base_port + index`. It blocks on the socket -- parking
/// natively on the socket's wait queue when idle and waking on each datagram --
/// then echoes the reply. This is the 1 uthread <-> 1 connection mirror of a
/// Hermes `run_echo` uthread with a single queue.
fn hermes_worker(index: usize, ip: Ipv4Addr, base_port: u16, worker: Arc<FakeWorker>) {
    let port = base_port + index as u16;
    let c = UdpConnection::listen(SocketAddrV4::new(ip, port))
        .unwrap_or_else(|e| panic!("worker {} failed to bind port {}: {}", index, port, e));
    println!("worker {} bound port {}", index, port);

    let mut buf = vec![0u8; KBUFSIZE];
    loop {
        let (len, from) = match c.read_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        process_packet(&c, &buf[..len], from, &worker);
    }
}

/// Hermes-style UDP server: pre-spawns a fixed pool of `nb_uthreads` persistent
/// worker uthreads, each owning exactly one UDP socket (one connection) on its
/// own port. The runtime demultiplexes datagrams to the right socket by
/// destination port (3-tuple), so it is one persistent uthread per connection
/// with no per-packet thread spawn. Sockets are bound to ports
/// `base_port .. base_port + nb_uthreads - 1`.
pub fn run_hermes_style_udp_server(config: AppConfig) {
    let base_addr = config.addrs[0];
    let ip = *base_addr.ip();
    let base_port = base_addr.port();
    let nb_uthreads = config.nb_uthreads.max(1);

    println!(
        "running hermes-style udp server | addr={} nb_uthreads={} ports={}-{} server_stats={} log_runtime_stats={} log_runtime_bursts={}",
        base_addr, nb_uthreads, base_port,
        base_port + nb_uthreads as u16 - 1,
        config.server_stats, config.log_runtime_stats, config.log_runtime_bursts
    );
    SERVER_STATS_ENABLED.store(config.server_stats, Relaxed);
    unsafe {
        shenango::ffi::runtime_set_log_runtime_stats(config.log_runtime_stats);
        shenango::ffi::runtime_set_log_runtime_bursts(config.log_runtime_bursts);
    }

    let worker = config.fakeworker();

    // Pre-spawn workers 1..nb_uthreads, then run worker 0 inline (it loops
    // forever), mirroring Hermes' main_fn which spawns the rest and runs index 0.
    for index in 1..nb_uthreads {
        let w = worker.clone();
        config
            .backend
            .spawn_thread(move || hermes_worker(index, ip, base_port, w));
    }
    hermes_worker(0, ip, base_port, worker);
}
