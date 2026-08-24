use crate::AppConfig;
use arrayvec::ArrayVec;
use shenango::udp::UdpSpawner;
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddrV4;
use std::slice;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::Connection;
use crate::FakeWorker;
use crate::Payload;
use crate::KBUFSIZE;
use crate::PAYLOAD_SIZE;

use std::io;

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
                    worker.work(payload.work_iterations, payload.randomness as u64);
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
    let mut v = vec![0; PAYLOAD_SIZE];
    let mut r = || {
        socket.read_exact(&mut v[..PAYLOAD_SIZE])?;
        let mut payload = Payload::deserialize(&mut &v[..PAYLOAD_SIZE])?;
        v.clear();
        worker.work(payload.work_iterations, payload.randomness as u64);
        payload.randomness = shenango::rdtsc() as u32;
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

const RXLAT_SUB: u32 = 3; // 8 linear sub-buckets per octave (~±12% resolution)
const RXLAT_NB: usize = 256;
const RXLAT_MAXK: usize = 64; // per-kthread shards (avoid cross-core false-sharing on hot buckets)
const RXLAT_NAMES: [&str; 4] = ["cq_wait", "stack", "runq_wait", "service"];
static RXLAT_HIST: [[[AtomicU64; RXLAT_NB]; 4]; RXLAT_MAXK] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    const ROW: [AtomicU64; RXLAT_NB] = [Z; RXLAT_NB];
    const PERK: [[AtomicU64; RXLAT_NB]; 4] = [ROW; 4];
    [PERK; RXLAT_MAXK]
};
// HDR-style bucket: msb selects the octave, the RXLAT_SUB bits below it select a linear sub-bucket.
#[inline]
fn rxlat_bucket(ns: u64) -> usize {
    let v = ns.max(1);
    let msb = 63 - v.leading_zeros();
    let b = if msb < RXLAT_SUB {
        v as usize
    } else {
        (((msb - RXLAT_SUB + 1) as usize) << RXLAT_SUB)
            + ((v >> (msb - RXLAT_SUB)) & ((1u64 << RXLAT_SUB) - 1)) as usize
    };
    b.min(RXLAT_NB - 1)
}
// inverse: lower edge (ns) of bucket b
fn rxlat_lo_ns(b: usize) -> u64 {
    let s = 1usize << RXLAT_SUB;
    if b < s {
        b as u64
    } else {
        let msb = (b >> RXLAT_SUB) + RXLAT_SUB as usize - 1;
        (1u64 << msb) + (((b & (s - 1)) as u64) << (msb - RXLAT_SUB as usize))
    }
}
#[inline]
fn rxlat_rec(k: usize, stage: usize, ns: u64) {
    RXLAT_HIST[k][stage][rxlat_bucket(ns)].fetch_add(1, Ordering::Relaxed);
}
fn rxlat_report() {
    for s in 0..4 {
        // sum + reset across per-kthread shards (per-interval)
        let mut c = [0u64; RXLAT_NB];
        for k in 0..RXLAT_MAXK {
            for b in 0..RXLAT_NB {
                let v = RXLAT_HIST[k][s][b].load(Ordering::Relaxed);
                if v > 0 {
                    RXLAT_HIST[k][s][b].fetch_sub(v, Ordering::Relaxed);
                    c[b] += v;
                }
            }
        }
        let n: u64 = c.iter().sum();
        if n == 0 {
            continue;
        }
        let pct = |p: f64| -> f64 {
            let t = (n as f64 * p / 100.0) as u64;
            let mut seen = 0u64;
            for (b, &v) in c.iter().enumerate() {
                seen += v;
                if seen >= t {
                    return rxlat_lo_ns(b) as f64 / 1000.0;
                }
            }
            f64::INFINITY
        };
        println!(
            "{:<9} n={:<8} p50={:.1} p99={:.1} p99.9={:.1} us",
            RXLAT_NAMES[s], n, pct(50.0), pct(99.0), pct(99.9)
        );
    }
    // batch-size distribution seen by mlx5_gather_rx (per-interval): avg + exact percentiles
    let cur: [u64; 33] = unsafe { shenango::ffi::rxlat_burst_hist };
    static BURST_PREV: [AtomicU64; 33] = { const Z: AtomicU64 = AtomicU64::new(0); [Z; 33] };
    let d: [u64; 33] = std::array::from_fn(|i| cur[i] - BURST_PREV[i].swap(cur[i], Ordering::Relaxed));
    let n: u64 = d.iter().sum();
    if n > 0 {
        let avg = d.iter().enumerate().map(|(i, &v)| i as u64 * v).sum::<u64>() as f64 / n as f64;
        let bpct = |p: f64| {
            let t = (n as f64 * p / 100.0) as u64;
            d.iter().scan(0u64, |s, &v| { *s += v; Some(*s) }).position(|c| c >= t).unwrap_or(32)
        };
        println!("burst     avg={:.1} p50={} p99={} p99.9={} calls={}",
            avg, bpct(50.0), bpct(99.0), bpct(99.9), n);
    }
    println!("===============");
}

pub fn run_spawner_server(addr: SocketAddrV4, workerspec: &str) {
    static mut SPAWNER_WORKER: Option<FakeWorker> = None;
    unsafe {
        SPAWNER_WORKER = Some(FakeWorker::create(workerspec).unwrap());
    }
    // start the runtime STAT responder (port 40) so counters can be queried
    let _ = unsafe { shenango::ffi::stat_init_late() };
    extern "C" fn echo(d: *mut shenango::ffi::udp_spawn_data) {
        unsafe {
            let t_run = shenango::rdtsc();
            let (cqw, poll, ready) = ((*d).cq_wait_us, (*d).rx_poll_tsc, (*d).ready_tsc);
            let buf = slice::from_raw_parts((*d).buf as *mut u8, (*d).len as usize);
            let mut payload = Payload::deserialize(&mut &buf[..]).unwrap();
            #[allow(static_mut_refs)]
            let worker = SPAWNER_WORKER.as_ref().unwrap();
            worker.work(payload.work_iterations, payload.randomness as u64);
            payload.randomness = shenango::rdtsc() as u32;
            /* echo the request's padding so the reply mirrors its size */
            let mut array = ArrayVec::<_, 1472>::new();
            payload.serialize_into(&mut array).unwrap();
            array.try_extend_from_slice(&buf[PAYLOAD_SIZE..]).unwrap();
            let _ = UdpSpawner::reply(d, array.as_slice());
            UdpSpawner::release_data(d);
            let t_done = shenango::rdtsc();
            let cpu = shenango::ffi::cycles_per_us as u64;
            let ns = |c: u64| c * 1000 / cpu;
            let k = shenango::kthread_id().min(RXLAT_MAXK - 1);
            rxlat_rec(k, 0, cqw as u64 * 1000);
            rxlat_rec(k, 1, ns(ready.saturating_sub(poll)));
            rxlat_rec(k, 2, ns(t_run.saturating_sub(ready)));
            rxlat_rec(k, 3, ns(t_done.saturating_sub(t_run)));
        }
    }

    let _s = unsafe { UdpSpawner::new(addr, echo).unwrap() };

    shenango::thread::spawn_detached(|| loop {
        shenango::sleep(Duration::from_secs(1));
        rxlat_report();
    });

    let wg = shenango::WaitGroup::new();
    wg.add(1);
    wg.wait();
}
