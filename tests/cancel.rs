//! Cancellation (C8) and failure paths of a whole job, against a fake proxy in this process: it
//! answers every RESOLVE with a public address and holds every CONNECT open without a word.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use privbcast::attempt::TxData;
use privbcast::chain;
use privbcast::job::{Job, JobInputs};
use privbcast::params::Timing;
use privbcast::report::Report;
use privbcast::stream::Proxy;

const SEEDS: [&str; 7] = ["a.test.", "b.test.", "c.test.", "d.test.", "e.test.", "f.test.", "g.test."];

/// Serve one stream: the SOCKS5 exchange, then silence until the client closes.
fn serve(mut s: TcpStream, resolve_delay: Duration, answered: Arc<AtomicUsize>) {
    let mut buf = [0u8; 512];
    let read = |s: &mut TcpStream, n: usize| -> Option<Vec<u8>> {
        let mut out = vec![0u8; n];
        s.read_exact(&mut out).ok()?;
        Some(out)
    };
    let Some(g) = read(&mut s, 2) else { return };
    if read(&mut s, g[1] as usize).is_none() || s.write_all(&[5, 2]).is_err() {
        return;
    }
    let Some(a) = read(&mut s, 2) else { return };
    let Some(_user) = read(&mut s, a[1] as usize) else { return };
    let Some(plen) = read(&mut s, 1) else { return };
    if read(&mut s, plen[0] as usize).is_none() || s.write_all(&[1, 0]).is_err() {
        return;
    }
    let Some(head) = read(&mut s, 5) else { return };
    if read(&mut s, head[4] as usize + 2).is_none() {
        return;
    }
    if head[1] == 0xF0 {
        std::thread::sleep(resolve_delay);
        let n = answered.fetch_add(1, Ordering::Relaxed) as u8;
        let _ = s.write_all(&[5, 0, 0, 1, 11, n / 16, n % 16, 1, 0, 0]);
        return;
    }
    let _ = s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
}

fn fake_proxy(resolve_delay: Duration) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let answered = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let answered = answered.clone();
            std::thread::spawn(move || serve(s, resolve_delay, answered));
        }
    });
    Proxy::Tcp(addr)
}

/// Run a job on `proxy` with durations divided by 20, cancelling it `cancel_after` after start.
/// Returns the report and when the cancel was set and the report came, from job start.
fn run(proxy: Proxy, cancel_after: Option<Duration>) -> (Report, Duration, Duration) {
    let cancel = Arc::new(AtomicBool::new(false));
    let inputs = JobInputs {
        tx: Arc::new(TxData { bytes: vec![1, 2, 3], wtxid: [7; 32] }),
        txid: "00".into(),
        wtxid: "00".into(),
        proxy,
        chain: &chain::REGTEST,
        dns_seeds: SEEDS.iter().map(|s| s.to_string()).collect(),
        timing: Timing::new(20).unwrap(),
        cancel: Some(cancel.clone()),
    };
    let start = Instant::now();
    let job = std::thread::spawn(move || Job::new(inputs).run());
    let mut cancelled_at = Duration::ZERO;
    if let Some(after) = cancel_after {
        std::thread::sleep(after);
        cancelled_at = start.elapsed();
        cancel.store(true, Ordering::Relaxed);
    }
    let report = job.join().unwrap();
    (report, cancelled_at, start.elapsed())
}

#[test]
fn cancel_during_delivery() {
    // Delivery starts at 600 ms; the prompt slots' attempts are then blocked waiting for a peer that
    // never speaks, and their handshake deadline is 2,250 ms after their start.
    let (report, cancelled_at, ended) = run(fake_proxy(Duration::ZERO), Some(Duration::from_millis(1500)));
    let s = &report.summary;
    assert!(s.interrupted);
    assert_eq!(s.error, None);
    assert_eq!(s.slots_completed, 0);
    assert!(
        ended - cancelled_at < Duration::from_millis(400),
        "the job ended {:?} after the cancel",
        ended - cancelled_at
    );
    let cancel_ms = cancelled_at.as_millis() as i64;
    let attempts: Vec<_> = report.slots.iter().flat_map(|slot| &slot.attempts).collect();
    // The three prompt slots were dialling; the later slots had not started.
    assert_eq!(attempts.len(), 3, "{:?}", attempts.iter().map(|a| &a.reason).collect::<Vec<_>>());
    for a in attempts {
        assert_eq!(a.reason, "interrupted");
        assert!(a.times.connected.is_some());
        let ended = a.times.ended.unwrap();
        assert!(ended >= cancel_ms && ended < cancel_ms + 300, "ended at {ended} ms, cancelled at {cancel_ms} ms");
    }
    assert!(report.slots.iter().all(|slot| slot.interrupted));
}

#[test]
fn cancel_during_discovery() {
    // RESOLVE answers take 400 ms; the cancel comes at 100 ms.
    let (report, cancelled_at, ended) = run(fake_proxy(Duration::from_millis(400)), Some(Duration::from_millis(100)));
    assert!(report.summary.interrupted);
    assert_eq!(report.summary.connections, 0);
    assert!(
        ended - cancelled_at < Duration::from_millis(300),
        "the job ended {:?} after the cancel",
        ended - cancelled_at
    );
    assert!(report.discovery.duration < 300);
}

#[test]
fn proxy_refuses_connections() {
    // Nothing listens: every query fails at once, and the job fails when discovery ends (D2).
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let (report, _, ended) = run(Proxy::Tcp(port), None);
    assert_eq!(report.summary.error.as_deref(), Some("no candidates"));
    assert!(!report.summary.interrupted);
    assert_eq!(report.summary.connections, 0);
    assert!(ended < Duration::from_millis(500), "{ended:?}");
    assert!(report.discovery.seeds.iter().all(|s| s.queries == 4 && s.answers == 0));
}
