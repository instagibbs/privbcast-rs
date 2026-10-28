//! A job's discovery: QUERIES_PER_SEED query sets, each one RESOLVE query of every DNS seed's bare
//! name through the proxy, all launched at job start (D1, R1). Each query has a stream and a thread
//! of its own, with its set's credentials (B2). A query whose thread cannot be started is skipped;
//! one whose stream fails ends without an answer. An answer counts only if it reaches the job
//! before the discovery window ends, and is usable only as an address R2 accepts, which gets the
//! chain's default port. Discovery ends when every query has ended or when the window ends,
//! whatever is pending (C3); the queries still running then give up within LOOP_WAIT.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use crate::addr::{Addr, Endpoint};
use crate::assign::{DiscoveryResult, SeedAnswers};
use crate::log::debug;
use crate::params::*;
use crate::plan::Plan;
use crate::rng::Rng;
use crate::socks5::{Command, Credentials, Socks5Client};
use crate::stream::{self, Proxy};

/// How a query ended: the proxy's answer, None if it was not an IPv4 or IPv6 address; or why the
/// stream failed.
type QueryResult = Result<Option<Addr>, String>;

/// Run discovery on this thread: launch every query now, unless now is QUERY_GRACE or more after
/// job start (D1), and collect the answers until every query has ended, the window ends, or
/// `stopped` says the job is stopping (C8). Returns what it found; its duration is when it ended.
pub fn run(
    plan: &Plan,
    proxy: &Proxy,
    default_port: u16,
    rng: &mut Rng,
    start: Instant,
    stopped: &mut dyn FnMut() -> bool,
) -> DiscoveryResult {
    let now = || start.elapsed().as_millis() as Ms;
    let mut seeds: Vec<SeedAnswers> = plan
        .seed_order
        .iter()
        .map(|name| SeedAnswers { name: name.clone(), skipped: QUERIES_PER_SEED as u32, ..Default::default() })
        .collect();
    let window_end = plan.timing.scale(DISCOVERY_WINDOW);
    let until = start + Duration::from_millis(window_end as u64);
    let over = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<(usize, QueryResult)>();
    let mut queries = Vec::new();
    if now() < plan.timing.scale(QUERY_GRACE) {
        // The credentials of each query set, shared by its queries and nothing else (B2).
        let credentials: Vec<Credentials> = (0..QUERIES_PER_SEED).map(|_| Credentials::draw(rng)).collect();
        let stage_timeout = Duration::from_millis(plan.timing.scale(SOCKS_STAGE_TIMEOUT) as u64);
        for (index, seed) in seeds.iter_mut().enumerate() {
            for (set, creds) in credentials.iter().enumerate() {
                let id = queries.len();
                // The bare name, one query per stream (B2).
                let socks = Socks5Client::new(Command::Resolve, &seed.name, 0, creds.clone());
                let (proxy, over, tx) = (proxy.clone(), over.clone(), tx.clone());
                let spawned = std::thread::Builder::new().name("privbcast-query".into()).spawn(move || {
                    let result = match stream::open(&proxy, socks, stage_timeout, until, &over) {
                        Ok(open) => Ok(open.socks.answer().flatten()),
                        Err(reason) => Err(reason),
                    };
                    let _ = tx.send((id, result));
                });
                if let Err(e) = spawned {
                    debug(format_args!("Cannot query {}: {e}", seed.name));
                    continue;
                }
                queries.push((index, set));
                seed.queries += 1;
                seed.skipped -= 1;
            }
        }
    }
    drop(tx);
    debug(format_args!("Discovery: {} queries of {} DNS seeds started", queries.len(), seeds.len()));
    let mut pending = queries.len();
    // With no query under way, discovery is over (C3).
    let mut end = now();
    while pending > 0 {
        if stopped() {
            end = now();
            break;
        }
        // Nothing is acted on at or after the end of the window (C3, D2).
        let received = rx.recv_timeout(stream::slice(until));
        end = now();
        if end >= window_end {
            end = window_end;
            break;
        }
        let (id, result) = match received {
            Ok(r) => r,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            // Every query thread has finished: one that panicked sent nothing, and its query ended
            // without an answer (C7).
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        pending -= 1;
        let (index, set) = queries[id];
        let seed = &mut seeds[index];
        match result {
            Ok(answer) => {
                // Only an address R2 accepts is usable, whatever it is (R6).
                match answer {
                    Some(addr) if addr.is_routable() => seed.usable[set] = Some(Endpoint { addr, port: default_port }),
                    _ => seed.rejected += 1,
                }
                seed.answers += 1;
            }
            Err(reason) => debug(format_args!("Query of {} through {proxy} failed: {reason}", seed.name)),
        }
    }
    over.store(true, Ordering::Relaxed);
    debug(format_args!("Discovery ended at {end} ms"));
    DiscoveryResult { seeds, duration: end }
}
