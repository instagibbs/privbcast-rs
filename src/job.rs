//! One private broadcast of one transaction: discovery, the slots' opportunities as the plan
//! schedules them, and the report.
//!
//! The plan is drawn when the job is made, before any socket exists (C1). Discovery runs first;
//! delivery starts at the end of the discovery window, with the candidates fixed when discovery
//! ended (C2, C3). Each slot then runs on a thread of its own (C7): it waits for each opportunity's
//! scheduled time and runs the attempt there, a sans-IO state machine driven with blocking reads
//! and writes whose timeouts end at its next deadline (C4-C6, D2). The job's thread waits for the
//! slots and watches for cancellation and the cap, which it signals through one flag that no
//! thread leaves unchecked for longer than LOOP_WAIT (C8). A panic while running an attempt ends
//! only that attempt (C7). The job ends with its last slot, or when discovery ends if it found no
//! candidate, failed with "no candidates" (D2).
//!
//! The schedule, the deadlines and the report's times are offsets from job start on the steady
//! clock, so a step of the wall clock changes nothing (D2's wall-clock caveats do not apply).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::{All, Secp256k1};

use crate::assign::{Assignment, Candidate, assign};
use crate::attempt::{Attempt, TxData};
use crate::chain::Chain;
use crate::discovery;
use crate::log::{self, debug};
use crate::msg;
use crate::params::*;
use crate::plan::{Plan, SlotSchedule, draw_plan};
use crate::report::{AttemptReport, DiscoveryReport, Report, SlotReport, Summary};
use crate::rng::Rng;
use crate::socks5::{Command, Credentials, Socks5Client};
use crate::stream::{self, Conn, Proxy};

/// The most read from a recipient at a time.
const READ_SIZE: usize = 64 * 1024;

/// What a job works from, besides the clock and fresh randomness (A1).
pub struct JobInputs {
    pub tx: Arc<TxData>,
    /// As the report shows them.
    pub txid: String,
    pub wtxid: String,
    /// The SOCKS5 proxy that every stream goes through (B1).
    pub proxy: Proxy,
    pub chain: &'static Chain,
    /// The chain's DNS seeds, or the regtest override.
    pub dns_seeds: Vec<String>,
    pub timing: Timing,
    /// Set by the owner to cancel the job (C8).
    pub cancel: Option<Arc<AtomicBool>>,
}

/// What every slot thread shares.
struct Shared {
    tx: Arc<TxData>,
    proxy: Proxy,
    magic: [u8; 4],
    timing: Timing,
    start: Instant,
    secp: Secp256k1<All>,
    /// The job is stopping: every attempt ends now, and no opportunity starts after (C8).
    stop: AtomicBool,
}

impl Shared {
    fn now(&self) -> Ms {
        self.start.elapsed().as_millis() as Ms
    }

    fn at(&self, offset: Ms) -> Instant {
        self.start + Duration::from_millis(offset.max(0) as u64)
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Wait until `offset` after job start. False if the job is stopping.
    fn sleep_until(&self, offset: Ms) -> bool {
        loop {
            if self.stopping() {
                return false;
            }
            let left = stream::slice(self.at(offset));
            if left.is_zero() {
                return true;
            }
            std::thread::sleep(left);
        }
    }
}

/// What a slot did.
#[derive(Default)]
struct SlotOutcome {
    missed: usize,
    /// The attempts, in the order they were dialled.
    attempts: Vec<AttemptReport>,
    /// It ran to its end: the job did not stop it first.
    completed: bool,
}

pub struct Job {
    inputs: JobInputs,
    rng: Rng,
    start: Instant,
    plan: Plan,
}

impl Job {
    /// Job start is now. The plan is drawn here, before anything else (C1).
    pub fn new(inputs: JobInputs) -> Job {
        let start = Instant::now();
        let mut rng = Rng::new();
        let plan = draw_plan(&mut rng, inputs.timing, &inputs.dns_seeds);
        Job { inputs, rng, start, plan }
    }

    /// Run the job to its end on this thread and return its report.
    pub fn run(mut self) -> Report {
        let start = self.start;
        let cancel = self.inputs.cancel.clone();
        // Cancellation by the owner, or the cap (D2): both end the job as cancelled.
        let cancelled = move || {
            cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) || start.elapsed().as_millis() as Ms >= JOB_CAP
        };
        let result = discovery::run(
            &self.plan,
            &self.inputs.proxy,
            self.inputs.chain.default_port,
            &mut self.rng,
            start,
            &mut || cancelled(),
        );
        let assignment = assign(&self.plan, &result);
        let discovery_duration = result.duration;
        let mut outcomes: Vec<SlotOutcome> = (0..SLOTS).map(|_| SlotOutcome::default()).collect();
        let (mut interrupted, mut error) = (false, None);
        if cancelled() {
            interrupted = true;
        } else if assignment.exit_path_candidates == 0 {
            // With no candidate there is nothing to dial: the job ends now, visibly, rather than
            // waiting out a schedule that cannot send (D2).
            error = Some("no candidates".to_string());
        } else {
            let mut secp = Secp256k1::new();
            secp.seeded_randomize(&self.rng.bytes());
            let shared = Arc::new(Shared {
                tx: self.inputs.tx.clone(),
                proxy: self.inputs.proxy.clone(),
                magic: self.inputs.chain.magic,
                timing: self.plan.timing,
                start,
                secp,
                stop: AtomicBool::new(false),
            });
            let mut threads = Vec::with_capacity(SLOTS);
            for index in 0..SLOTS {
                let (shared, schedule) = (shared.clone(), self.plan.slots[index].clone());
                let candidates = assignment.opportunities[index].clone();
                // Each slot draws its keys, nonces and credentials from a generator of its own.
                let rng = Rng::from_key(self.rng.bytes());
                let spawned = std::thread::Builder::new()
                    .name("privbcast-slot".into())
                    .spawn(move || run_slot(&shared, index, &schedule, &candidates, rng));
                match spawned {
                    Ok(thread) => threads.push(Some(thread)),
                    Err(e) => {
                        debug(format_args!("Slot {index} cannot start: {e}"));
                        threads.push(None);
                    }
                }
            }
            while threads.iter().flatten().any(|t| !t.is_finished()) {
                if !interrupted && cancelled() {
                    debug(format_args!("The job is stopping"));
                    interrupted = true;
                    shared.stop.store(true, Ordering::Relaxed);
                }
                // Short, so that the job's end is timed closely; the slots do the waiting.
                std::thread::sleep(Duration::from_millis(5));
            }
            for (index, thread) in threads.into_iter().enumerate() {
                // A slot thread that panicked outside an attempt reports nothing.
                if let Some(Ok(outcome)) = thread.map(|t| t.join()) {
                    outcomes[index] = outcome;
                } else {
                    debug(format_args!("Slot {index} failed"));
                }
            }
        }
        self.finish(assignment, discovery_duration, outcomes, interrupted, error)
    }

    /// Make the report.
    fn finish(
        self,
        assignment: Assignment,
        discovery_duration: Ms,
        outcomes: Vec<SlotOutcome>,
        interrupted: bool,
        error: Option<String>,
    ) -> Report {
        let now = self.start.elapsed().as_millis() as Ms;
        let mut summary = Summary { interrupted, error, duration: now, ..Default::default() };
        let mut slots = Vec::with_capacity(SLOTS);
        for (i, outcome) in outcomes.into_iter().enumerate() {
            summary.slots_completed += outcome.completed as u32;
            for a in &outcome.attempts {
                summary.connections += 1;
                summary.announcements_handed += a.times.inv_handed.is_some() as u32;
                summary.announcements_written += a.times.inv_written.is_some() as u32;
                summary.tx_written += a.times.tx_written.is_some() as u32;
                summary.pongs += a.times.pong.is_some() as u32;
            }
            slots.push(SlotReport {
                schedule: self.plan.slots[i].clone(),
                empty_opportunities: assignment.opportunities[i].iter().filter(|c| c.is_none()).count(),
                missed_opportunities: outcome.missed,
                // Stopped by cancellation rather than run to its end (a failed job stops none).
                interrupted: interrupted && !outcome.completed,
                attempts: outcome.attempts,
            });
        }
        debug(format_args!(
            "Job ended at {now} ms: {} connections, {} announcements written",
            summary.connections, summary.announcements_written
        ));
        Report {
            txid: self.inputs.txid,
            wtxid: self.inputs.wtxid,
            chain: self.inputs.chain.name.into(),
            discovery: DiscoveryReport {
                duration: discovery_duration,
                seeds: assignment.seeds,
                duplicates: assignment.duplicates,
                rejected: assignment.rejected,
                exit_path_candidates: assignment.exit_path_candidates,
            },
            slots,
            summary,
        }
    }
}

/// A slot's thread: each opportunity at its scheduled time. One without a candidate ends then; one
/// the slot reaches more than START_GRACE late is missed, never dialled (C5). After the
/// announcement point nothing else in the slot runs (C6).
fn run_slot(
    shared: &Shared,
    index: usize,
    schedule: &SlotSchedule,
    candidates: &[Option<Candidate>],
    mut rng: Rng,
) -> SlotOutcome {
    let mut outcome = SlotOutcome::default();
    for (k, candidate) in candidates.iter().enumerate() {
        let at = schedule.scheduled[k];
        if !shared.sleep_until(at) {
            return outcome;
        }
        let Some(candidate) = candidate else { continue };
        let now = shared.now();
        if now > at + shared.timing.scale(START_GRACE) {
            outcome.missed += 1;
            debug(format_args!("Slot {index}: opportunity {k} missed, {} ms late", now - at));
            continue;
        }
        let report = run_attempt(shared, index, k, at, candidate, &mut rng);
        let announced = report.times.inv_handed.is_some();
        outcome.attempts.push(report);
        if shared.stopping() {
            return outcome;
        }
        if announced {
            break;
        }
    }
    outcome.completed = true;
    outcome
}

/// Dial the candidate and run the attempt to its end. Fresh BIP324 keys, nonces and proxy
/// credentials for every attempt (A4, B2).
fn run_attempt(
    shared: &Shared,
    index: usize,
    k: usize,
    scheduled: Ms,
    candidate: &Candidate,
    rng: &mut Rng,
) -> AttemptReport {
    let started = shared.now();
    let mut attempt = Attempt::new(shared.tx.clone(), scheduled, shared.timing, rng, &shared.secp, shared.magic);
    let endpoint = candidate.endpoint;
    let socks =
        Socks5Client::new(Command::Connect, &endpoint.addr.socks5_host(), endpoint.port, Credentials::draw(rng));
    debug(format_args!(
        "Slot {index}: dialling {} from {}, opportunity {k}",
        log::addr(&endpoint),
        candidate.provenance
    ));
    // A panic while acting on the attempt ends only the attempt, as a failed stream would (C7).
    let ran = catch_unwind(AssertUnwindSafe(|| connect_and_drive(shared, &mut attempt, socks)));
    if ran.is_err() {
        attempt.connection_failed(shared.now(), "internal error".into());
    }
    debug(format_args!(
        "Slot {index}: {} ended at {} ms: {}",
        log::addr(&endpoint),
        attempt.times().ended.unwrap_or(0),
        attempt.reason()
    ));
    AttemptReport {
        candidate: candidate.clone(),
        outcome: attempt.outcome(),
        reason: attempt.reason().to_string(),
        scheduled_start: scheduled,
        started,
        times: attempt.times().clone(),
        peer_version: attempt.peer_version(),
        peer_user_agent: attempt.peer_user_agent().map(msg::sanitize),
        extra_requests: attempt.extra_requests(),
        bytes_sent: attempt.bytes_sent(),
        bytes_recv: attempt.bytes_recv(),
    }
}

/// The stream through the proxy, then the connection: what is read goes to the attempt and what it
/// offers is written, each write marked with the time it completed. Every blocking call ends by the
/// attempt's next deadline, LOOP_WAIT at most, so deadlines and a stop are acted on in time (D2,
/// C8). Returns once the attempt has ended.
fn connect_and_drive(shared: &Shared, attempt: &mut Attempt, socks: Socks5Client) {
    let deadline = |attempt: &Attempt| shared.at(attempt.next_deadline().unwrap_or(0));
    let stage_timeout = Duration::from_millis(shared.timing.scale(SOCKS_STAGE_TIMEOUT) as u64);
    let mut conn = match stream::open(&shared.proxy, socks, stage_timeout, deadline(attempt), &shared.stop) {
        Ok(open) => {
            attempt.connected(shared.now(), &open.leftover);
            open.conn
        }
        Err(reason) => return stopped_or_failed(shared, attempt, format!("socket error: {reason}")),
    };
    let mut buf = vec![0u8; READ_SIZE];
    loop {
        if shared.stopping() {
            return attempt.interrupt(shared.now(), "interrupted".into());
        }
        attempt.tick(shared.now());
        if attempt.ended() {
            return;
        }
        if let Err(e) = conn.set_timeout(stream::slice(deadline(attempt))) {
            return attempt.connection_failed(shared.now(), format!("socket error: {e}"));
        }
        // Write what the attempt offers before reading: it offers more only on what it reads or on
        // a completed write.
        if !attempt.bytes_to_send().is_empty() {
            match write(&mut conn, attempt.bytes_to_send()) {
                Ok(n) => attempt.mark_sent(n, shared.now()),
                Err(e) => return attempt.connection_failed(shared.now(), format!("socket error: send() failed: {e}")),
            }
            continue;
        }
        match conn.read(&mut buf) {
            Ok(0) => return attempt.connection_failed(shared.now(), "peer closed the connection".into()),
            Ok(n) => attempt.received(&buf[..n], shared.now()),
            Err(e) if stream::retry(&e) => {}
            Err(e) => return attempt.connection_failed(shared.now(), format!("socket error: recv() failed: {e}")),
        }
    }
}

/// A write that ran out of time took nothing.
fn write(conn: &mut Conn, bytes: &[u8]) -> std::io::Result<usize> {
    match conn.write(bytes) {
        Err(e) if stream::retry(&e) => Ok(0),
        other => other,
    }
}

/// The stream did not open: the job is stopping, a deadline passed, or the stream failed.
fn stopped_or_failed(shared: &Shared, attempt: &mut Attempt, reason: String) {
    if shared.stopping() {
        attempt.interrupt(shared.now(), "interrupted".into());
    } else {
        attempt.connection_failed(shared.now(), reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_in_an_attempt_is_contained() {
        let mut rng = Rng::from_key([1; 32]);
        let tx = Arc::new(TxData { bytes: vec![1], wtxid: [2; 32] });
        let mut attempt = Attempt::new(tx, 0, Timing::default(), &mut rng, &Secp256k1::new(), [0; 4]);
        let ran = catch_unwind(AssertUnwindSafe(|| {
            attempt.connected(1, &[]);
            panic!("acting on the attempt fails");
        }));
        assert!(ran.is_err());
        attempt.connection_failed(2, "internal error".into());
        assert!(attempt.ended());
        assert_eq!(attempt.reason(), "internal error");
    }
}
