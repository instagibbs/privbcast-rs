//! The values of a job: the Parameters section of the specification, then the values it leaves
//! open. Durations are in milliseconds and unscaled: a job's own durations go through
//! [`Timing::scale`].

/// A duration or an offset from job start, in milliseconds.
pub type Ms = i64;

/// Query sets, each carrying one RESOLVE query of every DNS seed, all launched at job start (D1).
pub const QUERIES_PER_SEED: usize = 4;
/// Job start to delivery start. Discovery ends by then (C3).
pub const DISCOVERY_WINDOW: Ms = 12_000;
pub const SLOTS: usize = 6;
/// A first attempt and three backups.
pub const OPPORTUNITIES_PER_SLOT: usize = 4;

/// Where a slot's first opportunity lies: at delivery start, or in the mid or late range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stratum {
    Prompt,
    Mid,
    Late,
}

impl Stratum {
    pub fn name(self) -> &'static str {
        match self {
            Stratum::Prompt => "prompt",
            Stratum::Mid => "mid",
            Stratum::Late => "late",
        }
    }
}

/// The slots' strata, fixed per release.
pub const SLOT_LAYOUT: [Stratum; SLOTS] =
    [Stratum::Prompt, Stratum::Prompt, Stratum::Prompt, Stratum::Mid, Stratum::Late, Stratum::Late];

/// A closed interval of durations, [min, max].
#[derive(Clone, Copy, Debug)]
pub struct Range {
    pub min: Ms,
    pub max: Ms,
}

/// The mid slot's first opportunity, after delivery start.
pub const MID_SLOT_RANGE: Range = Range { min: 35_000, max: 180_000 };
/// The late slots' first opportunities, after delivery start.
pub const LATE_SLOT_RANGE: Range = Range { min: 185_000, max: 240_000 };
/// The late slots' first opportunities are at least this far apart.
pub const LATE_SLOT_SEPARATION: Ms = 5_000;
/// A backup's scheduled start, after the previous opportunity's.
pub const BACKUP_RANGE: Range = Range { min: 50_000, max: 60_000 };
/// An opportunity not dialled within this of its scheduled start is missed (C5).
pub const START_GRACE: Ms = 5_000;
/// Scheduled start to the announcement point.
pub const HANDSHAKE_BUDGET: Ms = 45_000;
/// Announcement point to the peer's request. The TX and the PING are written by its end (E6).
pub const REQUEST_WINDOW: Ms = 75_000;
/// The wait for the PONG after the PING is written (E6).
pub const PONG_WAIT: Ms = 10_000;
/// A connection that has received more than this after the proxy connected it is ended (D3).
pub const MAX_RECV_BYTES: u64 = 128 * 1024;
/// An attempt ends by its scheduled start plus this (D2).
pub const ATTEMPT_MAX: Ms = HANDSHAKE_BUDGET + REQUEST_WINDOW + PONG_WAIT;
/// A slot ends by its first opportunity's scheduled start plus this (D2).
pub const SLOT_MAX: Ms = (OPPORTUNITIES_PER_SLOT as Ms - 1) * BACKUP_RANGE.max + ATTEMPT_MAX;
/// A job's last slot ends by job start plus this (D2).
pub const SCHEDULED_BOUND: Ms = DISCOVERY_WINDOW + LATE_SLOT_RANGE.max + SLOT_MAX;
/// A job still running this long after it started is stopped, on the steady clock (D2).
pub const JOB_CAP: Ms = 600_000;

const _: () = assert!(ATTEMPT_MAX == 130_000);
const _: () = assert!(SLOT_MAX == 310_000);
const _: () = assert!(SCHEDULED_BOUND == 562_000);
const _: () = assert!(SCHEDULED_BOUND <= JOB_CAP);
const _: () = assert!(MID_SLOT_RANGE.max < LATE_SLOT_RANGE.min);
const _: () = assert!(LATE_SLOT_SEPARATION < LATE_SLOT_RANGE.max - LATE_SLOT_RANGE.min);
const _: () = assert!(BACKUP_RANGE.min == HANDSHAKE_BUDGET + START_GRACE);

/// The job's VERSION (E1): this version and these services, time 0, addr_recv null with services
/// 0, addr_from null with these services, a random nonce, this user agent, start height 0 and relay
/// false. The same in every release.
pub const PROFILE_VERSION: i32 = 70016;
pub const PROFILE_SERVICES: u64 = NODE_WITNESS;
pub const PROFILE_USER_AGENT: &str = "/pynode:0.0.1/";
/// The lowest version a peer's VERSION may show for the job to announce (E2): BIP339.
pub const MIN_PEER_PROTOCOL_VERSION: i32 = 70016;
pub const NODE_WITNESS: u64 = 1 << 3;

/// The DNS seeds the mainnet release lists, at least (R3).
pub const MIN_DNS_SEEDS: usize = 7;
const _: () = assert!((MIN_DNS_SEEDS - 1) * QUERIES_PER_SEED >= SLOTS * OPPORTUNITIES_PER_SLOT);
const _: () = assert!(MIN_DNS_SEEDS > SLOTS);

/// The largest regtest time divisor (U1).
pub const MAX_TIME_DIVISOR: i64 = 1000;

// Not normative: constrained only by C3, C5 and D2.

/// Each stage of a proxy stream: the connect to the proxy and each step of the SOCKS5 exchange.
pub const SOCKS_STAGE_TIMEOUT: Ms = 20_000;
/// How late after job start a RESOLVE query may still be launched.
pub const QUERY_GRACE: Ms = START_GRACE;
const _: () = assert!(QUERY_GRACE < DISCOVERY_WINDOW);
/// The longest the job's thread waits before reading its clock and cancel flag again. Not scaled.
pub const LOOP_WAIT: Ms = 100;

/// The time divisor of a job: the regtest test override, 1 otherwise (U1). It divides every
/// duration of the plan and every I/O timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    divisor: i64,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing { divisor: 1 }
    }
}

impl Timing {
    /// None unless 1 <= divisor <= MAX_TIME_DIVISOR.
    pub fn new(divisor: i64) -> Option<Timing> {
        (1..=MAX_TIME_DIVISOR).contains(&divisor).then_some(Timing { divisor })
    }

    /// The duration under this timing, at millisecond resolution.
    pub fn scale(&self, duration: Ms) -> Ms {
        duration / self.divisor
    }
}
