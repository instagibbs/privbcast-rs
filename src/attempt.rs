//! One connection to a recipient, from the moment the proxy connected it: a BIP324 session as
//! initiator, the handshake, the announcement, serving the transaction and the PING (E1-E8). It
//! owns no socket and reads no clock: the caller passes the bytes read, writes what
//! bytes_to_send() offers, and passes the time, an offset from job start, with every call.
//!
//! Every byte it offers is a function of the transaction, the randomness drawn at construction,
//! what the peer sent, when it arrived against the attempt's deadlines, and interrupt() (A2).
//! Nothing is acted on at or after a deadline (D2). Once ended, it offers no bytes, not even the
//! rest of a partly written message (E7).

use std::collections::VecDeque;
use std::sync::Arc;

use bitcoin::secp256k1::ellswift::ElligatorSwift;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};

use crate::bip324::{MAX_GARBAGE_LEN, V2Transport};
use crate::msg;
use crate::params::*;
use crate::rng::Rng;

/// How an attempt ended (Report: outcome).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Ended before the announcement point.
    NotAnnounced,
    AnnouncedNotRequested,
    TxWrittenNoPong,
    PongReceived,
    /// The connection failed after the announcement point.
    PostAnnouncementFailure,
}

impl Outcome {
    pub fn name(self) -> &'static str {
        match self {
            Outcome::NotAnnounced => "not_announced",
            Outcome::AnnouncedNotRequested => "announced_not_requested",
            Outcome::TxWrittenNoPong => "tx_written_no_pong",
            Outcome::PongReceived => "pong_received",
            Outcome::PostAnnouncementFailure => "post_announcement_failure",
        }
    }
}

/// When an attempt's events happened, as offsets from job start. None for an event that did not
/// happen.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttemptTimes {
    /// The proxy connected the stream.
    pub connected: Option<Ms>,
    /// The transport accepted the INV: the announcement point.
    pub inv_handed: Option<Ms>,
    /// The last byte of the INV was written.
    pub inv_written: Option<Ms>,
    /// The GETDATA that was served arrived.
    pub getdata: Option<Ms>,
    pub tx_written: Option<Ms>,
    pub ping_written: Option<Ms>,
    /// The PONG carrying the PING's nonce arrived.
    pub pong: Option<Ms>,
    pub ended: Option<Ms>,
}

/// The transaction a job broadcasts.
pub struct TxData {
    /// Its serialization with witness: the TX payload.
    pub bytes: Vec<u8>,
    /// In internal byte order, as an INV carries it.
    pub wtxid: [u8; 32],
}

/// The messages an attempt sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Version,
    WtxidRelay,
    Verack,
    Inv,
    Tx,
    Ping,
}

impl Kind {
    fn msg_type(self) -> &'static str {
        match self {
            Kind::Version => "version",
            Kind::WtxidRelay => "wtxidrelay",
            Kind::Verack => "verack",
            Kind::Inv => "inv",
            Kind::Tx => "tx",
            Kind::Ping => "ping",
        }
    }
}

pub struct Attempt {
    tx: Arc<TxData>,
    scheduled_start: Ms,
    timing: Timing,
    /// BIP324 as initiator, never v1 (B4).
    transport: V2Transport,
    version_nonce: u64,
    ping_nonce: u64,
    /// Messages not yet handed to the transport, which takes one at a time.
    queue: VecDeque<(Kind, Vec<u8>)>,
    /// The message the transport holds, until its last byte is written.
    in_transport: Option<Kind>,
    peer_version: Option<i32>,
    peer_user_agent: Option<Vec<u8>>,
    peer_wtxidrelay: bool,
    peer_verack: bool,
    times: AttemptTimes,
    outcome: Option<Outcome>,
    reason: String,
    extra_requests: u32,
    bytes_sent: u64,
    bytes_recv: u64,
}

impl Attempt {
    /// The BIP324 key and garbage, then the VERSION and PING nonces, are drawn from rng here (A4).
    pub fn new(
        tx: Arc<TxData>,
        scheduled_start: Ms,
        timing: Timing,
        rng: &mut Rng,
        secp: &Secp256k1<All>,
        magic: [u8; 4],
    ) -> Attempt {
        let secret = loop {
            if let Ok(key) = SecretKey::from_slice(&rng.bytes::<32>()) {
                break key;
            }
        };
        // The encoding takes fresh randomness, so that it is indistinguishable from uniform.
        let ours = ElligatorSwift::from_seckey(secp, secret, Some(rng.bytes()));
        let mut garbage = vec![0u8; rng.randrange(MAX_GARBAGE_LEN as u64 + 1) as usize];
        rng.fill(&mut garbage);
        Attempt {
            tx,
            scheduled_start,
            timing,
            transport: V2Transport::new_initiator(magic, secret, ours, garbage),
            version_nonce: rng.rand64(),
            ping_nonce: rng.rand64(),
            queue: VecDeque::new(),
            in_transport: None,
            peer_version: None,
            peer_user_agent: None,
            peer_wtxidrelay: false,
            peer_verack: false,
            times: AttemptTimes::default(),
            outcome: None,
            reason: String::new(),
            extra_requests: 0,
            bytes_sent: 0,
            bytes_recv: 0,
        }
    }

    /// The proxy connected the stream, and `first`, the peer's bytes that came with its reply,
    /// were read. The VERSION is queued (E1), then `first` is handled as received() handles bytes.
    pub fn connected(&mut self, now: Ms, first: &[u8]) {
        if self.ended() || self.times.connected.is_some() {
            return;
        }
        self.times.connected = Some(now);
        let within = self.count_received(first);
        self.tick(now);
        if self.ended() {
            return;
        }
        self.queue_msg(Kind::Version, msg::version(self.version_nonce), now);
        self.feed(&first[..within], now);
    }

    /// Bytes read from the connection. They count toward the receive cap (D3), at a deadline too;
    /// those within it feed the transport, and the messages they complete are handled.
    pub fn received(&mut self, bytes: &[u8], now: Ms) {
        if self.ended() || bytes.is_empty() || self.times.connected.is_none() {
            return;
        }
        let within = self.count_received(bytes);
        self.tick(now);
        self.feed(&bytes[..within], now);
    }

    /// How many of bytes are within the receive cap.
    fn count_received(&mut self, bytes: &[u8]) -> usize {
        let room = MAX_RECV_BYTES.saturating_sub(self.bytes_recv);
        self.bytes_recv += bytes.len() as u64;
        bytes.len().min(room as usize)
    }

    fn feed(&mut self, mut bytes: &[u8], now: Ms) {
        while !bytes.is_empty() && !self.ended() {
            match self.transport.received_bytes(bytes) {
                Ok(n) => bytes = &bytes[n..],
                Err(_) => return self.fail(now, "transport error".into()),
            }
            // A message of a type the transport cannot decode is dropped.
            if let Some(received) = self.transport.take_message() {
                if let Some(msg_type) = received.msg_type {
                    self.process(&msg_type, &received.payload, now);
                }
            }
        }
        if self.bytes_recv > MAX_RECV_BYTES {
            self.fail(now, "receive cap".into());
        }
    }

    /// What to write next. Empty before connected() and once ended.
    pub fn bytes_to_send(&self) -> &[u8] {
        if self.ended() || self.times.connected.is_none() {
            return &[];
        }
        self.transport.bytes_to_send()
    }

    /// The first n bytes of bytes_to_send() were written. When the last byte of the INV, the TX or
    /// the PING goes, its time is recorded, at a deadline too; then, unless a deadline has passed,
    /// the next message is handed to the transport.
    pub fn mark_sent(&mut self, n: usize, now: Ms) {
        let n = n.min(self.bytes_to_send().len());
        if n == 0 {
            return;
        }
        self.transport.mark_sent(n);
        self.bytes_sent += n as u64;
        if !self.bytes_to_send().is_empty() {
            return self.tick(now);
        }
        match self.in_transport.take() {
            Some(Kind::Inv) => self.times.inv_written = Some(now),
            Some(Kind::Tx) => self.times.tx_written = Some(now),
            Some(Kind::Ping) => self.times.ping_written = Some(now),
            _ => {}
        }
        // Then the deadlines: once one has passed, nothing more goes to the transport (D2).
        self.tick(now);
        self.hand_off(now);
    }

    /// End the attempt if a deadline has passed.
    pub fn tick(&mut self, now: Ms) {
        let Some(deadline) = self.next_deadline() else { return };
        if now < deadline {
            return;
        }
        let reason = if self.times.inv_handed.is_none() {
            "not announced by the handshake deadline"
        } else if self.times.getdata.is_none() {
            "no request in the request window"
        } else if self.times.tx_written.is_none() {
            "TX not written in the request window"
        } else if self.times.ping_written.is_none_or(|p| p >= deadline) {
            "PING not written in the request window"
        } else {
            "no PONG in time"
        };
        self.end(now, self.state_outcome(), reason.into());
    }

    /// The connection failed: the peer closed it or the socket failed.
    pub fn connection_failed(&mut self, now: Ms, reason: String) {
        self.tick(now);
        self.fail(now, reason);
    }

    /// The job was cancelled (C8) or failed: end now, whatever the state.
    pub fn interrupt(&mut self, now: Ms, reason: String) {
        self.tick(now);
        self.end(now, self.state_outcome(), reason);
    }

    pub fn ended(&self) -> bool {
        self.outcome.is_some()
    }

    /// How the attempt ended. Before it has ended: how an interruption would end it now.
    pub fn outcome(&self) -> Outcome {
        self.outcome.unwrap_or_else(|| self.state_outcome())
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn times(&self) -> &AttemptTimes {
        &self.times
    }

    pub fn peer_version(&self) -> Option<i32> {
        self.peer_version
    }

    pub fn peer_user_agent(&self) -> Option<&[u8]> {
        self.peer_user_agent.as_deref()
    }

    pub fn extra_requests(&self) -> u32 {
        self.extra_requests
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    pub fn bytes_recv(&self) -> u64 {
        self.bytes_recv
    }

    /// The handshake budget, then the request window, by whose end the TX and the PING are written
    /// (E6), then the PONG wait. A PING written at the window's end opens no PONG wait. None once
    /// ended.
    pub fn next_deadline(&self) -> Option<Ms> {
        if self.ended() {
            return None;
        }
        let mut phase_end = self.scheduled_start + self.timing.scale(HANDSHAKE_BUDGET);
        if let Some(handed) = self.times.inv_handed {
            phase_end = handed + self.timing.scale(REQUEST_WINDOW);
        }
        if let Some(ping) = self.times.ping_written {
            if ping < phase_end {
                phase_end = ping + self.timing.scale(PONG_WAIT);
            }
        }
        Some(phase_end.min(self.scheduled_start + self.timing.scale(ATTEMPT_MAX)))
    }

    /// What the attempt has achieved: the outcome of a deadline or an interruption now. A request
    /// whose TX is not fully written is a failure after the announcement point.
    fn state_outcome(&self) -> Outcome {
        if self.times.inv_handed.is_none() {
            Outcome::NotAnnounced
        } else if self.times.getdata.is_none() {
            Outcome::AnnouncedNotRequested
        } else if self.times.tx_written.is_none() {
            Outcome::PostAnnouncementFailure
        } else {
            Outcome::TxWrittenNoPong
        }
    }

    fn end(&mut self, now: Ms, outcome: Outcome, reason: String) {
        if self.ended() {
            return;
        }
        self.outcome = Some(outcome);
        self.reason = reason;
        self.times.ended = Some(now);
        self.queue.clear();
    }

    /// End on a failure of the connection or of the peer.
    fn fail(&mut self, now: Ms, reason: String) {
        let outcome =
            if self.times.inv_handed.is_some() { Outcome::PostAnnouncementFailure } else { Outcome::NotAnnounced };
        self.end(now, outcome, reason);
    }

    fn queue_msg(&mut self, kind: Kind, payload: Vec<u8>, now: Ms) {
        self.queue.push_back((kind, payload));
        self.hand_off(now);
    }

    /// Hand the next queued message to the transport if it takes one.
    fn hand_off(&mut self, now: Ms) {
        if self.ended() || self.in_transport.is_some() {
            return;
        }
        let Some((kind, payload)) = self.queue.front() else { return };
        if !self.transport.set_message(kind.msg_type(), payload) {
            return;
        }
        let kind = *kind;
        self.queue.pop_front();
        // The announcement point: the request window starts.
        if kind == Kind::Inv {
            self.times.inv_handed = Some(now);
        }
        self.in_transport = Some(kind);
    }

    fn process(&mut self, msg_type: &str, payload: &[u8], now: Ms) {
        // A message the attempt does not act on in its state is ignored (E7).
        if self.peer_version.is_none() {
            if msg_type == "version" {
                self.process_version(payload, now);
            }
        } else if !self.peer_verack {
            // Neither carries a payload: one that does is malformed (E7).
            if (msg_type == "wtxidrelay" || msg_type == "verack") && !payload.is_empty() {
                return self.fail(now, format!("malformed {msg_type}"));
            }
            // WTXIDRELAY counts only between the peer's VERSION and its VERACK (BIP339).
            if msg_type == "wtxidrelay" {
                self.peer_wtxidrelay = true;
            } else if msg_type == "verack" {
                self.peer_verack = true;
                if !self.peer_wtxidrelay {
                    return self.end(now, Outcome::NotAnnounced, "no WTXIDRELAY before the peer's VERACK".into());
                }
                // One INV with one entry, MSG_WTX for the wtxid (E3).
                self.queue_msg(Kind::Inv, msg::inv(&self.tx.wtxid), now);
            }
        } else if self.times.inv_handed.is_some() {
            // Before the announcement point, a GETDATA is ignored and not counted (E4). Once one was
            // served, another is counted without being parsed: nothing more is served (E5).
            if msg_type == "getdata" && self.times.getdata.is_some() {
                self.extra_requests += 1;
            } else if msg_type == "getdata" {
                self.process_getdata(payload, now);
            } else if msg_type == "pong" && self.times.ping_written.is_some() {
                self.process_pong(payload, now);
            }
        }
    }

    fn process_version(&mut self, payload: &[u8], now: Ms) {
        // Every field up to the relay flag, and nothing after it (E2).
        let Ok(v) = msg::parse_version(payload) else {
            return self.fail(now, "malformed VERSION".into());
        };
        self.peer_version = Some(v.version);
        self.peer_user_agent = Some(v.user_agent);
        // E2: after any other VERSION, nothing more is sent.
        if v.version < MIN_PEER_PROTOCOL_VERSION {
            return self.end(
                now,
                Outcome::NotAnnounced,
                format!("peer version {} is below {MIN_PEER_PROTOCOL_VERSION}", v.version),
            );
        }
        if v.services & NODE_WITNESS == 0 {
            return self.end(now, Outcome::NotAnnounced, "peer does not offer NODE_WITNESS".into());
        }
        if !v.relay {
            return self.end(now, Outcome::NotAnnounced, "peer does not relay transactions".into());
        }
        self.queue_msg(Kind::WtxidRelay, Vec::new(), now);
        self.queue_msg(Kind::Verack, Vec::new(), now);
    }

    fn process_getdata(&mut self, payload: &[u8], now: Ms) {
        // One that does not decode, or has bytes left over, gets no reply and ends the attempt (E7).
        let Ok(request) = msg::parse_getdata(payload) else {
            self.extra_requests += 1;
            return self.fail(now, "malformed GETDATA".into());
        };
        // Served once, only for a single-entry MSG_WTX naming the wtxid (E5); TX, then a PING (E6).
        if request.len() == 1 && request[0].0 == msg::MSG_WTX && request[0].1 == self.tx.wtxid {
            self.times.getdata = Some(now);
            self.queue_msg(Kind::Tx, self.tx.bytes.clone(), now);
            self.queue_msg(Kind::Ping, msg::ping(self.ping_nonce), now);
        } else {
            self.extra_requests += 1;
        }
    }

    fn process_pong(&mut self, payload: &[u8], now: Ms) {
        let Ok(nonce) = msg::parse_pong(payload) else {
            return self.fail(now, "malformed PONG".into());
        };
        // A PONG with another nonce changes nothing (E6).
        if nonce != self.ping_nonce {
            return;
        }
        self.times.pong = Some(now);
        self.end(now, Outcome::PongReceived, "PONG received".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip324::tests::Responder;
    use crate::msg::tests::peer_version;

    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];
    const START: Ms = 1_000;

    fn tx() -> Arc<TxData> {
        Arc::new(TxData { bytes: vec![1, 2, 3], wtxid: [0xab; 32] })
    }

    /// An attempt and a BIP324 peer, wired together by pump().
    struct Pair {
        attempt: Attempt,
        peer: Responder,
        /// What the peer has received, by type.
        got: Vec<(Option<String>, Vec<u8>)>,
    }

    impl Pair {
        fn new(seed: u8) -> Pair {
            let mut rng = Rng::from_key([seed; 32]);
            let secp = Secp256k1::new();
            let mut attempt = Attempt::new(tx(), START, Timing::default(), &mut rng, &secp, MAGIC);
            let mut peer = Responder::new(MAGIC, seed);
            attempt.connected(START, &[]);
            let hello = peer.hello(&[1, 2, 3]);
            attempt.received(&hello, START);
            let mut pair = Pair { attempt, peer, got: Vec::new() };
            pair.pump(START);
            pair
        }

        /// Move the attempt's bytes to the peer.
        fn pump(&mut self, now: Ms) {
            loop {
                let out = self.attempt.bytes_to_send().to_vec();
                if out.is_empty() {
                    break;
                }
                self.attempt.mark_sent(out.len(), now);
                let (back, got) = self.peer.feed(&out);
                self.got.extend(got);
                self.attempt.received(&back, now);
            }
        }

        fn send(&mut self, msg_type: &str, payload: &[u8], now: Ms) {
            let bytes = self.peer.send(msg_type, payload);
            self.attempt.received(&bytes, now);
            self.pump(now);
        }

        fn types(&self) -> Vec<&str> {
            self.got.iter().map(|(t, _)| t.as_deref().unwrap()).collect()
        }

        fn handshake(&mut self, now: Ms) {
            self.send("version", &peer_version(70016, 9, b"/Satoshi:30.0.0/", true), now);
            self.send("wtxidrelay", &[], now);
            self.send("verack", &[], now);
        }
    }

    #[test]
    fn full_exchange() {
        let mut p = Pair::new(1);
        assert_eq!(p.types(), ["version"]);
        p.handshake(START + 100);
        assert_eq!(p.types(), ["version", "wtxidrelay", "verack", "inv"]);
        assert_eq!(p.got[3].1, msg::inv(&[0xab; 32]));
        assert_eq!(p.attempt.times().inv_handed, Some(START + 100));
        // A GETDATA for something else is counted and not served.
        p.send("getdata", &msg::inv(&[0xcd; 32]), START + 200);
        assert_eq!(p.attempt.extra_requests(), 1);
        p.send("getdata", &msg::inv(&[0xab; 32]), START + 300);
        assert_eq!(p.types(), ["version", "wtxidrelay", "verack", "inv", "tx", "ping"]);
        assert_eq!(p.got[4].1, vec![1, 2, 3]);
        let nonce = msg::parse_pong(&p.got[5].1).unwrap();
        p.send("pong", &msg::ping(nonce ^ 1), START + 400);
        assert!(!p.attempt.ended());
        p.send("pong", &msg::ping(nonce), START + 500);
        assert_eq!(p.attempt.outcome(), Outcome::PongReceived);
        assert_eq!(p.attempt.times().pong, Some(START + 500));
        assert!(p.attempt.bytes_to_send().is_empty());
    }

    #[test]
    fn peer_refusals() {
        for (v, services, relay, reason) in [
            (70015, 9, true, "peer version 70015 is below 70016"),
            (70016, 1, true, "peer does not offer NODE_WITNESS"),
            (70016, 9, false, "peer does not relay transactions"),
        ] {
            let mut p = Pair::new(2);
            p.send("version", &peer_version(v, services, b"x", relay), START + 10);
            assert_eq!(p.attempt.outcome(), Outcome::NotAnnounced);
            assert_eq!(p.attempt.reason(), reason);
            assert_eq!(p.types(), ["version"]);
        }
        let mut p = Pair::new(3);
        p.send("version", &peer_version(70016, 9, b"x", true), START + 10);
        p.send("verack", &[], START + 20);
        assert_eq!(p.attempt.reason(), "no WTXIDRELAY before the peer's VERACK");
        assert_eq!(p.types(), ["version", "wtxidrelay", "verack"]);
    }

    #[test]
    fn extra_bytes_are_malformed() {
        let mut v = peer_version(70016, 9, b"x", true);
        v.push(0);
        let mut p = Pair::new(4);
        p.send("version", &v, START + 10);
        assert_eq!(p.attempt.reason(), "malformed VERSION");
        for t in ["wtxidrelay", "verack"] {
            let mut p = Pair::new(5);
            p.send("version", &peer_version(70016, 9, b"x", true), START + 10);
            p.send(t, &[0], START + 20);
            assert_eq!(p.attempt.reason(), format!("malformed {t}"));
            assert_eq!(p.attempt.times().inv_handed, None);
        }
        let mut p = Pair::new(6);
        p.handshake(START + 10);
        let mut g = msg::inv(&[0xab; 32]);
        g.push(0);
        p.send("getdata", &g, START + 20);
        assert_eq!(p.attempt.outcome(), Outcome::PostAnnouncementFailure);
        assert_eq!(p.attempt.times().tx_written, None);
        let mut p = Pair::new(7);
        p.handshake(START + 10);
        p.send("getdata", &msg::inv(&[0xab; 32]), START + 20);
        let nonce = msg::parse_pong(&p.got[5].1).unwrap();
        let mut pong = msg::ping(nonce);
        pong.push(0);
        p.send("pong", &pong, START + 30);
        assert_eq!(p.attempt.reason(), "malformed PONG");
        // A failure after the announcement point, as in Bitcoin Core, with the TX written.
        assert_eq!(p.attempt.outcome(), Outcome::PostAnnouncementFailure);
        assert!(p.attempt.times().tx_written.is_some());
    }

    #[test]
    fn getdata_before_announcement_is_ignored() {
        let mut p = Pair::new(8);
        p.send("version", &peer_version(70016, 9, b"x", true), START + 10);
        p.send("getdata", &msg::inv(&[0xab; 32]), START + 20);
        assert_eq!(p.attempt.extra_requests(), 0);
        assert!(!p.types().contains(&"tx"));
    }

    #[test]
    fn deadlines() {
        let mut p = Pair::new(9);
        p.attempt.tick(START + HANDSHAKE_BUDGET - 1);
        assert!(!p.attempt.ended());
        p.attempt.tick(START + HANDSHAKE_BUDGET);
        assert_eq!(p.attempt.reason(), "not announced by the handshake deadline");
        let mut p = Pair::new(10);
        p.handshake(START + 10);
        p.attempt.tick(START + 10 + REQUEST_WINDOW);
        assert_eq!(p.attempt.outcome(), Outcome::AnnouncedNotRequested);
        let mut p = Pair::new(11);
        p.handshake(START + 10);
        p.send("getdata", &msg::inv(&[0xab; 32]), START + 20);
        p.attempt.tick(START + 20 + PONG_WAIT);
        assert_eq!(p.attempt.reason(), "no PONG in time");
        assert_eq!(p.attempt.outcome(), Outcome::TxWrittenNoPong);
        // Nothing is acted on at or after a deadline.
        let mut p = Pair::new(12);
        p.send("version", &peer_version(70016, 9, b"x", true), START + HANDSHAKE_BUDGET);
        assert_eq!(p.types(), ["version"]);
        assert_eq!(p.attempt.reason(), "not announced by the handshake deadline");
    }

    #[test]
    fn receive_cap() {
        let mut p = Pair::new(13);
        p.send("version", &peer_version(70016, 9, b"x", true), START + 10);
        let big = vec![0u8; 70_000];
        p.send("unknownmsg", &big, START + 20);
        assert!(!p.attempt.ended());
        p.send("unknownmsg", &big, START + 30);
        assert_eq!(p.attempt.reason(), "receive cap");
    }

    /// What must hold of an attempt whatever its peer did.
    fn check_invariants(a: &Attempt) {
        let t = a.times();
        assert_eq!(a.ended(), t.ended.is_some());
        if a.ended() {
            assert!(a.bytes_to_send().is_empty(), "an ended attempt offers nothing (E7)");
        }
        // Each event needs the one before it.
        assert!(t.inv_handed.is_none() || t.connected.is_some());
        assert!(t.inv_written.is_none() || t.inv_handed.is_some());
        assert!(t.getdata.is_none() || t.inv_handed.is_some());
        assert!(t.tx_written.is_none() || t.getdata.is_some());
        assert!(t.ping_written.is_none() || t.tx_written.is_some());
        assert!(t.pong.is_none() || t.ping_written.is_some());
        assert_eq!(a.outcome() == Outcome::PongReceived, t.pong.is_some());
        assert!(a.extra_requests() == 0 || t.inv_handed.is_some());
        if a.outcome() == Outcome::NotAnnounced {
            assert!(t.inv_handed.is_none());
        }
        // Nothing is acted on at or after a deadline (D2): no event is later than the attempt's cap.
        for e in [t.inv_handed, t.getdata, t.pong].into_iter().flatten() {
            assert!(e < START + ATTEMPT_MAX);
        }
    }

    /// Iterations of the randomized tests: PRIVBCAST_ITERS, default 300.
    fn iterations() -> u64 {
        std::env::var("PRIVBCAST_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(300)
    }

    /// A peer that mostly follows the protocol, and at random sends malformed, irrelevant or
    /// misordered messages, or lets time pass.
    #[test]
    fn random_peers() {
        let mut outcomes = std::collections::HashMap::new();
        for i in 0..iterations() {
            let mut rng = Rng::from_key({
                let mut k = [0u8; 32];
                k[..8].copy_from_slice(&i.to_le_bytes());
                k
            });
            let mut p = Pair::new((i % 251) as u8 + 1);
            let mut now = START;
            // The well-behaved peer's next message.
            let mut step = 0;
            for _ in 0..rng.randrange(16) + 1 {
                let span = if rng.randrange(8) == 0 { 60_000 } else { 2_000 };
                now += rng.randrange(span) as Ms;
                let mut junk = vec![0u8; rng.randrange(60) as usize];
                rng.fill(&mut junk);
                let nonce = p.got.iter().rev().find(|(t, _)| t.as_deref() == Some("ping")).map(|(_, n)| n.clone());
                let (t, payload): (&str, Vec<u8>) = if rng.randrange(10) < 7 {
                    step += 1;
                    match step {
                        1 => ("version", peer_version(70016, 9, b"/x/", true)),
                        2 => ("wtxidrelay", vec![]),
                        3 => ("verack", vec![]),
                        4 => ("getdata", msg::inv(&[0xab; 32])),
                        _ => ("pong", nonce.unwrap_or_default()),
                    }
                } else {
                    match rng.randrange(9) {
                        0 => (
                            "version",
                            peer_version(
                                70015 + rng.randrange(3) as i32,
                                [1, 9, 8][rng.randrange(3) as usize],
                                b"/x/",
                                rng.randrange(3) != 0,
                            ),
                        ),
                        1 => ("version", junk),
                        2 => ("wtxidrelay", vec![0]),
                        3 => ("verack", vec![0]),
                        4 => ("getdata", msg::inv(&[0xcd; 32])),
                        5 => ("getdata", junk),
                        6 => ("pong", junk),
                        7 => ("ping", msg::ping(rng.rand64())),
                        _ => ("unknownmsg", junk),
                    }
                };
                if rng.randrange(8) == 0 {
                    p.attempt.tick(now);
                } else {
                    p.send(t, &payload, now);
                }
                check_invariants(&p.attempt);
                if p.attempt.ended() {
                    break;
                }
            }
            p.attempt.interrupt(now + 1, "interrupted".into());
            check_invariants(&p.attempt);
            *outcomes.entry(p.attempt.outcome().name()).or_insert(0) += 1;
        }
        // The peers reach every outcome.
        assert_eq!(outcomes.len(), 5, "{outcomes:?}");
    }

    /// Random bytes from the peer, in random chunks: the transport fails or waits, never panics.
    #[test]
    fn random_bytes() {
        for i in 0..iterations() {
            let mut rng = Rng::from_key([(i % 256) as u8; 32]);
            let secp = Secp256k1::new();
            let mut attempt = Attempt::new(tx(), START, Timing::default(), &mut rng, &secp, MAGIC);
            attempt.connected(START, &[]);
            let mut now = START;
            for _ in 0..rng.randrange(8) + 1 {
                let mut chunk = vec![0u8; rng.randrange(5000) as usize];
                rng.fill(&mut chunk);
                now += 10;
                attempt.received(&chunk, now);
                let n = attempt.bytes_to_send().len();
                attempt.mark_sent(rng.randrange(n as u64 + 1) as usize, now);
                check_invariants(&attempt);
            }
        }
    }
}
