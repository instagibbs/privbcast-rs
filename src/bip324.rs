//! BIP324 v2 transport, as initiator only, driven by bytes (B4). It owns no socket and reads no
//! clock. Built on rust-bitcoin's secp256k1 (ElligatorSwift, ECDH), bitcoin_hashes (HMAC-SHA256)
//! and chacha20-poly1305.
//!
//! Like Bitcoin Core's V2Transport as initiator: the key and random garbage are sent at once; the
//! garbage terminator and the version packet once the peer's key arrives; then one application
//! message at a time, each once the previous one is fully written. No decoys are sent. Received
//! decoys and the contents of the peer's version packet are ignored.

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::secp256k1::SecretKey;
use bitcoin::secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
use chacha20_poly1305::chacha20::ChaCha20;
use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};

pub const ELLSWIFT_LEN: usize = 64;
pub const GARBAGE_TERMINATOR_LEN: usize = 16;
pub const MAX_GARBAGE_LEN: usize = 4095;
const REKEY_INTERVAL: u64 = 224;
const LENGTH_LEN: usize = 3;
const HEADER_LEN: usize = 1;
const TAG_LEN: usize = 16;
const IGNORE_BIT: u8 = 0x80;
/// The 12 bytes of a long message type.
const MESSAGE_TYPE_SIZE: usize = 12;
/// The largest contents accepted: a long message type and a payload of at most 4,000,000 bytes,
/// as Bitcoin Core accepts.
const MAX_CONTENTS_LEN: usize = 1 + MESSAGE_TYPE_SIZE + 4_000_000;

/// The BIP324 short message type ids, by id. Ids not listed are unknown.
const SHORT_IDS: [(u8, &str); 29] = [
    (1, "addr"),
    (2, "block"),
    (3, "blocktxn"),
    (4, "cmpctblock"),
    (5, "feefilter"),
    (6, "filteradd"),
    (7, "filterclear"),
    (8, "filterload"),
    (9, "getblocks"),
    (10, "getblocktxn"),
    (11, "getdata"),
    (12, "getheaders"),
    (13, "headers"),
    (14, "inv"),
    (15, "mempool"),
    (16, "merkleblock"),
    (17, "notfound"),
    (18, "ping"),
    (19, "pong"),
    (20, "sendcmpct"),
    (21, "tx"),
    (22, "getcfilters"),
    (23, "cfilter"),
    (24, "getcfheaders"),
    (25, "cfheaders"),
    (26, "getcfcheckpt"),
    (27, "cfcheckpt"),
    (28, "addrv2"),
    (37, "feature"),
];

fn hmac_sha256(key: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let mut engine = HmacEngine::<sha256::Hash>::new(key);
    for d in data {
        engine.input(d);
    }
    Hmac::<sha256::Hash>::from_engine(engine).to_byte_array()
}

/// The FSChaCha20 stream cipher of BIP324, which encrypts the packet lengths.
struct FsChaCha20 {
    key: [u8; 32],
    chunk_counter: u64,
    rekey_counter: u64,
    block: u32,
    buf: [u8; 64],
    pos: usize,
}

impl FsChaCha20 {
    fn new(key: [u8; 32]) -> FsChaCha20 {
        FsChaCha20 { key, chunk_counter: 0, rekey_counter: 0, block: 0, buf: [0; 64], pos: 64 }
    }

    fn next_byte(&mut self) -> u8 {
        if self.pos == self.buf.len() {
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&self.rekey_counter.to_le_bytes());
            self.buf = ChaCha20::new(Key::new(self.key), Nonce::new(nonce), 0).get_keystream(self.block);
            self.block += 1;
            self.pos = 0;
        }
        self.pos += 1;
        self.buf[self.pos - 1]
    }

    fn crypt(&mut self, chunk: &mut [u8]) {
        for byte in chunk.iter_mut() {
            *byte ^= self.next_byte();
        }
        self.chunk_counter += 1;
        if self.chunk_counter == REKEY_INTERVAL {
            let mut key = [0u8; 32];
            for byte in key.iter_mut() {
                *byte = self.next_byte();
            }
            self.key = key;
            self.chunk_counter = 0;
            self.rekey_counter += 1;
            self.block = 0;
            self.pos = self.buf.len();
        }
    }
}

/// The FSChaCha20Poly1305 AEAD of BIP324, which encrypts the packets.
struct FsAead {
    key: [u8; 32],
    packet_counter: u64,
}

impl FsAead {
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&((self.packet_counter % REKEY_INTERVAL) as u32).to_le_bytes());
        nonce[4..].copy_from_slice(&(self.packet_counter / REKEY_INTERVAL).to_le_bytes());
        nonce
    }

    fn advance(&mut self, nonce: [u8; 12]) {
        if (self.packet_counter + 1) % REKEY_INTERVAL == 0 {
            let mut rekey_nonce = nonce;
            rekey_nonce[..4].copy_from_slice(&[0xff; 4]);
            let mut key = [0u8; 32];
            ChaCha20Poly1305::new(Key::new(self.key), Nonce::new(rekey_nonce)).encrypt(&mut key, Some(&[]));
            self.key = key;
        }
        self.packet_counter += 1;
    }

    fn encrypt(&mut self, aad: &[u8], text: &mut [u8]) -> [u8; TAG_LEN] {
        let nonce = self.nonce();
        let tag = ChaCha20Poly1305::new(Key::new(self.key), Nonce::new(nonce)).encrypt(text, Some(aad));
        self.advance(nonce);
        tag
    }

    fn decrypt(&mut self, aad: &[u8], text: &mut [u8], tag: [u8; TAG_LEN]) -> bool {
        let nonce = self.nonce();
        let ok = ChaCha20Poly1305::new(Key::new(self.key), Nonce::new(nonce)).decrypt(text, tag, Some(aad)).is_ok();
        self.advance(nonce);
        ok
    }
}

/// The session keys of one connection and its ciphers in each direction.
pub struct Cipher {
    send_l: FsChaCha20,
    send_p: FsAead,
    recv_l: FsChaCha20,
    recv_p: FsAead,
    pub session_id: [u8; 32],
    pub send_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    pub recv_terminator: [u8; GARBAGE_TERMINATOR_LEN],
}

impl Cipher {
    /// The ECDH of our secret key with the peer's key, then the key derivation.
    pub fn new(
        secret: SecretKey,
        ours: ElligatorSwift,
        theirs: ElligatorSwift,
        initiating: bool,
        magic: [u8; 4],
    ) -> Cipher {
        let shared = if initiating {
            ElligatorSwift::shared_secret(ours, theirs, secret, ElligatorSwiftParty::A, None)
        } else {
            ElligatorSwift::shared_secret(theirs, ours, secret, ElligatorSwiftParty::B, None)
        };
        Cipher::from_shared_secret(shared.as_secret_bytes(), initiating, magic)
    }

    pub fn from_shared_secret(shared: &[u8; 32], initiating: bool, magic: [u8; 4]) -> Cipher {
        let mut salt = b"bitcoin_v2_shared_secret".to_vec();
        salt.extend_from_slice(&magic);
        let prk = hmac_sha256(&salt, &[shared]);
        let expand = |info: &[u8]| hmac_sha256(&prk, &[info, &[1]]);
        let terminators = expand(b"garbage_terminators");
        let (initiator_t, responder_t) = (terminators[..16].try_into().unwrap(), terminators[16..].try_into().unwrap());
        let (initiator_l, initiator_p) = (expand(b"initiator_L"), expand(b"initiator_P"));
        let (responder_l, responder_p) = (expand(b"responder_L"), expand(b"responder_P"));
        let (send_l, send_p, recv_l, recv_p, send_terminator, recv_terminator) = if initiating {
            (initiator_l, initiator_p, responder_l, responder_p, initiator_t, responder_t)
        } else {
            (responder_l, responder_p, initiator_l, initiator_p, responder_t, initiator_t)
        };
        Cipher {
            send_l: FsChaCha20::new(send_l),
            send_p: FsAead { key: send_p, packet_counter: 0 },
            recv_l: FsChaCha20::new(recv_l),
            recv_p: FsAead { key: recv_p, packet_counter: 0 },
            session_id: expand(b"session_id"),
            send_terminator,
            recv_terminator,
        }
    }

    /// One packet: the encrypted length, then header, contents and tag.
    pub fn encrypt(&mut self, contents: &[u8], aad: &[u8], ignore: bool) -> Vec<u8> {
        let len = contents.len();
        assert!(len < 1 << 24);
        let mut out = vec![0u8; LENGTH_LEN + HEADER_LEN + len + TAG_LEN];
        out[..LENGTH_LEN].copy_from_slice(&(len as u32).to_le_bytes()[..LENGTH_LEN]);
        self.send_l.crypt(&mut out[..LENGTH_LEN]);
        out[LENGTH_LEN] = if ignore { IGNORE_BIT } else { 0 };
        out[LENGTH_LEN + HEADER_LEN..LENGTH_LEN + HEADER_LEN + len].copy_from_slice(contents);
        let tag = self.send_p.encrypt(aad, &mut out[LENGTH_LEN..LENGTH_LEN + HEADER_LEN + len]);
        out[LENGTH_LEN + HEADER_LEN + len..].copy_from_slice(&tag);
        out
    }

    /// The contents length of the next packet.
    pub fn decrypt_length(&mut self, mut bytes: [u8; LENGTH_LEN]) -> usize {
        self.recv_l.crypt(&mut bytes);
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) as usize
    }

    /// Decrypt a packet's header, contents and tag in place. Returns whether the ignore bit is
    /// set, or None if the packet does not authenticate. The contents are then at
    /// packet[1..packet.len() - 16].
    pub fn decrypt(&mut self, packet: &mut [u8], aad: &[u8]) -> Option<bool> {
        let split = packet.len().checked_sub(TAG_LEN)?;
        let (text, tag) = packet.split_at_mut(split);
        if text.is_empty() || !self.recv_p.decrypt(aad, text, tag.try_into().unwrap()) {
            return None;
        }
        Some(text[0] & IGNORE_BIT != 0)
    }
}

/// The message type that contents begin with, and the payload after it. None as the type when it
/// cannot be decoded: no contents, an unknown short id, or a long type that is not ASCII padded
/// with zero bytes.
pub fn decode_contents(contents: &[u8]) -> (Option<String>, &[u8]) {
    let Some((&first, rest)) = contents.split_first() else { return (None, &[]) };
    if first != 0 {
        let msg_type = SHORT_IDS.iter().find(|(id, _)| *id == first).map(|(_, t)| t.to_string());
        return (msg_type, rest);
    }
    if rest.len() < MESSAGE_TYPE_SIZE {
        return (None, rest);
    }
    let (name, payload) = rest.split_at(MESSAGE_TYPE_SIZE);
    let len = name.iter().position(|b| *b == 0).unwrap_or(MESSAGE_TYPE_SIZE);
    if name[..len].iter().any(|b| !(b' '..=0x7e).contains(b)) || name[len..].iter().any(|b| *b != 0) {
        return (None, payload);
    }
    (Some(String::from_utf8(name[..len].to_vec()).unwrap()), payload)
}

/// Contents for a message: its short id where it has one, else the long type.
pub fn encode_contents(msg_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut contents = Vec::with_capacity(1 + MESSAGE_TYPE_SIZE + payload.len());
    if let Some((id, _)) = SHORT_IDS.iter().find(|(_, t)| *t == msg_type) {
        contents.push(*id);
    } else {
        assert!(msg_type.len() <= MESSAGE_TYPE_SIZE);
        contents.push(0);
        contents.extend_from_slice(msg_type.as_bytes());
        contents.resize(1 + MESSAGE_TYPE_SIZE, 0);
    }
    contents.extend_from_slice(payload);
    contents
}

/// A message received in full. msg_type is None when the type could not be decoded: the message
/// is then dropped, as Bitcoin Core drops it.
pub struct Received {
    pub msg_type: Option<String>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecvState {
    Key,
    GarbageTerminator,
    Version,
    App,
}

/// The transport failed: the connection must end.
#[derive(Debug, PartialEq, Eq)]
pub struct TransportError(pub &'static str);

pub struct V2Transport {
    magic: [u8; 4],
    secret: SecretKey,
    ours: ElligatorSwift,
    /// Our garbage, until it has authenticated the version packet.
    garbage: Vec<u8>,
    cipher: Option<Cipher>,
    send_buf: Vec<u8>,
    sent: usize,
    /// The version packet is queued: application messages may follow.
    ready: bool,
    recv_state: RecvState,
    recv_buf: Vec<u8>,
    recv_len: usize,
    /// The peer's garbage, which the first packet it sends authenticates.
    recv_aad: Vec<u8>,
    message: Option<Received>,
}

impl V2Transport {
    /// An initiator with this key, its ElligatorSwift encoding and this garbage of at most
    /// MAX_GARBAGE_LEN bytes, which it offers to send at once.
    pub fn new_initiator(magic: [u8; 4], secret: SecretKey, ours: ElligatorSwift, garbage: Vec<u8>) -> V2Transport {
        assert!(garbage.len() <= MAX_GARBAGE_LEN);
        let mut send_buf = ours.to_array().to_vec();
        send_buf.extend_from_slice(&garbage);
        V2Transport {
            magic,
            secret,
            ours,
            garbage,
            cipher: None,
            send_buf,
            sent: 0,
            ready: false,
            recv_state: RecvState::Key,
            recv_buf: Vec::new(),
            recv_len: 0,
            recv_aad: Vec::new(),
            message: None,
        }
    }

    pub fn bytes_to_send(&self) -> &[u8] {
        &self.send_buf[self.sent..]
    }

    pub fn mark_sent(&mut self, n: usize) {
        self.sent += n.min(self.send_buf.len() - self.sent);
        if self.ready && self.sent == self.send_buf.len() {
            self.send_buf.clear();
            self.sent = 0;
        }
    }

    /// Queue one message. False if the transport does not take one now: before the peer's key
    /// arrived, or while bytes are left to write.
    pub fn set_message(&mut self, msg_type: &str, payload: &[u8]) -> bool {
        if !self.ready || !self.bytes_to_send().is_empty() {
            return false;
        }
        let contents = encode_contents(msg_type, payload);
        self.send_buf = self.cipher.as_mut().unwrap().encrypt(&contents, &[], false);
        self.sent = 0;
        true
    }

    /// Process bytes from the peer, up to the end of the next complete message. Returns how many
    /// were consumed; take the message with take_message() before passing more.
    pub fn received_bytes(&mut self, bytes: &[u8]) -> Result<usize, TransportError> {
        let mut used = 0;
        while used < bytes.len() && self.message.is_none() {
            let rest = &bytes[used..];
            match self.recv_state {
                RecvState::Key => {
                    let n = rest.len().min(ELLSWIFT_LEN - self.recv_buf.len());
                    self.recv_buf.extend_from_slice(&rest[..n]);
                    used += n;
                    if self.recv_buf.len() == ELLSWIFT_LEN {
                        self.process_key();
                    }
                }
                RecvState::GarbageTerminator => {
                    let n = if self.recv_buf.len() < GARBAGE_TERMINATOR_LEN {
                        rest.len().min(GARBAGE_TERMINATOR_LEN - self.recv_buf.len())
                    } else {
                        1
                    };
                    self.recv_buf.extend_from_slice(&rest[..n]);
                    used += n;
                    let terminator = self.cipher.as_ref().unwrap().recv_terminator;
                    if self.recv_buf.ends_with(&terminator) {
                        self.recv_buf.truncate(self.recv_buf.len() - GARBAGE_TERMINATOR_LEN);
                        self.recv_aad = std::mem::take(&mut self.recv_buf);
                        self.recv_state = RecvState::Version;
                    } else if self.recv_buf.len() == MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN {
                        return Err(TransportError("missing garbage terminator"));
                    }
                }
                RecvState::Version | RecvState::App => {
                    if self.recv_buf.len() < LENGTH_LEN {
                        let n = rest.len().min(LENGTH_LEN - self.recv_buf.len());
                        self.recv_buf.extend_from_slice(&rest[..n]);
                        used += n;
                        if self.recv_buf.len() == LENGTH_LEN {
                            let len_bytes = self.recv_buf[..LENGTH_LEN].try_into().unwrap();
                            self.recv_len = self.cipher.as_mut().unwrap().decrypt_length(len_bytes);
                            if self.recv_len > MAX_CONTENTS_LEN {
                                return Err(TransportError("packet too large"));
                            }
                        }
                        continue;
                    }
                    let total = LENGTH_LEN + HEADER_LEN + self.recv_len + TAG_LEN;
                    let n = rest.len().min(total - self.recv_buf.len());
                    self.recv_buf.extend_from_slice(&rest[..n]);
                    used += n;
                    if self.recv_buf.len() == total {
                        self.process_packet()?;
                    }
                }
            }
        }
        Ok(used)
    }

    pub fn take_message(&mut self) -> Option<Received> {
        self.message.take()
    }

    fn process_key(&mut self) {
        let theirs = ElligatorSwift::from_array(self.recv_buf[..].try_into().unwrap());
        let mut cipher = Cipher::new(self.secret, self.ours, theirs, true, self.magic);
        // The garbage terminator, then the version packet, which authenticates our garbage.
        self.send_buf.extend_from_slice(&cipher.send_terminator);
        let garbage = std::mem::take(&mut self.garbage);
        self.send_buf.extend_from_slice(&cipher.encrypt(&[], &garbage, false));
        self.cipher = Some(cipher);
        self.ready = true;
        self.recv_buf.clear();
        self.recv_state = RecvState::GarbageTerminator;
    }

    fn process_packet(&mut self) -> Result<(), TransportError> {
        let mut packet = std::mem::take(&mut self.recv_buf);
        let aad = std::mem::take(&mut self.recv_aad);
        let ignore = self
            .cipher
            .as_mut()
            .unwrap()
            .decrypt(&mut packet[LENGTH_LEN..], &aad)
            .ok_or(TransportError("packet decryption failure"))?;
        if ignore {
            return Ok(());
        }
        if self.recv_state == RecvState::Version {
            // Its contents are ignored.
            self.recv_state = RecvState::App;
            return Ok(());
        }
        let contents = &packet[LENGTH_LEN + HEADER_LEN..packet.len() - TAG_LEN];
        let (msg_type, payload) = decode_contents(contents);
        self.message = Some(Received { msg_type, payload: payload.to_vec() });
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn packet_vectors() {
        const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
        let csv = include_str!("../testdata/bip324_packet_encoding_test_vectors.csv");
        let mut lines = csv.lines();
        let header: Vec<&str> = lines.next().unwrap().split(',').collect();
        let mut count = 0;
        for line in lines {
            let fields: Vec<&str> = line.split(',').collect();
            let get = |name: &str| fields[header.iter().position(|h| *h == name).unwrap()];
            let initiating = get("in_initiating") == "1";
            let secret = SecretKey::from_slice(&hex(get("in_priv_ours"))).unwrap();
            let ours = ElligatorSwift::from_array(hex(get("in_ellswift_ours")).try_into().unwrap());
            let theirs = ElligatorSwift::from_array(hex(get("in_ellswift_theirs")).try_into().unwrap());
            let mut cipher = Cipher::new(secret, ours, theirs, initiating, MAGIC);
            assert_eq!(to_hex(&cipher.session_id), get("out_session_id"));
            assert_eq!(to_hex(&cipher.send_terminator), get("mid_send_garbage_terminator"));
            assert_eq!(to_hex(&cipher.recv_terminator), get("mid_recv_garbage_terminator"));
            for _ in 0..get("in_idx").parse::<usize>().unwrap() {
                cipher.encrypt(&[], &[], false);
            }
            let contents = hex(get("in_contents")).repeat(get("in_multiply").parse().unwrap());
            let out = to_hex(&cipher.encrypt(&contents, &hex(get("in_aad")), get("in_ignore") == "1"));
            if !get("out_ciphertext").is_empty() {
                assert_eq!(out, get("out_ciphertext"));
            }
            if !get("out_ciphertext_endswith").is_empty() {
                assert!(out.ends_with(get("out_ciphertext_endswith")));
            }
            count += 1;
        }
        assert_eq!(count, 7);
    }

    #[test]
    fn contents() {
        assert_eq!(encode_contents("inv", &[1]), [14, 1]);
        let long = encode_contents("version", &[9]);
        assert_eq!(long[..8], [0, b'v', b'e', b'r', b's', b'i', b'o', b'n']);
        assert_eq!(long.len(), 14);
        assert_eq!(decode_contents(&long), (Some("version".to_string()), &[9u8][..]));
        assert_eq!(decode_contents(&[19, 1, 2]), (Some("pong".to_string()), &[1u8, 2][..]));
        assert_eq!(decode_contents(&[29]).0, None);
        assert_eq!(decode_contents(&[]).0, None);
        let mut bad = long.clone();
        bad[9] = b'x'; // after the first zero byte
        assert_eq!(decode_contents(&bad).0, None);
    }

    /// Messages as a peer receives them: type and payload.
    pub type Messages = Vec<(Option<String>, Vec<u8>)>;

    /// The responder side of a BIP324 connection, for tests.
    pub struct Responder {
        secret: SecretKey,
        ours: ElligatorSwift,
        pub cipher: Option<Cipher>,
        buf: Vec<u8>,
        garbage_done: bool,
        version_done: bool,
        aad: Vec<u8>,
        magic: [u8; 4],
    }

    impl Responder {
        pub fn new(magic: [u8; 4], seed: u8) -> Responder {
            let secp = Secp256k1::new();
            let secret = SecretKey::from_slice(&[seed.max(1); 32]).unwrap();
            let ours = ElligatorSwift::from_seckey(&secp, secret, Some([seed; 32]));
            Responder {
                secret,
                ours,
                cipher: None,
                buf: Vec::new(),
                garbage_done: false,
                version_done: false,
                aad: Vec::new(),
                magic,
            }
        }

        /// Our key, garbage and terminator and version packet, once the initiator's key is known.
        pub fn hello(&mut self, garbage: &[u8]) -> Vec<u8> {
            let mut out = self.ours.to_array().to_vec();
            out.extend_from_slice(garbage);
            self.aad = garbage.to_vec();
            out
        }

        /// Feed the initiator's bytes; returns the bytes to send back and the messages received.
        pub fn feed(&mut self, bytes: &[u8]) -> (Vec<u8>, Messages) {
            self.buf.extend_from_slice(bytes);
            let mut out = Vec::new();
            let mut messages = Vec::new();
            if self.cipher.is_none() {
                if self.buf.len() < ELLSWIFT_LEN {
                    return (out, messages);
                }
                let theirs = ElligatorSwift::from_array(self.buf[..ELLSWIFT_LEN].try_into().unwrap());
                let mut cipher = Cipher::new(self.secret, self.ours, theirs, false, self.magic);
                self.buf.drain(..ELLSWIFT_LEN);
                out.extend_from_slice(&cipher.send_terminator);
                let aad = std::mem::take(&mut self.aad);
                out.extend_from_slice(&cipher.encrypt(&[], &aad, false));
                self.cipher = Some(cipher);
            }
            let cipher = self.cipher.as_mut().unwrap();
            if !self.garbage_done {
                let Some(pos) = self.buf.windows(GARBAGE_TERMINATOR_LEN).position(|w| w == cipher.recv_terminator)
                else {
                    return (out, messages);
                };
                self.aad = self.buf[..pos].to_vec();
                self.buf.drain(..pos + GARBAGE_TERMINATOR_LEN);
                self.garbage_done = true;
            }
            while self.buf.len() >= LENGTH_LEN {
                // Peek at the length without consuming the cipher state twice.
                let mut probe = clone_l(&cipher.recv_l);
                let mut len = [self.buf[0], self.buf[1], self.buf[2]];
                probe.crypt(&mut len);
                let len = u32::from_le_bytes([len[0], len[1], len[2], 0]) as usize;
                let total = LENGTH_LEN + HEADER_LEN + len + TAG_LEN;
                if self.buf.len() < total {
                    break;
                }
                cipher.decrypt_length(self.buf[..LENGTH_LEN].try_into().unwrap());
                let mut packet: Vec<u8> = self.buf.drain(..total).collect();
                let aad = std::mem::take(&mut self.aad);
                let ignore = cipher.decrypt(&mut packet[LENGTH_LEN..], &aad).expect("authenticates");
                if ignore {
                    continue;
                }
                if !self.version_done {
                    self.version_done = true;
                    continue;
                }
                let (t, p) = decode_contents(&packet[LENGTH_LEN + HEADER_LEN..packet.len() - TAG_LEN]);
                messages.push((t, p.to_vec()));
            }
            (out, messages)
        }

        pub fn send(&mut self, msg_type: &str, payload: &[u8]) -> Vec<u8> {
            self.cipher.as_mut().unwrap().encrypt(&encode_contents(msg_type, payload), &[], false)
        }
    }

    fn clone_l(l: &FsChaCha20) -> FsChaCha20 {
        FsChaCha20 {
            key: l.key,
            chunk_counter: l.chunk_counter,
            rekey_counter: l.rekey_counter,
            block: l.block,
            buf: l.buf,
            pos: l.pos,
        }
    }

    #[test]
    fn handshake_and_messages() {
        let magic = [0xfa, 0xbf, 0xb5, 0xda];
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let ours = ElligatorSwift::from_seckey(&secp, secret, Some([4; 32]));
        let mut t = V2Transport::new_initiator(magic, secret, ours, vec![7; 100]);
        let mut peer = Responder::new(magic, 9);
        assert!(!t.set_message("version", &[1]));
        let first = t.bytes_to_send().to_vec();
        t.mark_sent(first.len());
        let mut reply = peer.hello(&[5; 33]);
        let (back, _) = peer.feed(&first);
        reply.extend_from_slice(&back);
        reply.extend_from_slice(&peer.send("pong", &[1, 2, 3, 4, 5, 6, 7, 8]));
        // Byte by byte, to cover every partial state.
        let mut messages = Vec::new();
        for b in &reply {
            assert_eq!(t.received_bytes(&[*b]), Ok(1));
            if let Some(m) = t.take_message() {
                messages.push(m);
            }
        }
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].msg_type.as_deref(), Some("pong"));
        let out = t.bytes_to_send().to_vec();
        t.mark_sent(out.len());
        assert!(t.set_message("version", &[1, 2]));
        assert!(!t.set_message("verack", &[]));
        let mut out2 = out;
        out2.extend_from_slice(t.bytes_to_send());
        let n = t.bytes_to_send().len();
        t.mark_sent(n);
        let (_, got) = peer.feed(&out2);
        assert_eq!(got, vec![(Some("version".to_string()), vec![1, 2])]);
        // A packet that does not authenticate fails the transport.
        let mut bad = peer.send("ping", &[0; 8]);
        bad[5] ^= 1;
        assert!(t.received_bytes(&bad).is_err());
    }

    #[test]
    fn missing_terminator() {
        let magic = [0xfa, 0xbf, 0xb5, 0xda];
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let ours = ElligatorSwift::from_seckey(&secp, secret, None);
        let mut t = V2Transport::new_initiator(magic, secret, ours, Vec::new());
        let mut peer = Responder::new(magic, 9);
        let mut bytes = peer.hello(&[]);
        bytes.extend_from_slice(&[0u8; MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN]);
        let mut result = Ok(0);
        let mut pos = 0;
        while pos < bytes.len() {
            result = t.received_bytes(&bytes[pos..]);
            match &result {
                Ok(n) => pos += n,
                Err(_) => break,
            }
        }
        assert_eq!(result, Err(TransportError("missing garbage terminator")));
    }
}
