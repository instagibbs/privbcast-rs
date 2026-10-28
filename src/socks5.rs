//! The client side of one SOCKS5 exchange (RFC 1928) with username and password authentication
//! (RFC 1929), driven by bytes. It owns no socket and reads no clock.

use crate::addr::Addr;
use crate::rng::Rng;

const SOCKS_VERSION: u8 = 0x05;
/// RFC 1929 username and password authentication, the only method offered (B2).
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCESS: u8 = 0x00;
const REPLY_SUCCEEDED: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAINNAME: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
/// Random bytes in each of the username and the password, which are sent hex encoded.
const CREDENTIAL_BYTES: usize = 16;
/// VER, REP, RSV and ATYP, before the bound address.
const REPLY_HEAD_SIZE: usize = 4;
/// A username that begins with this selects Tor's extended SOCKS5 parameters (Tor proposal 351).
const TOR_EXTENSIONS_MARKER: &str = "<torS0X>";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Open a stream to the destination.
    Connect = 0x01,
    /// Tor's extension: resolve a name to one address, returned in the reply.
    Resolve = 0xF0,
}

/// The username and password a stream presents to the proxy, which puts streams with different
/// credentials on different circuits (B2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Credentials {
    /// Fresh random credentials.
    pub fn draw(rng: &mut Rng) -> Credentials {
        let hex = |bytes: [u8; CREDENTIAL_BYTES]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        Credentials { username: hex(rng.bytes()), password: hex(rng.bytes()) }
    }
}

/// Whether a SOCKS5 request can carry host as its destination: one to 255 bytes, none NUL.
pub fn can_carry(host: &str) -> bool {
    !host.is_empty() && host.len() <= 255 && !host.contains('\0')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Method,
    Auth,
    Reply,
    Done,
    Failed,
}

/// The greeting offers username and password authentication only. A proxy that selects any other
/// method fails the exchange. Each reply is accepted only once the message it answers has been
/// written in full.
pub struct Socks5Client {
    cmd: Command,
    credentials: Credentials,
    /// The CONNECT or RESOLVE request, sent once authenticated.
    request: Vec<u8>,
    stage: Stage,
    /// The message being written, and how much of it was.
    send: Vec<u8>,
    sent: usize,
    /// The reply received so far, and its length once known.
    reply: Vec<u8>,
    reply_size: usize,
    reason: String,
    answer: Option<Option<Addr>>,
}

impl Socks5Client {
    /// host goes as DOMAINNAME, a numeric address too, so that nothing is looked up here (B1) and
    /// Tor's SafeSocks accepts it. A host or credentials that cannot be sent fail the exchange
    /// before anything is sent.
    pub fn new(cmd: Command, host: &str, port: u16, credentials: Credentials) -> Socks5Client {
        let mut client = Socks5Client {
            cmd,
            credentials,
            request: Vec::new(),
            stage: Stage::Method,
            send: Vec::new(),
            sent: 0,
            reply: Vec::new(),
            reply_size: 0,
            reason: String::new(),
            answer: None,
        };
        if !can_carry(host) {
            client.fail("destination is not a name or address that SOCKS5 can carry".into());
            return client;
        }
        let Credentials { username, password } = &client.credentials;
        if username.is_empty()
            || username.len() > 255
            || password.is_empty()
            || password.len() > 255
            || username.starts_with(TOR_EXTENSIONS_MARKER)
        {
            client.fail("credentials are not 1 to 255 bytes each, or select Tor's extensions".into());
            return client;
        }
        // VER CMD RSV ATYP DST.ADDR DST.PORT (RFC 1928 section 4).
        client.request = vec![SOCKS_VERSION, cmd as u8, 0x00, ATYP_DOMAINNAME, host.len() as u8];
        client.request.extend_from_slice(host.as_bytes());
        client.request.extend_from_slice(&port.to_be_bytes());
        // VER NMETHODS METHODS (RFC 1928 section 3).
        client.send = vec![SOCKS_VERSION, 0x01, METHOD_USERNAME_PASSWORD];
        client
    }

    /// What to write next. Empty while waiting for the proxy, once done and once failed.
    pub fn bytes_to_send(&self) -> &[u8] {
        &self.send[self.sent..]
    }

    /// The first n bytes of bytes_to_send() were written.
    pub fn mark_sent(&mut self, n: usize) {
        self.sent += n.min(self.send.len() - self.sent);
    }

    /// Process bytes from the proxy. Returns how many were consumed: all of them until the
    /// exchange ends, none after it. Bytes past the final reply are the caller's.
    pub fn received(&mut self, bytes: &[u8]) -> usize {
        let mut used = 0;
        while used < bytes.len() && matches!(self.stage, Stage::Method | Stage::Auth | Stage::Reply) {
            let byte = bytes[used];
            used += 1;
            if self.sent < self.send.len() {
                self.fail("proxy replied before the request was written".into());
                break;
            }
            self.reply.push(byte);
            self.parse();
        }
        used
    }

    pub fn done(&self) -> bool {
        self.stage == Stage::Done
    }

    pub fn failed(&self) -> bool {
        self.stage == Stage::Failed
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// For RESOLVE once done: Some(None) if the reply carried an address that is neither IPv4
    /// nor IPv6, or a name; None before the reply.
    pub fn answer(&self) -> Option<Option<Addr>> {
        self.answer
    }

    fn parse(&mut self) {
        let pos = self.reply.len() - 1;
        let byte = self.reply[pos];
        match self.stage {
            Stage::Method => {
                // VER METHOD (RFC 1928 section 3)
                if pos == 0 && byte != SOCKS_VERSION {
                    return self.fail(format!("malformed method selection: version {byte}"));
                }
                if pos == 1 {
                    if byte != METHOD_USERNAME_PASSWORD {
                        return self.fail(format!(
                            "proxy selected method 0x{byte:02x}, not username and password authentication"
                        ));
                    }
                    // VER ULEN UNAME PLEN PASSWD (RFC 1929 section 2)
                    let Credentials { username, password } = &self.credentials;
                    let mut auth = vec![AUTH_VERSION, username.len() as u8];
                    auth.extend_from_slice(username.as_bytes());
                    auth.push(password.len() as u8);
                    auth.extend_from_slice(password.as_bytes());
                    self.next(Stage::Auth, auth);
                }
            }
            Stage::Auth => {
                // VER STATUS (RFC 1929 section 2)
                if pos == 0 && byte != AUTH_VERSION {
                    return self.fail(format!("malformed authentication reply: version {byte}"));
                }
                if pos == 1 {
                    if byte != AUTH_SUCCESS {
                        return self.fail(format!("proxy refused the credentials: status 0x{byte:02x}"));
                    }
                    let request = std::mem::take(&mut self.request);
                    self.next(Stage::Reply, request);
                }
            }
            Stage::Reply => {
                // VER REP RSV ATYP BND.ADDR BND.PORT (RFC 1928 section 6)
                if pos == 0 && byte != SOCKS_VERSION {
                    return self.fail(format!("malformed reply: version {byte}"));
                }
                if pos == 1 && byte != REPLY_SUCCEEDED {
                    return self.fail(format!("proxy reply 0x{byte:02x}: {}", error_string(byte)));
                }
                if pos == 2 && byte != 0x00 {
                    return self.fail("malformed reply: reserved byte set".into());
                }
                if pos == 3 {
                    match byte {
                        ATYP_IPV4 => self.reply_size = REPLY_HEAD_SIZE + 4 + 2,
                        ATYP_IPV6 => self.reply_size = REPLY_HEAD_SIZE + 16 + 2,
                        ATYP_DOMAINNAME => {} // the length comes next
                        _ => return self.fail(format!("malformed reply: address type 0x{byte:02x}")),
                    }
                }
                if pos == REPLY_HEAD_SIZE && self.reply[3] == ATYP_DOMAINNAME {
                    if byte == 0 {
                        return self.fail("malformed reply: empty name".into());
                    }
                    self.reply_size = REPLY_HEAD_SIZE + 1 + byte as usize + 2;
                }
                if pos >= REPLY_HEAD_SIZE && self.reply.len() == self.reply_size {
                    let bound = &self.reply[REPLY_HEAD_SIZE..];
                    if self.cmd == Command::Resolve {
                        self.answer = Some(match self.reply[3] {
                            ATYP_IPV4 => Some(Addr::V4(bound[..4].try_into().unwrap())),
                            ATYP_IPV6 => Addr::from_ipv6_answer(bound[..16].try_into().unwrap()),
                            _ => None,
                        });
                    }
                    self.stage = Stage::Done;
                }
            }
            Stage::Done | Stage::Failed => unreachable!("no byte is parsed once the exchange has ended"),
        }
    }

    /// Await the reply to msg, which is written next.
    fn next(&mut self, stage: Stage, msg: Vec<u8>) {
        self.stage = stage;
        self.send = msg;
        self.sent = 0;
        self.reply.clear();
    }

    fn fail(&mut self, reason: String) {
        self.stage = Stage::Failed;
        self.reason = reason;
        self.send.clear();
        self.sent = 0;
    }
}

/// The meaning of a SOCKS5 reply code, with Tor's extended codes.
fn error_string(code: u8) -> String {
    match code {
        0x01 => "general failure",
        0x02 => "connection not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "protocol error",
        0x08 => "address type not supported",
        0xf0 => "onion service descriptor can not be found",
        0xf1 => "onion service descriptor is invalid",
        0xf2 => "onion service introduction failed",
        0xf3 => "onion service rendezvous failed",
        0xf4 => "onion service missing client authorization",
        0xf5 => "onion service wrong client authorization",
        0xf6 => "onion service invalid address",
        0xf7 => "onion service introduction timed out",
        _ => return format!("unknown (0x{code:02x})"),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials { username: "u".into(), password: "pw".into() }
    }

    /// Run the client to the end against a proxy that sends these replies, each after the client
    /// wrote what it had. Returns what the client wrote.
    fn exchange(client: &mut Socks5Client, replies: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut written = Vec::new();
        for reply in replies {
            written.push(client.bytes_to_send().to_vec());
            let n = client.bytes_to_send().len();
            client.mark_sent(n);
            client.received(reply);
        }
        written
    }

    #[test]
    fn connect() {
        let mut client = Socks5Client::new(Command::Connect, "2a00:0:0:0:0:0:0:71", 8333, creds());
        let written = exchange(&mut client, &[&[5, 2], &[1, 0], &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]]);
        assert!(client.done());
        assert_eq!(written[0], [5, 1, 2]);
        assert_eq!(written[1], [1, 1, b'u', 2, b'p', b'w']);
        let mut request = vec![5, 1, 0, 3, 19];
        request.extend_from_slice(b"2a00:0:0:0:0:0:0:71");
        request.extend_from_slice(&8333u16.to_be_bytes());
        assert_eq!(written[2], request);
        assert_eq!(client.answer(), None);
    }

    #[test]
    fn resolve() {
        let mut client = Socks5Client::new(Command::Resolve, "seed.example.", 0, creds());
        exchange(&mut client, &[&[5, 2], &[1, 0], &[5, 0, 0, 1, 1, 2, 3, 4, 0, 0]]);
        assert_eq!(client.answer(), Some(Some(Addr::V4([1, 2, 3, 4]))));
        let mut client = Socks5Client::new(Command::Resolve, "seed.example.", 0, creds());
        exchange(&mut client, &[&[5, 2], &[1, 0], &[5, 0, 0, 3, 1, b'x', 0, 0]]);
        assert_eq!(client.answer(), Some(None));
    }

    #[test]
    fn failures() {
        let mut client = Socks5Client::new(Command::Connect, "x", 1, creds());
        exchange(&mut client, &[&[5, 0]]);
        assert!(client.failed());
        let mut client = Socks5Client::new(Command::Connect, "x", 1, creds());
        exchange(&mut client, &[&[5, 2], &[1, 1]]);
        assert!(client.failed());
        let mut client = Socks5Client::new(Command::Connect, "x", 1, creds());
        exchange(&mut client, &[&[5, 2], &[1, 0], &[5, 1]]);
        assert_eq!(client.reason(), "proxy reply 0x01: general failure");
        // A reply before the request was written in full.
        let mut client = Socks5Client::new(Command::Connect, "x", 1, creds());
        assert_eq!(client.received(&[5]), 1);
        assert!(client.failed());
        assert!(Socks5Client::new(Command::Connect, "", 1, creds()).failed());
        let tor = Credentials { username: "<torS0X>0".into(), password: "p".into() };
        assert!(Socks5Client::new(Command::Connect, "x", 1, tor).failed());
    }

    #[test]
    fn trailing_bytes_are_the_callers() {
        let mut client = Socks5Client::new(Command::Connect, "x", 1, creds());
        client.mark_sent(3);
        client.received(&[5, 2]);
        client.mark_sent(client.bytes_to_send().len());
        client.received(&[1, 0]);
        client.mark_sent(client.bytes_to_send().len());
        assert_eq!(client.received(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb]), 10);
        assert!(client.done());
    }

    /// Random replies in random chunks, after each message is written in part or in full: the
    /// client never panics, never consumes more than it is given, and once done offers nothing.
    #[test]
    fn random_replies() {
        let iterations: u64 = std::env::var("PRIVBCAST_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(300);
        let mut done = 0;
        for i in 0..iterations * 10 {
            let mut rng = Rng::from_key([
                (i % 256) as u8,
                (i / 256) as u8,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                23,
                24,
                25,
                26,
                27,
                28,
                29,
                30,
            ]);
            let cmd = if rng.randrange(2) == 0 { Command::Connect } else { Command::Resolve };
            let mut client = Socks5Client::new(cmd, "seed.example.", 8333, creds());
            // The proxy's replies in order, each built mostly right, so that the exchange goes far.
            let atyp = [1u8, 1, 3, 4, 7][rng.randrange(5) as usize];
            let mut reply = vec![5u8, 0, 0, atyp];
            reply.extend(match atyp {
                1 => vec![1, 2, 3, 4, 0, 0],
                3 => vec![2, b'a', b'b', 0, 0],
                4 => vec![0x2a; 18],
                _ => vec![],
            });
            let script = [vec![5u8, 2], vec![1, 0], reply];
            for message in &script {
                // Usually the whole message is written before the reply arrives.
                let n = client.bytes_to_send().len();
                client.mark_sent(if rng.randrange(8) == 0 { rng.randrange(n as u64 + 1) as usize } else { n });
                let mut bytes = message.clone();
                if rng.randrange(6) == 0 {
                    let k = rng.randrange(bytes.len() as u64) as usize;
                    bytes[k] = rng.bytes::<1>()[0];
                }
                let mut tail = vec![0u8; if message[0] == 5 && message.len() > 2 { rng.randrange(8) as usize } else { 0 }];
                rng.fill(&mut tail);
                bytes.extend(tail);
                // In random chunks.
                let mut pos = 0;
                while pos < bytes.len() {
                    let take = (rng.randrange(bytes.len() as u64) as usize + 1).min(bytes.len() - pos);
                    let used = client.received(&bytes[pos..pos + take]);
                    assert!(used <= take);
                    pos += take;
                    if client.done() || client.failed() {
                        break;
                    }
                }
                assert!(!(client.done() && client.failed()));
                if client.done() || client.failed() {
                    assert!(client.bytes_to_send().is_empty());
                    assert_eq!(client.received(&[5, 0]), 0, "nothing is consumed once the exchange ended");
                    break;
                }
            }
            if client.done() {
                done += 1;
                assert_eq!(client.answer().is_some(), cmd == Command::Resolve);
            }
        }
        assert!(done > 0);
    }
}
