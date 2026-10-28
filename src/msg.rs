//! The P2P payloads a job sends and the ones it reads. Reading is strict: a message the job acts
//! on is malformed if it does not decode or has bytes left over (E7), as Bitcoin Core's
//! deserializers decide it (canonical CompactSize, at most 0x02000000).

use crate::params::{PROFILE_SERVICES, PROFILE_USER_AGENT, PROFILE_VERSION};

pub const MSG_WTX: u32 = 5;
/// The longest user agent a VERSION may carry (E2).
pub const MAX_USER_AGENT_LENGTH: usize = 256;
/// The largest CompactSize a length may have.
const MAX_SIZE: u64 = 0x0200_0000;
/// addr_recv or addr_from in a VERSION: services, address and port.
const VERSION_ADDRESS_SIZE: usize = 8 + 16 + 2;

/// The job's VERSION (E1): the profile, time 0, addr_recv null with services 0, addr_from null
/// with the profile's services, this nonce, start height 0 and relay false.
pub fn version(nonce: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(100);
    out.extend_from_slice(&PROFILE_VERSION.to_le_bytes());
    out.extend_from_slice(&PROFILE_SERVICES.to_le_bytes());
    out.extend_from_slice(&0i64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&[0; 18]);
    out.extend_from_slice(&PROFILE_SERVICES.to_le_bytes());
    out.extend_from_slice(&[0; 18]);
    out.extend_from_slice(&nonce.to_le_bytes());
    write_compact_size(&mut out, PROFILE_USER_AGENT.len() as u64);
    out.extend_from_slice(PROFILE_USER_AGENT.as_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.push(0);
    out
}

/// One INV with one entry: MSG_WTX for the wtxid (E3).
pub fn inv(wtxid: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&MSG_WTX.to_le_bytes());
    out.extend_from_slice(wtxid);
    out
}

pub fn ping(nonce: u64) -> Vec<u8> {
    nonce.to_le_bytes().to_vec()
}

fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=252 => out.push(n as u8),
        253..=0xffff => {
            out.push(253);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(254);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(255);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// The payload did not decode.
#[derive(Debug, PartialEq, Eq)]
pub struct Malformed;

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if self.data.len() < n {
            return Err(Malformed);
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Malformed> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn compact_size(&mut self) -> Result<u64, Malformed> {
        let n = match self.array::<1>()?[0] {
            253 => {
                let n = u16::from_le_bytes(self.array()?) as u64;
                if n < 253 {
                    return Err(Malformed);
                }
                n
            }
            254 => {
                let n = u32::from_le_bytes(self.array()?) as u64;
                if n < 0x1_0000 {
                    return Err(Malformed);
                }
                n
            }
            255 => {
                let n = u64::from_le_bytes(self.array()?);
                if n < 0x1_0000_0000 {
                    return Err(Malformed);
                }
                n
            }
            n => n as u64,
        };
        if n > MAX_SIZE {
            return Err(Malformed);
        }
        Ok(n)
    }

    fn end(&self) -> Result<(), Malformed> {
        if self.data.is_empty() { Ok(()) } else { Err(Malformed) }
    }
}

/// What the job reads of a peer's VERSION.
#[derive(Debug, PartialEq, Eq)]
pub struct PeerVersion {
    pub version: i32,
    pub services: u64,
    pub user_agent: Vec<u8>,
    pub relay: bool,
}

/// Every field up to the relay flag, a user agent of at most 256 bytes, nothing after the flag
/// (E2). Time, nonce, start height and both addresses are read and ignored.
pub fn parse_version(payload: &[u8]) -> Result<PeerVersion, Malformed> {
    let mut r = Reader { data: payload };
    let version = i32::from_le_bytes(r.array()?);
    let services = u64::from_le_bytes(r.array()?);
    r.take(8)?; // time
    r.take(2 * VERSION_ADDRESS_SIZE)?;
    r.take(8)?; // nonce
    let len = r.compact_size()?;
    if len > MAX_USER_AGENT_LENGTH as u64 {
        return Err(Malformed);
    }
    let user_agent = r.take(len as usize)?.to_vec();
    r.take(4)?; // start height
    let relay = r.array::<1>()?[0] != 0;
    r.end()?;
    Ok(PeerVersion { version, services, user_agent, relay })
}

/// The entries of a GETDATA, by type and hash.
pub fn parse_getdata(payload: &[u8]) -> Result<Vec<(u32, [u8; 32])>, Malformed> {
    let mut r = Reader { data: payload };
    let n = r.compact_size()?;
    if n.saturating_mul(36) > r.data.len() as u64 {
        return Err(Malformed);
    }
    let mut entries = Vec::with_capacity(n as usize);
    for _ in 0..n {
        entries.push((u32::from_le_bytes(r.array()?), r.array()?));
    }
    r.end()?;
    Ok(entries)
}

/// A PONG's nonce.
pub fn parse_pong(payload: &[u8]) -> Result<u64, Malformed> {
    let mut r = Reader { data: payload };
    let nonce = u64::from_le_bytes(r.array()?);
    r.end()?;
    Ok(nonce)
}

/// A user agent as the report shows it: only the characters Bitcoin Core's SanitizeString keeps.
pub fn sanitize(user_agent: &[u8]) -> String {
    const SAFE: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890 .,;-_/:?@()";
    user_agent.iter().filter(|b| SAFE.contains(b)).map(|b| *b as char).collect()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A peer's VERSION, with bytes after the relay flag if given.
    pub fn peer_version(version: i32, services: u64, user_agent: &[u8], relay: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&services.to_le_bytes());
        out.extend_from_slice(&[0; 8 + 52 + 8]);
        write_compact_size(&mut out, user_agent.len() as u64);
        out.extend_from_slice(user_agent);
        out.extend_from_slice(&[0; 4]);
        out.push(relay as u8);
        out
    }

    #[test]
    fn our_version() {
        let v = version(0x0102030405060708);
        assert_eq!(v.len(), 100);
        let parsed = parse_version(&v).unwrap();
        assert_eq!(
            parsed,
            PeerVersion { version: 70016, services: 8, user_agent: b"/pynode:0.0.1/".to_vec(), relay: false }
        );
    }

    #[test]
    fn strict_version() {
        let ok = peer_version(70016, 9, b"/Satoshi:30.0.0/", true);
        assert!(parse_version(&ok).is_ok());
        let mut extra = ok.clone();
        extra.push(0);
        assert_eq!(parse_version(&extra), Err(Malformed));
        assert_eq!(parse_version(&ok[..ok.len() - 1]), Err(Malformed));
        assert!(parse_version(&peer_version(70016, 9, &[b'a'; 256], true)).is_ok());
        assert_eq!(parse_version(&peer_version(70016, 9, &[b'a'; 257], true)), Err(Malformed));
        // A non-canonical length.
        let mut noncanonical = ok[..80].to_vec();
        noncanonical.extend_from_slice(&[253, 1, 0, b'x']);
        noncanonical.extend_from_slice(&[0; 5]);
        assert_eq!(parse_version(&noncanonical), Err(Malformed));
    }

    #[test]
    fn getdata_and_pong() {
        let mut one = inv(&[7; 32]);
        assert_eq!(parse_getdata(&one), Ok(vec![(MSG_WTX, [7; 32])]));
        one.push(0);
        assert_eq!(parse_getdata(&one), Err(Malformed));
        assert_eq!(parse_getdata(&[2, 0]), Err(Malformed));
        assert_eq!(parse_getdata(&[0]), Ok(vec![]));
        assert_eq!(parse_pong(&ping(5)), Ok(5));
        assert_eq!(parse_pong(&[0; 9]), Err(Malformed));
        assert_eq!(parse_pong(&[0; 7]), Err(Malformed));
    }

    #[test]
    fn sanitized() {
        assert_eq!(sanitize(b"/Satoshi:30.0.0(x)/\n<b>"), "/Satoshi:30.0.0(x)/b");
    }
}
