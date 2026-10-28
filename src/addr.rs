//! Recipient addresses: which RESOLVE answers are usable (R2), and how an address is written in the
//! report and in a SOCKS5 request. The classification follows Bitcoin Core's CNetAddr.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// An address with the chain's default port: a candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub addr: Addr,
    pub port: u16,
}

const IPV4_IN_IPV6_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
/// Bitcoin Core reads these as an invalid address and an internal name, neither IPv4 nor IPv6.
const TORV2_IN_IPV6_PREFIX: [u8; 6] = [0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43];
const INTERNAL_IN_IPV6_PREFIX: [u8; 6] = [0xfd, 0x6b, 0x88, 0xc0, 0x87, 0x24];

impl Addr {
    /// The address an IPv6 RESOLVE answer stands for, as Bitcoin Core reads it: an IPv4-mapped
    /// address is IPv4, and the TORv2 and internal prefixes are neither IPv4 nor IPv6.
    pub fn from_ipv6_answer(bytes: [u8; 16]) -> Option<Addr> {
        if bytes.starts_with(&IPV4_IN_IPV6_PREFIX) {
            return Some(Addr::V4([bytes[12], bytes[13], bytes[14], bytes[15]]));
        }
        if bytes.starts_with(&TORV2_IN_IPV6_PREFIX) || bytes.starts_with(&INTERNAL_IN_IPV6_PREFIX) {
            return None;
        }
        Some(Addr::V6(bytes))
    }

    fn is_valid(&self) -> bool {
        match self {
            Addr::V4(a) => *a != [0, 0, 0, 0] && *a != [255, 255, 255, 255],
            Addr::V6(a) => {
                // Unspecified, and the documentation ranges RFC 3849 and RFC 9637.
                *a != [0; 16]
                    && !a.starts_with(&[0x20, 0x01, 0x0d, 0xb8])
                    && !(a[0] == 0x3f && a[1] == 0xff && a[2] & 0xf0 == 0)
            }
        }
    }

    /// A public, routable IPv4 or IPv6 address (R2).
    pub fn is_routable(&self) -> bool {
        if !self.is_valid() {
            return false;
        }
        match self {
            Addr::V4(a) => {
                let private = a[0] == 10 || (a[0] == 192 && a[1] == 168) || (a[0] == 172 && (16..=31).contains(&a[1]));
                let benchmark = a[0] == 198 && (a[1] == 18 || a[1] == 19);
                let link_local = a[0] == 169 && a[1] == 254;
                let shared = a[0] == 100 && (64..=127).contains(&a[1]);
                let documentation =
                    a.starts_with(&[192, 0, 2]) || a.starts_with(&[198, 51, 100]) || a.starts_with(&[203, 0, 113]);
                let local = a[0] == 127 || a[0] == 0;
                !(private || benchmark || link_local || shared || documentation || local)
            }
            Addr::V6(a) => {
                let link_local = a.starts_with(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
                let unique_local = a[0] & 0xfe == 0xfc;
                let orchid = a.starts_with(&[0x20, 0x01, 0x00]) && a[3] & 0xf0 == 0x10;
                let orchid2 = a.starts_with(&[0x20, 0x01, 0x00]) && a[3] & 0xf0 == 0x20;
                let loopback = *a == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
                !(link_local || unique_local || orchid || orchid2 || loopback)
            }
        }
    }

    /// The name a SOCKS5 request carries for this address: an IPv6 address with all eight groups,
    /// because Tor copies the name into its BEGIN cell as "<name>:<port>" and an exit reads a
    /// shortened IPv6 address followed by the port as one address with no port.
    pub fn socks5_host(&self) -> String {
        match self {
            Addr::V4(_) => self.to_string(),
            Addr::V6(a) => groups(a).iter().map(|g| format!("{g:x}")).collect::<Vec<_>>().join(":"),
        }
    }
}

fn groups(a: &[u8; 16]) -> [u16; 8] {
    std::array::from_fn(|i| u16::from_be_bytes([a[2 * i], a[2 * i + 1]]))
}

impl fmt::Display for Addr {
    /// IPv4 dotted, IPv6 as RFC 5952 writes it: the longest run of two or more zero groups, the
    /// first of equal runs, shortened to "::".
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Addr::V4(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Addr::V6(a) => {
                let g = groups(a);
                let (mut best_start, mut best_len) = (0, 0);
                let mut i = 0;
                while i < 8 {
                    if g[i] == 0 {
                        let start = i;
                        while i < 8 && g[i] == 0 {
                            i += 1;
                        }
                        if i - start > best_len {
                            (best_start, best_len) = (start, i - start);
                        }
                    } else {
                        i += 1;
                    }
                }
                let hex = |range: &[u16]| range.iter().map(|x| format!("{x:x}")).collect::<Vec<_>>().join(":");
                if best_len < 2 {
                    write!(f, "{}", hex(&g))
                } else {
                    write!(f, "{}::{}", hex(&g[..best_start]), hex(&g[best_start + best_len..]))
                }
            }
        }
    }
}

impl fmt::Display for Endpoint {
    /// Address and port, an IPv6 address in brackets.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.addr {
            Addr::V4(_) => write!(f, "{}:{}", self.addr, self.port),
            Addr::V6(_) => write!(f, "[{}]:{}", self.addr, self.port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn v6(s: &str) -> Addr {
        Addr::V6(s.parse::<Ipv6Addr>().unwrap().octets())
    }

    #[test]
    fn routable() {
        for a in ["1.2.3.4", "8.8.8.8", "100.63.0.1", "172.32.0.1"] {
            let o: std::net::Ipv4Addr = a.parse().unwrap();
            assert!(Addr::V4(o.octets()).is_routable(), "{a}");
        }
        for a in [
            "10.0.0.1",
            "127.0.0.1",
            "0.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "255.255.255.255",
        ] {
            let o: std::net::Ipv4Addr = a.parse().unwrap();
            assert!(!Addr::V4(o.octets()).is_routable(), "{a}");
        }
        assert!(v6("2a00::71").is_routable());
        for a in ["::", "::1", "fe80::1", "fc00::1", "2001:db8::1", "2001:10::1", "2001:20::1", "3fff::1"] {
            assert!(!v6(a).is_routable(), "{a}");
        }
    }

    #[test]
    fn ipv6_answers() {
        assert_eq!(
            Addr::from_ipv6_answer("::ffff:1.2.3.4".parse::<Ipv6Addr>().unwrap().octets()),
            Some(Addr::V4([1, 2, 3, 4]))
        );
        assert_eq!(Addr::from_ipv6_answer("fd87:d87e:eb43::1".parse::<Ipv6Addr>().unwrap().octets()), None);
        assert_eq!(Addr::from_ipv6_answer("fd6b:88c0:8724::1".parse::<Ipv6Addr>().unwrap().octets()), None);
    }

    #[test]
    fn strings() {
        assert_eq!(v6("2001:db8:0:0:0:0:0:1").to_string(), "2001:db8::1");
        assert_eq!(v6("2001:0:0:1:0:0:0:1").to_string(), "2001:0:0:1::1");
        assert_eq!(v6("2001:db8:0:1:1:1:1:1").to_string(), "2001:db8:0:1:1:1:1:1");
        assert_eq!(v6("::").to_string(), "::");
        assert_eq!(v6("1::").to_string(), "1::");
        assert_eq!(v6("2a00::71").socks5_host(), "2a00:0:0:0:0:0:0:71");
        assert_eq!(Endpoint { addr: v6("2a00::71"), port: 8333 }.to_string(), "[2a00::71]:8333");
        assert_eq!(Endpoint { addr: Addr::V4([1, 2, 3, 4]), port: 8333 }.to_string(), "1.2.3.4:8333");
    }
}
