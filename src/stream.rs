//! One stream through the SOCKS5 proxy, with blocking I/O on the thread that owns it: the connect
//! to the proxy, over TCP or a unix socket, then the exchange of its Socks5Client. Once the proxy
//! has answered the request the stream is open and carries the destination's bytes, starting with
//! any that arrived with the reply.
//!
//! The proxy is an address or a path, so nothing is resolved (B1). Each stage, the connect and each
//! step of the exchange, has SOCKS_STAGE_TIMEOUT, and the whole is bounded by the caller's deadline.
//! No call blocks longer than LOOP_WAIT before the stop flag is checked again. A connect cannot be
//! interrupted, so it is bounded by its timeout alone.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::params::LOOP_WAIT;
use crate::socks5::Socks5Client;

/// The most read from the proxy at a time during the exchange. Its final reply has at most 262
/// bytes; anything after it is the destination's.
const REPLY_READ_SIZE: usize = 512;

/// Where the proxy listens: a TCP endpoint or a unix socket path, never a name (B1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proxy {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl fmt::Display for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Proxy::Tcp(addr) => write!(f, "{addr}"),
            #[cfg(unix)]
            Proxy::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

/// A connected socket to the proxy.
pub enum Conn {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl Conn {
    fn connect(proxy: &Proxy, timeout: Duration) -> io::Result<Conn> {
        match proxy {
            Proxy::Tcp(addr) => {
                let s = TcpStream::connect_timeout(addr, timeout)?;
                s.set_nodelay(true)?;
                Ok(Conn::Tcp(s))
            }
            #[cfg(unix)]
            Proxy::Unix(path) => Ok(Conn::Unix(UnixStream::connect(path)?)),
        }
    }

    /// The read and write timeout: how long the next call may block.
    pub fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        let timeout = Some(timeout.max(Duration::from_millis(1)));
        match self {
            Conn::Tcp(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)
            }
            #[cfg(unix)]
            Conn::Unix(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)
            }
        }
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Conn::Tcp(s) => s.set_nonblocking(nonblocking),
            #[cfg(unix)]
            Conn::Unix(s) => s.set_nonblocking(nonblocking),
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            Conn::Unix(s) => s.read(buf),
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            Conn::Unix(s) => s.write(buf),
        }
    }
}

/// A read or write that ran out of time or was interrupted, to be retried.
pub fn retry(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted)
}

/// How long the next blocking call may last: until `until`, at most LOOP_WAIT.
pub fn slice(until: Instant) -> Duration {
    until.saturating_duration_since(Instant::now()).min(Duration::from_millis(LOOP_WAIT as u64))
}

/// Whether the proxy has sent anything that has not been read.
fn pending(conn: &mut Conn) -> io::Result<bool> {
    conn.set_nonblocking(true)?;
    let mut byte = [0u8; 1];
    let result = match conn.read(&mut byte) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(e),
    };
    conn.set_nonblocking(false)?;
    result
}

/// An open stream: the socket, the destination's first bytes, and the finished exchange, which
/// holds a RESOLVE's answer.
pub struct Open {
    pub conn: Conn,
    pub leftover: Vec<u8>,
    pub socks: Socks5Client,
}

/// Connect to the proxy and run the exchange, blocking, by `until` at the latest and only while
/// `stop` is clear. Err is why the stream failed.
pub fn open(
    proxy: &Proxy,
    mut socks: Socks5Client,
    stage_timeout: Duration,
    until: Instant,
    stop: &AtomicBool,
) -> Result<Open, String> {
    if socks.failed() {
        return Err(socks.reason().to_string());
    }
    let connect_timeout = stage_timeout.min(until.saturating_duration_since(Instant::now()));
    if connect_timeout.is_zero() || stop.load(Ordering::Relaxed) {
        return Err("not started".into());
    }
    let mut conn = Conn::connect(proxy, connect_timeout).map_err(|e| format!("connect to the proxy failed: {e}"))?;
    let mut stage_end = Instant::now() + stage_timeout;
    let mut buf = [0u8; REPLY_READ_SIZE];
    let check = |stage_end: Instant| -> Result<Duration, String> {
        if stop.load(Ordering::Relaxed) {
            return Err("interrupted".into());
        }
        let left = slice(stage_end.min(until));
        if left.is_zero() {
            return Err("timed out waiting for the proxy".into());
        }
        Ok(left)
    };
    loop {
        // Bytes the proxy sends before the message they answer is written fail the exchange.
        if !socks.bytes_to_send().is_empty() && pending(&mut conn).map_err(|e| format!("recv() failed: {e}"))? {
            return Err("proxy replied before the request was written".into());
        }
        while !socks.bytes_to_send().is_empty() {
            conn.set_timeout(check(stage_end)?).map_err(|e| format!("send() failed: {e}"))?;
            match conn.write(socks.bytes_to_send()) {
                Ok(n) => socks.mark_sent(n),
                Err(e) if retry(&e) => {}
                Err(e) => return Err(format!("send() failed: {e}")),
            }
        }
        conn.set_timeout(check(stage_end)?).map_err(|e| format!("recv() failed: {e}"))?;
        let n = match conn.read(&mut buf) {
            Ok(0) => return Err("the proxy closed the connection".into()),
            Ok(n) => n,
            Err(e) if retry(&e) => continue,
            Err(e) => return Err(format!("recv() failed: {e}")),
        };
        let used = socks.received(&buf[..n]);
        if socks.failed() {
            return Err(socks.reason().to_string());
        }
        if socks.done() {
            return Ok(Open { conn, leftover: buf[used..n].to_vec(), socks });
        }
        // A reply was complete: the next step of the exchange has begun.
        if !socks.bytes_to_send().is_empty() {
            stage_end = Instant::now() + stage_timeout;
        }
    }
}
