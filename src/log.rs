//! Debug lines on stderr. A recipient's address appears only when asked for, as Bitcoin Core's
//! -logips does for peers.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::addr::Endpoint;

static DEBUG: AtomicBool = AtomicBool::new(false);
static LOG_IPS: AtomicBool = AtomicBool::new(false);

pub fn configure(debug: bool, log_ips: bool) {
    DEBUG.store(debug, Ordering::Relaxed);
    LOG_IPS.store(log_ips, Ordering::Relaxed);
}

pub fn debug(args: fmt::Arguments) {
    if DEBUG.load(Ordering::Relaxed) {
        eprintln!("[privbcast] {args}");
    }
}

/// A recipient's address for a debug line.
pub fn addr(endpoint: &Endpoint) -> String {
    if LOG_IPS.load(Ordering::Relaxed) { endpoint.to_string() } else { "a recipient".into() }
}
