use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;

use bitcoin::Transaction;
use bitcoin::consensus;
use bitcoin::hashes::Hash;
use bitcoin::hex::FromHex;

use privbcast::attempt::TxData;
use privbcast::chain;
use privbcast::job::{Job, JobInputs};
use privbcast::log;
use privbcast::params::Timing;
use privbcast::stream::Proxy;

const USAGE: &str = "\
Usage: privbcast --proxy=<ip:port|unix:path> [options] <transaction hex | ->

Broadcast one transaction through a Tor SOCKS5 proxy as a private broadcast job and print the job
report as JSON. `-` reads the hex from stdin.

Options:
  --proxy=<ip:port|unix:path>  Tor's SocksPort, with IsolateSOCKSAuth (Tor's default). Required.
  --chain=<name>               main (default), test, testnet4, signet or regtest.
  --seed=<name>                Regtest only, repeatable, required there: the DNS seed names.
  --timedivisor=<n>            Regtest only: divide every duration of the job by n (1 to 1000).
  --debug                      Debug lines on stderr.
  --logips                     Name recipients' addresses in debug lines.
  -h, --help                   This text.

Exit status: 0 if at least one announcement was written, 1 if none was, 2 on a usage error.";

struct Args {
    proxy: Proxy,
    chain: &'static chain::Chain,
    seeds: Vec<String>,
    timing: Timing,
    debug: bool,
    log_ips: bool,
    tx_hex: String,
}

fn parse_proxy(s: &str) -> Result<Proxy, String> {
    if let Some(path) = s.strip_prefix("unix:") {
        #[cfg(unix)]
        return Ok(Proxy::Unix(path.into()));
        #[cfg(not(unix))]
        return Err(format!("unix sockets are not supported here: {path}"));
    }
    // An address, never a name: nothing is resolved locally (B1).
    s.parse().map(Proxy::Tcp).map_err(|_| format!("the proxy must be an IP address and port or unix:<path>, not {s}"))
}

fn parse_args() -> Result<Option<Args>, String> {
    let (mut proxy, mut chain_name, mut seeds, mut divisor) = (None, "main".to_string(), Vec::new(), None);
    let (mut debug, mut log_ips, mut tx_hex) = (false, false, None);
    for arg in std::env::args().skip(1) {
        let (key, value) = match arg.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        let value_of = |v: Option<String>| v.ok_or_else(|| format!("{key} needs a value"));
        match key.as_str() {
            "-h" | "--help" => return Ok(None),
            "--proxy" => proxy = Some(parse_proxy(&value_of(value)?)?),
            "--chain" => chain_name = value_of(value)?,
            "--seed" => seeds.push(value_of(value)?),
            "--timedivisor" => {
                divisor = Some(value_of(value)?.parse::<i64>().map_err(|e| format!("--timedivisor: {e}"))?)
            }
            "--debug" => debug = true,
            "--logips" => log_ips = true,
            _ if arg.starts_with("--") => return Err(format!("unknown option {arg}")),
            _ if tx_hex.is_none() => tx_hex = Some(arg),
            _ => return Err(format!("unexpected argument {arg}")),
        }
    }
    let proxy = proxy.ok_or("--proxy is required")?;
    let chain = chain::by_name(&chain_name).ok_or(format!("unknown chain {chain_name}"))?;
    // The test overrides are refused on other chains, and regtest needs seeds (U1).
    let regtest = chain.name == "regtest";
    if !regtest && (!seeds.is_empty() || divisor.is_some()) {
        return Err("--seed and --timedivisor are for regtest only".into());
    }
    if regtest && seeds.is_empty() {
        return Err("regtest needs --seed".into());
    }
    let timing = match divisor {
        Some(d) => Timing::new(d).ok_or("--timedivisor must be from 1 to 1000")?,
        None => Timing::default(),
    };
    let seeds = if regtest { seeds } else { chain.dns_seeds.iter().map(|s| s.to_string()).collect() };
    let mut tx_hex = tx_hex.ok_or("the transaction is required")?;
    if tx_hex == "-" {
        tx_hex.clear();
        std::io::stdin().read_to_string(&mut tx_hex).map_err(|e| format!("reading stdin: {e}"))?;
    }
    Ok(Some(Args { proxy, chain, seeds, timing, debug, log_ips, tx_hex: tx_hex.trim().to_string() }))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let decoded = Vec::<u8>::from_hex(&args.tx_hex)
        .map_err(|e| e.to_string())
        .and_then(|b| consensus::deserialize::<Transaction>(&b).map_err(|e| e.to_string()));
    let tx = match decoded {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("error: the transaction does not decode: {e}");
            return ExitCode::from(2);
        }
    };
    log::configure(args.debug, args.log_ips);
    let wtxid = tx.compute_wtxid();
    let inputs = JobInputs {
        // The caller's transaction as it decoded, serialized with its witness (N2's intent).
        tx: Arc::new(TxData { bytes: consensus::serialize(&tx), wtxid: wtxid.to_byte_array() }),
        txid: tx.compute_txid().to_string(),
        wtxid: wtxid.to_string(),
        proxy: args.proxy,
        chain: args.chain,
        dns_seeds: args.seeds,
        timing: args.timing,
        cancel: None,
    };
    let report = Job::new(inputs).run();
    println!("{}", report.to_json());
    if report.summary.announcements_written > 0 { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
