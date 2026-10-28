# privbcast

A standalone private broadcast job: it broadcasts one Bitcoin transaction through Tor to peers it
finds through the DNS seeds, as the specification in bitcoin/bitcoin#36628
(`doc/design/private-broadcast.md`) describes, without the node integration. One process runs one
job and prints its JSON report.

```
privbcast --proxy=127.0.0.1:9050 <transaction hex>
privbcast --proxy=unix:/run/tor/socks --chain=signet - < tx.hex
```

The exit status is 0 if at least one announcement was written, 1 if none was, and 2 on a usage
error. Tor's SocksPort must keep `IsolateSOCKSAuth` (the default), or several of a job's streams can
share a circuit.

## Design

- **Your IP address.** Every connection goes through the Tor SocksPort, including the DNS seed
  lookups, which Tor exits resolve. There are no direct connections and no local DNS lookups, and
  nothing from a local node is used: no peer list, no address manager, no mempool.
- **Separate circuits.** Each connection, and each set of seed lookups, uses fresh SOCKS
  credentials, so Tor puts it on a circuit of its own (with `IsolateSOCKSAuth`).
- **One fingerprint for every user.** Every job looks the same on the wire: a BIP324 handshake with
  a freshly randomized key encoding and random garbage, a VERSION with fixed fields (protocol 70016,
  user agent `/pynode:0.0.1/`, no relay), and the same message sequence. Nothing is configurable,
  since a setting would set its users apart.
- **A fixed plan.** The schedule of up to 24 connections, at most 6 at once, over about 10 minutes,
  is drawn before the first connection, and no peer can change it.
- **What stays visible.** Recipients and Tor exits see the transaction arrive from Tor exits at a
  few peers, and can tell that private broadcast was used. DNS seeds and exits can lie, which can
  affect delivery but reveals nothing about you.

## Tests

- `cargo test`: BIP324 test vectors, the wire behaviour against a BIP324 peer, the assignment
  rules, randomized peers and byte streams (`PRIVBCAST_ITERS`), and whole jobs cancelled against
  an in-process proxy (`tests/cancel.rs`).
- `tests/e2e_regtest.py`: the binary against a regtest `bitcoind` through the functional test
  framework's SOCKS5 server. Needs a Core checkout with the private broadcast framework:
  `BITCOIN_SRC=<checkout> python3 tests/e2e_regtest.py --configfile=<build>/test/config.ini`.
- `tests/diff/`: a fake Tor that records what a job sends, to compare implementations on the wire
  (Core's job, this tool, a blind reimplementation); results are kept beside it.

## Dependencies

Three direct dependencies, pinned exactly: `bitcoin` 0.32 (transaction decoding, and through it
secp256k1 and bitcoin_hashes), `chacha20-poly1305` and `getrandom`. The build compiles 18 crates,
nearly all from the rust-bitcoin project. There is no async runtime, serde or clap. BIP324 is
implemented here rather than with the `bip324` crate, whose key encoding uses no randomness and
so is recognisable on the wire.

Requires Rust 1.85 or newer.
