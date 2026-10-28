#!/usr/bin/env python3
"""End-to-end run of the privbcast binary against a regtest bitcoind, through the SOCKS5 server of
Bitcoin Core's functional test framework standing in for Tor.

The server answers RESOLVE queries for seven test seed names with distinct public addresses, and
redirects every CONNECT to the node's P2P port, so all of a job's attempts reach the one node over
BIP324. The node must end up with the transaction in its mempool, and must have seen the job's
profile.

Run from a Bitcoin Core checkout that has the private broadcast test framework (PR #36628):

    BITCOIN_SRC=~/bitcoin BITCOIN_BUILD=~/bitcoin/build \\
        python3 tests/e2e_regtest.py --configfile=$BITCOIN_BUILD/test/config.ini

PRIVBCAST_BIN overrides the binary (default target/debug/privbcast).
"""
import json
import os
import socket
import subprocess
import sys
import threading

sys.path.insert(0, os.path.join(os.environ["BITCOIN_SRC"], "test", "functional"))

from test_framework.socks5 import AddressType, Command, start_socks5_server  # noqa: E402
from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.util import assert_equal, assert_greater_than, p2p_port  # noqa: E402
from test_framework.wallet import MiniWallet  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BIN = os.environ.get("PRIVBCAST_BIN", os.path.join(REPO, "target", "debug", "privbcast"))
SEEDS = [f"seed-{c}.test." for c in "abcdefg"]


class PrivbcastE2ETest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-v2transport=1", "-debug=net"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        tx = wallet.create_self_transfer()

        resolves = {}

        def resolve_factory(name):
            # The n-th query of a seed gets a public address of its own.
            n = resolves.get(name, 0)
            resolves[name] = n + 1
            return f"11.{SEEDS.index(name)}.{n}.1" if name in SEEDS else None

        def destinations_factory(addr, port, proxy_client):
            assert_equal(port, 18444)
            return {"actual_to_addr": "127.0.0.1", "actual_to_port": p2p_port(0)}

        server = start_socks5_server(destinations_factory, resolve_factory)
        proxy = f"127.0.0.1:{server.conf.addr[1]}"
        self.log.info("Run a job through the proxy, on seven seeds, with durations divided by 10")
        args = [BIN, f"--proxy={proxy}", "--chain=regtest", "--timedivisor=10", "--debug", "--logips"]
        args += [f"--seed={s}" for s in SEEDS]
        with node.assert_debug_log(["/pynode:0.0.1/: version 70016"], timeout=90):
            run = subprocess.run(args + [tx["hex"]], capture_output=True, text=True, timeout=120)
        self.log.debug(run.stderr)
        with open(os.path.join(self.options.tmpdir, "report.json"), "w") as f:
            f.write(run.stdout)
        with open(os.path.join(self.options.tmpdir, "privbcast.log"), "w") as f:
            f.write(run.stderr)
        report = json.loads(run.stdout)
        server.stop()

        self.log.info("The node has the transaction, and the report says how it got there")
        assert tx["txid"] in node.getrawmempool()
        assert_equal(run.returncode, 0)
        assert_equal((report["txid"], report["wtxid"], report["chain"]), (tx["txid"], tx["wtxid"], "regtest"))
        summary = report["summary"]
        assert_equal(summary["error"], None)
        assert_equal(summary["interrupted"], False)
        assert_greater_than(summary["pongs"], 0)
        assert_equal(summary["slots_completed"], 6)
        discovery = report["discovery"]
        assert_equal(discovery["exit_path_candidates"], 28)
        assert_equal(sorted(s["name"] for s in discovery["seeds"]), SEEDS)
        assert all(s["queries"] == 4 and s["answers"] == 4 for s in discovery["seeds"])
        # Every slot announced on its first attempt: the node took every connection.
        for slot in report["slots"]:
            assert_equal(len(slot["attempts"]), 1)
            attempt = slot["attempts"][0]
            assert attempt["endpoint"].startswith("11.") and attempt["endpoint"].endswith(".1:18444")
            assert attempt["peer_user_agent"].startswith("/Satoshi:")
            assert attempt["inv_written_ms"] is not None
        pongs = [a for s in report["slots"] for a in s["attempts"] if a["outcome"] == "pong_received"]
        assert all(a["tx_written_ms"] is not None for a in pongs)
        # Four query sets of seven RESOLVEs, each set with credentials of its own, and fresh ones for
        # every CONNECT (B2). Every destination is a name (DOMAINNAME), the addresses too.
        assert_equal(sum(resolves.values()), 28)
        commands = []
        while not server.queue.empty():
            commands.append(server.queue.get())
        sets = {}
        for c in commands:
            if c.cmd == Command.RESOLVE:
                sets.setdefault((c.username, c.password), []).append(c.addr.decode())
        assert_equal(len(sets), 4)
        assert all(sorted(names) == SEEDS for names in sets.values())
        connects = [c for c in commands if c.cmd == Command.CONNECT]
        assert_equal(len(connects), summary["connections"])
        creds = [(c.username, c.password) for c in connects]
        assert_equal(len(set(creds)), len(creds))
        assert not set(creds) & set(sets)
        assert all(c.atyp == AddressType.DOMAINNAME for c in commands)

        self.log.info("Seeds that answer nothing: the job fails with no candidates when discovery ends")
        server = start_socks5_server(destinations_factory, lambda name: None)
        args = [BIN, f"--proxy=127.0.0.1:{server.conf.addr[1]}", "--chain=regtest", "--timedivisor=10"]
        run = subprocess.run(args + [f"--seed={s}" for s in SEEDS] + [tx["hex"]], capture_output=True, text=True, timeout=60)
        server.stop()
        report = json.loads(run.stdout)
        assert_equal(run.returncode, 1)
        assert_equal(report["summary"]["error"], "no candidates")
        assert_equal(report["summary"]["connections"], 0)
        assert_equal(report["discovery"]["rejected"], 0)
        assert all(s["queries"] == 4 and s["answers"] == 0 for s in report["discovery"]["seeds"])

        self.log.info("A proxy without username and password authentication gets no stream (B2)")
        server = start_socks5_server(destinations_factory, resolve_factory, auth=False)
        args = [BIN, f"--proxy=127.0.0.1:{server.conf.addr[1]}", "--chain=regtest", "--timedivisor=10"]
        run = subprocess.run(args + [f"--seed={s}" for s in SEEDS] + [tx["hex"]], capture_output=True, text=True, timeout=60)
        assert server.queue.empty()
        server.stop()
        report = json.loads(run.stdout)
        assert_equal(report["summary"]["error"], "no candidates")

        self.log.info("Recipients that accept and stay silent: each attempt ends at its handshake deadline, and its "
                      "slot moves on to its backups")
        silent = socket.socket()
        silent.bind(("127.0.0.1", 0))
        silent.listen(64)
        held = []

        def accept():
            while True:
                try:
                    held.append(silent.accept()[0])
                except OSError:
                    return
        threading.Thread(target=accept, daemon=True).start()
        resolves.clear()
        server = start_socks5_server(lambda addr, port, client: {"actual_to_addr": "127.0.0.1", "actual_to_port": silent.getsockname()[1]},
                                     resolve_factory)
        args = [BIN, f"--proxy=127.0.0.1:{server.conf.addr[1]}", "--chain=regtest", "--timedivisor=10"]
        run = subprocess.run(args + [f"--seed={s}" for s in SEEDS] + [tx["hex"]], capture_output=True, text=True, timeout=120)
        server.stop()
        silent.close()
        report = json.loads(run.stdout)
        assert_equal(run.returncode, 1)
        assert_equal(report["summary"]["connections"], 24)
        assert_equal(report["summary"]["slots_completed"], 6)
        for slot in report["slots"]:
            assert_equal(len(slot["attempts"]), 4)
            for a in slot["attempts"]:
                assert_equal((a["outcome"], a["reason"]), ("not_announced", "not announced by the handshake deadline"))
                assert a["connected_ms"] is not None
                # The deadline, 45 s / 10 after the scheduled start, is acted on within a step.
                assert 4500 <= a["ended_ms"] - a["scheduled_start_ms"] < 4500 + 200, a
                assert_greater_than(a["bytes_sent"], 63)

        self.log.info("Test overrides are refused off regtest (U1)")
        run = subprocess.run([BIN, "--proxy=127.0.0.1:9050", "--seed=x", tx["hex"]], capture_output=True, text=True)
        assert_equal(run.returncode, 2)


if __name__ == "__main__":
    PrivbcastE2ETest(__file__).main()
