#!/usr/bin/env python3
"""Run one private broadcast implementation through a set of scenarios against the fake Tor in
fake_tor.py, and write what each job did on the wire, and its report, as JSON lines.

Implementations: "core" is a regtest bitcoind with -privatebroadcast (restarted for every job, so
each job gets its own fake Tor); any other name is a binary with the privbcast command-line
interface, given as --bin.

    BITCOIN_SRC=<core checkout with PR #36628> python3 tests/diff/wire_diff.py \\
        --configfile=<build>/test/config.ini --impl=core --out=core.jsonl
    ... --impl=rs --bin=target/release/privbcast --out=rs.jsonl
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.environ["BITCOIN_SRC"], "test", "functional"))
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from fake_tor import BEHAVIOURS, SMALL_RCVBUF, FakeTor  # noqa: E402
from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.util import wait_until_helper_internal  # noqa: E402
from test_framework.wallet import MiniWallet  # noqa: E402

SEEDS = [f"seed-{c}.test." for c in "abcdefg"]
BASES = [s.rstrip(".") for s in SEEDS]

# Answers a lying seed or exit might give, by seed: which of them become candidates (R2)?
ODD_ANSWERS = {
    0: ["224.0.0.5", "240.0.0.1", "ff02::1", "64:ff9b::102:304"],
    1: ["2002:b0b::1", "::ffff:11.9.9.9", "2001:0:1::1", "100::1"],
    2: ["10.0.0.1", "192.0.0.9", "192.88.99.1", "fec0::1"],
}

SCENARIOS = list(BEHAVIOURS) + ["proxy_refuse", "odd_answers"]


def resolver(scenario):
    def resolve(name, n):
        base = name.rstrip(".")
        if base not in BASES:
            return None
        si = BASES.index(base)
        if scenario == "odd_answers" and si in ODD_ANSWERS:
            return ODD_ANSWERS[si][n % 4]
        return f"11.{si}.{n}.1"
    return resolve


def connector(scenario):
    if scenario == "proxy_refuse":
        return lambda addr, port: 5  # connection refused
    behaviour = "noreq" if scenario == "odd_answers" else scenario
    return lambda addr, port: behaviour


class WireDiff(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--impl", required=True)
        parser.add_argument("--bin", default=None)
        parser.add_argument("--out", required=True)
        parser.add_argument("--divisor", type=int, default=20)
        parser.add_argument("--scenarios", default=",".join(SCENARIOS))
        parser.add_argument("--silent-jobs", type=int, default=4, help="extra silent jobs, for the distributions")

    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-v2transport=1"]]

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        jobs = [s for s in self.options.scenarios.split(",") if s] + ["silent"] * self.options.silent_jobs
        # A confirmed coin per job, Core's test-accept needs one.
        self.generate(self.wallet, len(jobs))
        self.generate(self.nodes[0], 100)
        with open(self.options.out, "w") as out:
            for i, scenario in enumerate(jobs):
                record = self.run_job(i, scenario)
                out.write(json.dumps(record) + "\n")
                out.flush()
                s = record["report"]["summary"] if record["report"] else {}
                self.log.info(f"{self.options.impl} job {i} {scenario}: streams={len({e['stream'] for e in record['events'] if 'stream' in e})} "
                              f"connections={s.get('connections')} error={s.get('error')}")

    def run_job(self, i, scenario):
        # A large transaction where the recipient stops reading, so that writing it blocks.
        vsize = 90_000 if scenario in SMALL_RCVBUF else 0
        tx = self.wallet.create_self_transfer(utxo_to_spend=self.wallet.get_utxo(confirmed_only=True), target_vsize=vsize)
        wtxid_internal = bytes.fromhex(tx["wtxid"])[::-1]
        tor = FakeTor(resolver(scenario), connector(scenario), "regtest", wtxid_internal, timeout=30, small_rcvbuf=scenario in SMALL_RCVBUF)
        d = self.options.divisor
        record = {"impl": self.options.impl, "scenario": scenario, "job": i, "divisor": d, "wtxid": tx["wtxid"]}
        t0 = time.monotonic()
        if self.options.impl == "core":
            node = self.nodes[0]
            self.restart_node(0, extra_args=["-v2transport=1", "-privatebroadcast", f"-onion=127.0.0.1:{tor.port}",
                                             *[f"-privatebroadcastseed={s}" for s in SEEDS],
                                             f"-privatebroadcasttimedivisor={d}", "-debug=privatebroadcast"])
            t0 = time.monotonic()
            node.sendrawtransaction(tx["hex"])

            def done():
                jobs = {j["wtxid"]: j for j in node.getprivatebroadcastinfo()["jobs"]}
                return tx["wtxid"] in jobs and jobs[tx["wtxid"]]["state"] in ("done", "aborted")
            wait_until_helper_internal(done, timeout=180)
            job = {j["wtxid"]: j for j in node.getprivatebroadcastinfo()["jobs"]}[tx["wtxid"]]
            record["report"] = job.get("report")
            record["state"] = job["state"]
        else:
            args = [self.options.bin, f"--proxy=127.0.0.1:{tor.port}", "--chain=regtest", f"--timedivisor={d}"]
            # On stdin: a large transaction's hex is longer than one argument may be.
            args += [f"--seed={s}" for s in SEEDS] + ["-"]
            run = subprocess.run(args, input=tx["hex"], capture_output=True, text=True, timeout=180)
            record["exit"] = run.returncode
            record["stderr"] = run.stderr[-2000:]
            try:
                record["report"] = json.loads(run.stdout)
            except ValueError:
                record["report"] = None
        record["job_seconds"] = time.monotonic() - t0
        # Let recipients finish recording the closes.
        time.sleep(1)
        tor.stop()
        with tor.rec.lock:
            record["events"] = [dict(e, t=e["t"] - t0) for e in tor.rec.events]
        return record


if __name__ == "__main__":
    WireDiff(__file__).main()
