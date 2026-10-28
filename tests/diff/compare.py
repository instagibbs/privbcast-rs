#!/usr/bin/env python3
"""Compare what several private broadcast implementations did on the wire, from the JSON lines
wire_diff.py wrote for each: python3 compare.py core=core.jsonl rs=rs.jsonl blind=blind.jsonl

Prints, per topic, each implementation's value side by side, and marks rows where they differ.
"""
import json
import os
import statistics
import subprocess
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.realpath(__file__))
ELLCHECK = os.path.join(HERE, "ellcheck", "target", "release", "ellcheck")


def load(spec):
    name, path = spec.split("=", 1)
    return name, [json.loads(line) for line in open(path)]


def streams(job):
    """Events by stream id, in order."""
    by = defaultdict(list)
    for e in job["events"]:
        if "stream" in e:
            by[e["stream"]].append(e)
    return by


def request(evs):
    return next((e for e in evs if e["kind"] == "request"), None)


def wire_streams(jobs, scenario=None):
    """The CONNECT streams that reached a recipient, with their job."""
    for job in jobs:
        if scenario and job["scenario"] != scenario:
            continue
        for sid, evs in streams(job).items():
            req = request(evs)
            if req and req["cmd"] == 1 and any(e["kind"] == "key" for e in evs):
                yield job, sid, evs


def chunk_of_msgs(evs):
    """For each recorded packet (version packet, decoy or message), the index of the chunk that
    completed it: events are recorded in arrival order, so the latest chunk before it."""
    out, chunk = [], -1
    for e in evs:
        if e["kind"] == "chunk":
            chunk += 1
        elif e["kind"] in ("msg", "version_packet"):
            out.append((e.get("type", "<version packet>"), chunk, e))
    return out


def row(title, values, show_same=True):
    same = len({json.dumps(v, sort_keys=True) for v in values.values()}) == 1
    if same and not show_same:
        return
    mark = "  " if same else "≠ "
    print(f"{mark}{title}")
    for name, v in values.items():
        print(f"      {name:6} {v}")


def main():
    impls = dict(load(a) for a in sys.argv[1:])
    names = list(impls)

    print("== Proxy\n")
    vals = {}
    for n, jobs in impls.items():
        greet, auth, ports, names_seen, cred_lens = Counter(), Counter(), Counter(), set(), Counter()
        for job in jobs:
            for evs in streams(job).values():
                for e in evs:
                    if e["kind"] == "greeting":
                        greet[e["raw"]] += 1
                    if e["kind"] == "request":
                        auth[e["auth_ver"]] += 1
                        cred_lens[(len(e["user"]), len(e["password"]), all(c in "0123456789abcdef" for c in e["user"] + e["password"]))] += 1
                        if e["cmd"] == 0xF0:
                            ports[("RESOLVE", e["port"], e["atyp"])] += 1
                            names_seen.add(e["addr"])
                        else:
                            ports[("CONNECT", e["port"], e["atyp"])] += 1
        vals[n] = {"greetings": dict(greet), "auth_versions": dict(auth), "credentials (user len, pw len, hex)": {str(k): c for k, c in cred_lens.items()}}
        vals[n]["cmd/port/atyp"] = {f"{k[0]} port {k[1]} atyp {k[2]}": c for k, c in sorted(ports.items())}
        vals[n]["RESOLVE names"] = sorted(names_seen)
    for key in vals[names[0]]:
        row(key, {n: vals[n][key] for n in names})

    vals = {}
    for n, jobs in impls.items():
        job = next(j for j in jobs if j["scenario"] == "coop")
        resolves = [e for evs in streams(job).values() for e in evs if e["kind"] == "request" and e["cmd"] == 0xF0]
        resolves.sort(key=lambda e: e["stream"])
        sets = {}
        order = []
        for e in resolves:
            sets.setdefault((e["user"], e["password"]), len(sets))
            order.append(f"{e['addr'].split('.')[0][-1]}{sets[(e['user'], e['password'])]}")
        connects = [e for evs in streams(job).values() for e in evs if e["kind"] == "request" and e["cmd"] == 1]
        creds = [(e["user"], e["password"]) for e in connects]
        vals[n] = {
            "credential sets over RESOLVEs": len(sets),
            "RESOLVEs per set": sorted(Counter(sets[(e["user"], e["password"])] for e in resolves).values()),
            "launch order (seed letter + set), first 10": " ".join(order[:10]),
            "CONNECT credentials all distinct, none shared with RESOLVE": len(set(creds)) == len(creds) and not set(creds) & set(sets),
            "CONNECT destinations (sample)": sorted({e["addr"] for e in connects})[:3],
        }
    for key in vals[names[0]]:
        row(key, {n: vals[n][key] for n in names})

    print("\n== BIP324 handshake\n")
    vals = {}
    for n, jobs in impls.items():
        keys, garbage, decoys, vp_contents = [], [], 0, Counter()
        for job, sid, evs in wire_streams(jobs):
            key = next(e for e in evs if e["kind"] == "key")
            keys.append(key["ellswift"])
            g = next((e["n"] for e in evs if e["kind"] == "garbage"), None)
            if g is None and job["scenario"] == "silent":
                g = sum(e["n"] for e in evs if e["kind"] == "chunk") - 64
            if g is not None:
                garbage.append(g)
            decoys += sum(1 for e in evs if e["kind"] == "decoy")
            for e in evs:
                if e["kind"] == "version_packet":
                    vp_contents[e["contents"]] += 1
        zero = subprocess.run([ELLCHECK], input="\n".join(keys) + "\n", capture_output=True, text=True).stdout.split()
        vals[n] = {
            "keys flagged as zero-randomness ElligatorSwift": f"{zero.count('1')}/{len(zero)}",
            "keys distinct": f"{len(set(keys))}/{len(keys)}",
            "garbage length: n, min, max, mean": [len(garbage), min(garbage), max(garbage), round(statistics.mean(garbage))] if garbage else None,
            "garbage length: share in each quarter of 0-4095": [round(sum(1 for g in garbage if q * 1024 <= g < (q + 1) * 1024) / len(garbage), 2) for q in range(4)] if garbage else None,
            "decoy packets sent": decoys,
            "version packet contents": dict(vp_contents),
        }
    for key in vals[names[0]]:
        row(key, {n: vals[n][key] for n in names})

    vals = {}
    for n, jobs in impls.items():
        extra = Counter()
        for job, sid, evs in wire_streams(jobs, "slow_version_packet"):
            sent = next((e["t"] for e in evs if e["kind"] == "version_packet_sent"), None)
            g = next((e["n"] for e in evs if e["kind"] == "garbage"), None)
            if sent is None or g is None:
                continue
            before = sum(e["n"] for e in evs if e["kind"] == "chunk" and e["t"] < sent)
            extra[before - 64 - g] += 1
        vals[n] = {"bytes sent after the garbage, before our version packet (36 = terminator + version packet; 169 = + VERSION)": dict(extra)}
    for key in vals[names[0]]:
        row(key, {n: vals[n][key] for n in names})

    print("\n== Messages\n")
    vals = {}
    for n, jobs in impls.items():
        enc, versions, seqs, same_chunk = Counter(), Counter(), Counter(), Counter()
        for job, sid, evs in wire_streams(jobs, "coop"):
            msgs = [e for e in evs if e["kind"] == "msg"]
            seqs[" ".join(e["type"] for e in msgs)] += 1
            for e in msgs:
                enc[(e["type"], e["enc"], e["packet"] if e["type"] in ("version", "wtxidrelay", "verack", "inv", "ping") else "")] += 1
                if e["type"] == "version":
                    p = bytes.fromhex(e["payload"])
                    versions[(p[:72] + bytes(8) + p[80:]).hex()] += 1
            chunks = chunk_of_msgs(evs)
            for (a, ca, _), (b, cb, _) in zip(chunks, chunks[1:]):
                if (a, b) in (("<version packet>", "version"), ("wtxidrelay", "verack"), ("tx", "ping")):
                    same_chunk[(f"{a}+{b}", ca == cb)] += 1
        vals[n] = {
            "message sequences (coop)": dict(seqs),
            "type, encoding, packet length": {f"{k[0]} {k[1]} {k[2]}": c for k, c in sorted(enc.items())},
            "VERSION payloads with the nonce zeroed (distinct)": len(versions),
            "VERSION payload, nonce zeroed": list(versions)[:1],
            "pairs that arrived in one recv() (localhost, indicative only)": {f"{k[0]} {'same' if k[1] else 'apart'}": c for k, c in sorted(same_chunk.items())},
        }
    for key in vals[names[0]]:
        row(key, {n: vals[n][key] for n in names})

    print("\n== Scenarios: what each attempt did\n")
    scenarios = sorted({j["scenario"] for jobs in impls.values() for j in jobs})
    for sc in scenarios:
        vals = {}
        for n, jobs in impls.items():
            job = next((j for j in jobs if j["scenario"] == sc), None)
            if not job:
                vals[n] = None
                continue
            rep = job.get("report") or {}
            outcomes = Counter((a["outcome"], a["reason"]) for s in rep.get("slots", []) for a in s["attempts"])
            sent = Counter()
            closes = Counter()
            for _, sid, evs in wire_streams([job]):
                sent[" ".join(e["type"] for e in evs if e["kind"] == "msg") or "-"] += 1
                last_msg = max((e["t"] for e in evs if e["kind"] == "msg"), default=None)
                for e in evs:
                    if e["kind"] == "close":
                        closes[(e["how"], None if last_msg is None else round((e["t"] - last_msg) * 1000 // 50 * 50))] += 1
            s = rep.get("summary", {})
            vals[n] = {
                "outcomes (outcome, reason)": {f"{k[0]} | {k[1]}": c for k, c in sorted(outcomes.items(), key=str)},
                "what recipients received": dict(sent),
                "closes (how, ms after last message, 50 ms bins)": {str(k): c for k, c in sorted(closes.items(), key=str)},
                "summary": {k: s.get(k) for k in ("connections", "announcements_handed", "announcements_written", "tx_written", "pongs", "slots_completed", "interrupted", "error")},
            }
            if sc == "odd_answers":
                d = rep.get("discovery", {})
                vals[n]["discovery: rejected, duplicates, exit_path_candidates"] = [d.get("rejected"), d.get("duplicates"), d.get("exit_path_candidates")]
                vals[n]["CONNECTs to odd answers"] = sorted({request(evs)["addr"] for _, _, evs in [(None, None, e) for e in streams(job).values()] if request(evs) and request(evs)["cmd"] == 1 and not request(evs)["addr"].startswith("11.")})
        print(f"-- {sc}")
        for key in (vals[names[0]] or {}):
            row(key, {n: (vals[n] or {}).get(key) for n in names}, show_same=False)

    print("\n== Report schema\n")

    def shape(v):
        if isinstance(v, dict):
            return {k: shape(x) for k, x in v.items()}
        if isinstance(v, list):
            merged = {}
            for x in v:
                s = shape(x)
                if isinstance(s, dict):
                    for k, t in s.items():
                        merged.setdefault(k, set()).update(t if isinstance(t, set) else {json.dumps(t)})
                else:
                    merged.setdefault("[]", set()).add(json.dumps(s))
            return {k: sorted(t) for k, t in merged.items()}
        return type(v).__name__

    vals = {}
    for n, jobs in impls.items():
        fields = defaultdict(set)
        for job in jobs:
            rep = job.get("report")
            if not rep:
                continue
            for s in rep.get("slots", []):
                for a in s["attempts"]:
                    for k, v in a.items():
                        fields[f"attempt.{k}"].add(type(v).__name__)
                for k, v in s.items():
                    if k != "attempts":
                        fields[f"slot.{k}"].add(type(v).__name__)
            for k, v in rep.get("summary", {}).items():
                fields[f"summary.{k}"].add(type(v).__name__)
            for k, v in rep.get("discovery", {}).items():
                fields[f"discovery.{k}"].add(type(v).__name__)
            for k, v in rep.items():
                if k not in ("slots", "summary", "discovery"):
                    fields[k].add(type(v).__name__)
        vals[n] = {k: sorted(v) for k, v in fields.items()}
    for key in sorted({k for v in vals.values() for k in v}):
        row(key, {n: vals[n].get(key) for n in names}, show_same=False)


if __name__ == "__main__":
    main()
