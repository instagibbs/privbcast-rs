//! The job report (Interface, Report): a JSON object whose times are milliseconds from job start,
//! or null for an event that did not happen (H1). It names every endpoint dialled and contains no
//! transaction bytes (H3).

use std::fmt::Write;

use crate::assign::{Candidate, SeedSummary};
use crate::attempt::{AttemptTimes, Outcome};
use crate::params::Ms;
use crate::plan::SlotSchedule;

pub struct AttemptReport {
    pub candidate: Candidate,
    pub outcome: Outcome,
    pub reason: String,
    pub scheduled_start: Ms,
    /// The dial.
    pub started: Ms,
    pub times: AttemptTimes,
    pub peer_version: Option<i32>,
    /// Sanitized.
    pub peer_user_agent: Option<String>,
    pub extra_requests: u32,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

pub struct SlotReport {
    pub schedule: SlotSchedule,
    pub empty_opportunities: usize,
    pub missed_opportunities: usize,
    pub interrupted: bool,
    pub attempts: Vec<AttemptReport>,
}

pub struct DiscoveryReport {
    pub duration: Ms,
    pub seeds: Vec<SeedSummary>,
    pub duplicates: u32,
    pub rejected: u32,
    pub exit_path_candidates: u32,
}

#[derive(Default)]
pub struct Summary {
    pub connections: u32,
    pub announcements_handed: u32,
    pub announcements_written: u32,
    pub tx_written: u32,
    pub pongs: u32,
    pub slots_completed: u32,
    pub interrupted: bool,
    pub error: Option<String>,
    pub duration: Ms,
}

pub struct Report {
    pub txid: String,
    pub wtxid: String,
    pub chain: String,
    pub discovery: DiscoveryReport,
    pub slots: Vec<SlotReport>,
    pub summary: Summary,
}

/// A JSON value, written as it is built.
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(&'static str, Json)>),
}

impl Json {
    fn time(t: Option<Ms>) -> Json {
        t.map_or(Json::Null, Json::Int)
    }

    fn opt_str(s: Option<String>) -> Json {
        s.map_or(Json::Null, Json::Str)
    }

    fn write(&self, out: &mut String, indent: usize) {
        let pad = |out: &mut String, n: usize| out.extend(std::iter::repeat_n(' ', n));
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(i) => write!(out, "{i}").unwrap(),
            Json::Str(s) => {
                out.push('"');
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32).unwrap(),
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            Json::Arr(items) if items.is_empty() => out.push_str("[]"),
            Json::Arr(items) => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    pad(out, indent + 2);
                    item.write(out, indent + 2);
                    out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
                }
                pad(out, indent);
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push_str("{\n");
                for (i, (key, value)) in fields.iter().enumerate() {
                    pad(out, indent + 2);
                    write!(out, "\"{key}\": ").unwrap();
                    value.write(out, indent + 2);
                    out.push_str(if i + 1 < fields.len() { ",\n" } else { "\n" });
                }
                pad(out, indent);
                out.push('}');
            }
        }
    }
}

fn attempt_json(a: &AttemptReport) -> Json {
    let t = &a.times;
    Json::Obj(vec![
        ("endpoint", Json::Str(a.candidate.endpoint.to_string())),
        ("provenance", Json::Str(a.candidate.provenance.clone())),
        ("outcome", Json::Str(a.outcome.name().into())),
        ("reason", Json::Str(a.reason.clone())),
        ("scheduled_start_ms", Json::Int(a.scheduled_start)),
        ("started_ms", Json::Int(a.started)),
        ("connected_ms", Json::time(t.connected)),
        ("peer_version", a.peer_version.map_or(Json::Null, |v| Json::Int(v as i64))),
        ("peer_user_agent", Json::opt_str(a.peer_user_agent.clone())),
        ("inv_handed_ms", Json::time(t.inv_handed)),
        ("inv_written_ms", Json::time(t.inv_written)),
        ("getdata_ms", Json::time(t.getdata)),
        ("tx_written_ms", Json::time(t.tx_written)),
        ("ping_written_ms", Json::time(t.ping_written)),
        ("pong_ms", Json::time(t.pong)),
        ("ended_ms", Json::time(t.ended)),
        ("extra_requests", Json::Int(a.extra_requests as i64)),
        ("bytes_sent", Json::Int(a.bytes_sent as i64)),
        ("bytes_recv", Json::Int(a.bytes_recv as i64)),
    ])
}

fn slot_json(s: &SlotReport) -> Json {
    Json::Obj(vec![
        ("slot", Json::Int(s.schedule.index as i64)),
        ("stratum", Json::Str(s.schedule.stratum.name().into())),
        ("scheduled_ms", Json::Arr(s.schedule.scheduled.iter().map(|t| Json::Int(*t)).collect())),
        ("scheduled_end_ms", Json::Int(s.schedule.scheduled_end)),
        ("empty_opportunities", Json::Int(s.empty_opportunities as i64)),
        ("missed_opportunities", Json::Int(s.missed_opportunities as i64)),
        ("interrupted", Json::Bool(s.interrupted)),
        ("attempts", Json::Arr(s.attempts.iter().map(attempt_json).collect())),
    ])
}

impl Report {
    pub fn to_json(&self) -> String {
        let d = &self.discovery;
        let seeds = d
            .seeds
            .iter()
            .map(|s| {
                Json::Obj(vec![
                    ("name", Json::Str(s.name.clone())),
                    ("queries", Json::Int(s.queries as i64)),
                    ("skipped", Json::Int(s.skipped as i64)),
                    ("answers", Json::Int(s.answers as i64)),
                    ("accepted", Json::Int(s.accepted as i64)),
                ])
            })
            .collect();
        let s = &self.summary;
        let json = Json::Obj(vec![
            ("txid", Json::Str(self.txid.clone())),
            ("wtxid", Json::Str(self.wtxid.clone())),
            ("chain", Json::Str(self.chain.clone())),
            (
                "discovery",
                Json::Obj(vec![
                    ("duration_ms", Json::Int(d.duration)),
                    ("seeds", Json::Arr(seeds)),
                    ("duplicates", Json::Int(d.duplicates as i64)),
                    ("rejected", Json::Int(d.rejected as i64)),
                    ("exit_path_candidates", Json::Int(d.exit_path_candidates as i64)),
                ]),
            ),
            ("slots", Json::Arr(self.slots.iter().map(slot_json).collect())),
            (
                "summary",
                Json::Obj(vec![
                    ("connections", Json::Int(s.connections as i64)),
                    ("announcements_handed", Json::Int(s.announcements_handed as i64)),
                    ("announcements_written", Json::Int(s.announcements_written as i64)),
                    ("tx_written", Json::Int(s.tx_written as i64)),
                    ("pongs", Json::Int(s.pongs as i64)),
                    ("slots_completed", Json::Int(s.slots_completed as i64)),
                    ("interrupted", Json::Bool(s.interrupted)),
                    ("error", Json::opt_str(s.error.clone())),
                    ("duration_ms", Json::Int(s.duration)),
                ]),
            ),
        ]);
        let mut out = String::new();
        json.write(&mut out, 0);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        let mut out = String::new();
        Json::Obj(vec![("a", Json::Str("x\"\\\n\u{1}y".into())), ("b", Json::Arr(vec![])), ("c", Json::Null)])
            .write(&mut out, 0);
        assert_eq!(out, "{\n  \"a\": \"x\\\"\\\\\\n\\u0001y\",\n  \"b\": [],\n  \"c\": null\n}");
    }
}
