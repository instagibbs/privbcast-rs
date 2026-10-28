//! Every opportunity's candidate, fixed when discovery ends as a function of the plan and the
//! discovery result alone (C2).

use std::collections::BTreeSet;

use bitcoin::hashes::{Hash, sha256};

use crate::addr::Endpoint;
use crate::params::*;
use crate::plan::Plan;
use crate::rng::Rng;

/// One DNS seed's answers, as discovery collected them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeedAnswers {
    pub name: String,
    /// RESOLVE queries started and not started, answers received in the window, and those of them
    /// that were not public routable IPv4 or IPv6 addresses (R2).
    pub queries: u32,
    pub skipped: u32,
    pub answers: u32,
    pub rejected: u32,
    /// The other answers, with the chain's default port, by the query set they came through.
    pub usable: [Option<Endpoint>; QUERIES_PER_SEED],
}

/// What discovery found (C3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub seeds: Vec<SeedAnswers>,
    /// When discovery ended, from job start.
    pub duration: Ms,
}

/// The recipient of an opportunity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub endpoint: Endpoint,
    /// The name of the DNS seed it is credited to.
    pub provenance: String,
    /// The query set it came through.
    pub query_set: usize,
}

/// One DNS seed's entry in the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedSummary {
    pub name: String,
    pub queries: u32,
    pub skipped: u32,
    pub answers: u32,
    /// Distinct usable endpoints credited to this seed, each of which becomes a candidate.
    pub accepted: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    /// One per DNS seed, in the plan's order.
    pub seeds: Vec<SeedSummary>,
    /// Usable answers whose endpoint was already accepted, and answers that were not usable.
    pub duplicates: u32,
    pub rejected: u32,
    /// The sum of accepted.
    pub exit_path_candidates: u32,
    /// By slot, then opportunity. None where there is no candidate.
    pub opportunities: Vec<[Option<Candidate>; OPPORTUNITIES_PER_SLOT]>,
}

/// The hand-out state, by position in the plan's order of the seeds.
struct HandOut {
    /// Each seed's candidates not handed out yet, in the order it hands them out.
    left: Vec<Vec<Candidate>>,
    drawn_from: Vec<Vec<bool>>,
    supplied_first: Vec<bool>,
    next_seed: usize,
}

/// The candidate for one opportunity of a slot, or none.
fn draw(state: &mut HandOut, slot: usize, layer: usize) -> Option<Candidate> {
    let num_seeds = state.left.len();
    // A first attempt prefers its query set (R5c).
    let wanted = slot % QUERIES_PER_SEED;
    // First a seed the slot may still draw from, then any with a candidate left (R5b).
    for again in [false, true] {
        for any_set in [false, true] {
            if !any_set && layer > 0 {
                continue;
            }
            for step in 0..num_seeds {
                let pos = (state.next_seed + step) % num_seeds;
                let used = if layer == 0 { state.supplied_first[pos] } else { state.drawn_from[slot][pos] };
                if used && !again {
                    continue;
                }
                let candidates = &mut state.left[pos];
                let index = if any_set {
                    (!candidates.is_empty()).then_some(0)
                } else {
                    candidates.iter().position(|c| c.query_set == wanted)
                };
                let Some(index) = index else { continue };
                state.drawn_from[slot][pos] = true;
                if layer == 0 {
                    state.supplied_first[pos] = true;
                }
                state.next_seed = (pos + 1) % num_seeds;
                return Some(candidates.remove(index));
            }
        }
    }
    None
}

/// Each endpoint is credited to the first seed in plan.seed_order that returned it (R4), and to
/// the lowest query set it came through for that seed (R5c). A seed hands out its credited
/// endpoints in an order drawn at random, by a generator keyed from plan.answer_seed and the
/// seed's position (R5b). The opportunities are filled layer by layer, every slot's first
/// opportunity before any slot's first backup (R5a). In each layer the slots draw in turn, round
/// robin over the seeds, from a seed the slot may still draw from or, once none of those has a
/// candidate left, from any. In the first layer that is a seed that has supplied no first attempt,
/// in the others one the slot has not drawn from (R5b). For a first attempt, the seeds with a
/// candidate from query set slot mod QUERIES_PER_SEED come first, and that candidate is taken
/// (R5c).
pub fn assign(plan: &Plan, result: &DiscoveryResult) -> Assignment {
    assert!(result.seeds.iter().map(|s| &s.name).eq(plan.seed_order.iter()));
    let num_seeds = result.seeds.len();
    let mut assignment = Assignment {
        seeds: Vec::with_capacity(num_seeds),
        duplicates: 0,
        rejected: 0,
        exit_path_candidates: 0,
        opportunities: vec![Default::default(); SLOTS],
    };
    let mut left = Vec::with_capacity(num_seeds);
    let mut accepted = BTreeSet::new();
    for (pos, answers) in result.seeds.iter().enumerate() {
        assignment.rejected += answers.rejected;
        // By query set, so that the order the answers arrived in plays no part (R5b), and an
        // endpoint that came through several sets is credited to the lowest of them (R5c).
        let mut credited = Vec::new();
        for (set, endpoint) in answers.usable.iter().enumerate() {
            let Some(endpoint) = endpoint else { continue };
            if accepted.insert(*endpoint) {
                credited.push(Candidate { endpoint: *endpoint, provenance: answers.name.clone(), query_set: set });
            } else {
                assignment.duplicates += 1;
            }
        }
        // A generator per seed, so that how many answers the other seeds had plays no part in this
        // seed's order.
        let mut key = plan.answer_seed.to_le_bytes().to_vec();
        key.extend_from_slice(&(pos as u64).to_le_bytes());
        Rng::from_key(sha256::Hash::hash(&key).to_byte_array()).shuffle(&mut credited);
        assignment.seeds.push(SeedSummary {
            name: answers.name.clone(),
            queries: answers.queries,
            skipped: answers.skipped,
            answers: answers.answers,
            accepted: credited.len() as u32,
        });
        assignment.exit_path_candidates += credited.len() as u32;
        left.push(credited);
    }
    let mut state = HandOut {
        left,
        drawn_from: vec![vec![false; num_seeds]; SLOTS],
        supplied_first: vec![false; num_seeds],
        next_seed: 0,
    };
    if num_seeds > 0 {
        for layer in 0..OPPORTUNITIES_PER_SLOT {
            for slot in 0..SLOTS {
                assignment.opportunities[slot][layer] = draw(&mut state, slot, layer);
            }
        }
    }
    assignment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Addr;
    use crate::plan::draw_plan;
    use std::collections::{HashMap, HashSet};

    fn endpoint(seed: usize, set: usize) -> Endpoint {
        Endpoint { addr: Addr::V4([1, seed as u8, set as u8, 1]), port: 8333 }
    }

    fn result(plan: &Plan, answering: usize) -> DiscoveryResult {
        let seeds = plan
            .seed_order
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let mut s = SeedAnswers { name: name.clone(), queries: 4, ..Default::default() };
                if i < answering {
                    s.answers = 4;
                    s.usable = std::array::from_fn(|set| Some(endpoint(i, set)));
                }
                s
            })
            .collect();
        DiscoveryResult { seeds, duration: 0 }
    }

    #[test]
    fn properties() {
        let mut rng = Rng::from_key([5; 32]);
        let names: Vec<String> = (0..7).map(|i| format!("seed{i}")).collect();
        for answering in 0..=7 {
            for _ in 0..50 {
                let plan = draw_plan(&mut rng, Timing::default(), &names);
                let a = assign(&plan, &result(&plan, answering));
                let total = answering * QUERIES_PER_SEED;
                assert_eq!(a.exit_path_candidates as usize, total);
                let filled: Vec<&Candidate> = a.opportunities.iter().flatten().flatten().collect();
                // Every candidate used once at most (R4), and as many as there are opportunities.
                assert_eq!(filled.len(), total.min(SLOTS * OPPORTUNITIES_PER_SLOT));
                assert_eq!(filled.iter().map(|c| c.endpoint).collect::<HashSet<_>>().len(), filled.len());
                // R5a: first opportunities before backups.
                let firsts = a.opportunities.iter().filter(|o| o[0].is_some()).count();
                assert_eq!(firsts, total.min(SLOTS));
                // R5b: no seed supplies two first attempts while one has supplied none.
                let mut per_seed: HashMap<&str, usize> = HashMap::new();
                for o in &a.opportunities {
                    if let Some(c) = &o[0] {
                        *per_seed.entry(&c.provenance).or_default() += 1;
                    }
                }
                if answering >= SLOTS {
                    assert!(per_seed.values().all(|n| *n == 1));
                }
                // With all but one seed answering, every opportunity is filled (R3).
                if answering >= 6 {
                    assert_eq!(filled.len(), SLOTS * OPPORTUNITIES_PER_SLOT);
                }
                // R5c: slot j's first attempt from query set j mod 4.
                if answering >= SLOTS {
                    for (j, o) in a.opportunities.iter().enumerate() {
                        assert_eq!(o[0].as_ref().unwrap().query_set, j % QUERIES_PER_SEED);
                    }
                }
            }
        }
    }

    #[test]
    fn duplicates_credit_the_first_seed() {
        let mut rng = Rng::from_key([6; 32]);
        let names: Vec<String> = (0..3).map(|i| format!("seed{i}")).collect();
        let plan = draw_plan(&mut rng, Timing::default(), &names);
        let mut r = result(&plan, 3);
        let same = endpoint(9, 9);
        r.seeds[0].usable[2] = Some(same);
        r.seeds[1].usable[0] = Some(same);
        let a = assign(&plan, &r);
        assert_eq!(a.duplicates, 1);
        assert_eq!(a.seeds[0].accepted, 4);
        assert_eq!(a.seeds[1].accepted, 3);
    }
}
