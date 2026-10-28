//! What a job draws at its start, before any network activity (C1).

use crate::params::*;
use crate::rng::Rng;

/// A slot's times, as offsets from job start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotSchedule {
    pub index: usize,
    pub stratum: Stratum,
    /// The opportunities' scheduled starts: the first attempt, then each backup.
    pub scheduled: [Ms; OPPORTUNITIES_PER_SLOT],
    /// The last opportunity's scheduled start plus ATTEMPT_MAX. The slot ends by then (D2).
    pub scheduled_end: Ms,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub timing: Timing,
    pub slots: Vec<SlotSchedule>,
    /// Each DNS seed once, in the order candidates are credited and handed out (R5b).
    pub seed_order: Vec<String>,
    /// Seeds the order in which each DNS seed's candidates are handed out (R5b).
    pub answer_seed: u64,
}

/// A uniform draw from range under timing, at millisecond resolution.
fn draw(rng: &mut Rng, timing: &Timing, range: Range) -> Ms {
    let (min, max) = (timing.scale(range.min), timing.scale(range.max));
    min + rng.randrange((max - min + 1) as u64) as Ms
}

/// Draw a job's plan from rng alone: the schedule under timing, the order of dns_seeds and the
/// answer seed. A name listed twice counts once.
pub fn draw_plan(rng: &mut Rng, timing: Timing, dns_seeds: &[String]) -> Plan {
    let mut late = [0; 2];
    // Redrawn until LATE_SLOT_SEPARATION apart.
    loop {
        for offset in late.iter_mut() {
            *offset = draw(rng, &timing, LATE_SLOT_RANGE);
        }
        if (late[0] - late[1]).abs() >= timing.scale(LATE_SLOT_SEPARATION) {
            break;
        }
    }
    let delivery_start = timing.scale(DISCOVERY_WINDOW);
    let mut next_late = 0;
    let mut slots = Vec::with_capacity(SLOTS);
    for (index, stratum) in SLOT_LAYOUT.iter().copied().enumerate() {
        let mut scheduled = [delivery_start; OPPORTUNITIES_PER_SLOT];
        match stratum {
            Stratum::Prompt => {}
            Stratum::Mid => scheduled[0] += draw(rng, &timing, MID_SLOT_RANGE),
            Stratum::Late => {
                scheduled[0] += late[next_late];
                next_late += 1;
            }
        }
        for k in 1..OPPORTUNITIES_PER_SLOT {
            scheduled[k] = scheduled[k - 1] + draw(rng, &timing, BACKUP_RANGE);
        }
        let scheduled_end = scheduled[OPPORTUNITIES_PER_SLOT - 1] + timing.scale(ATTEMPT_MAX);
        slots.push(SlotSchedule { index, stratum, scheduled, scheduled_end });
    }
    let mut seed_order: Vec<String> = Vec::new();
    for name in dns_seeds {
        if !seed_order.contains(name) {
            seed_order.push(name.clone());
        }
    }
    rng.shuffle(&mut seed_order);
    Plan { timing, slots, seed_order, answer_seed: rng.rand64() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape() {
        let mut rng = Rng::from_key([3; 32]);
        let seeds: Vec<String> = ["a", "b", "a", "c"].iter().map(|s| s.to_string()).collect();
        for divisor in [1, 10, 1000] {
            let timing = Timing::new(divisor).unwrap();
            for _ in 0..200 {
                let plan = draw_plan(&mut rng, timing, &seeds);
                let mut order = plan.seed_order.clone();
                order.sort();
                assert_eq!(order, ["a", "b", "c"]);
                let start = timing.scale(DISCOVERY_WINDOW);
                for slot in &plan.slots {
                    let first = slot.scheduled[0] - start;
                    match slot.stratum {
                        Stratum::Prompt => assert_eq!(first, 0),
                        Stratum::Mid => assert!((timing.scale(35_000)..=timing.scale(180_000)).contains(&first)),
                        Stratum::Late => assert!((timing.scale(185_000)..=timing.scale(240_000)).contains(&first)),
                    }
                    for k in 1..OPPORTUNITIES_PER_SLOT {
                        let gap = slot.scheduled[k] - slot.scheduled[k - 1];
                        assert!((timing.scale(50_000)..=timing.scale(60_000)).contains(&gap));
                    }
                    assert_eq!(slot.scheduled_end, slot.scheduled[3] + timing.scale(ATTEMPT_MAX));
                    assert!(
                        slot.scheduled_end
                            <= timing.scale(DISCOVERY_WINDOW)
                                + timing.scale(LATE_SLOT_RANGE.max)
                                + timing.scale(SLOT_MAX)
                                + 3
                    );
                }
                assert!(
                    (plan.slots[4].scheduled[0] - plan.slots[5].scheduled[0]).abs()
                        >= timing.scale(LATE_SLOT_SEPARATION)
                );
            }
        }
    }
}
