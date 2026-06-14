//! Withdrawal scheduler — plugin layer component **W11** of the Wyrtloom
//! "Conversation" workflow (SoftDevSpec.md §2.2 row W11).
//!
//! Plans spaced **solo-flight** sessions per person using an
//! EXPANDING-INTERVAL algorithm. During a solo flight the agent is unavailable
//! for the flagged task scope except via an explicit, logged **human abort**.
//! Solo-flight outcomes update the calibration ledger as **PRACTICE** events,
//! never as assessments.
//!
//! Constitutional guarantees satisfied (cite `SoftDevSpec.md`):
//!
//! * **CG-13** — "The withdrawal scheduler SHALL plan spaced solo-flight
//!   sessions per person from the calibration ledger (spacing algorithm:
//!   expanding interval)." See [`Scheduler::plan`] and [`ExpansionPolicy`].
//! * **CG-14** — "During a solo flight the agent SHALL be unavailable for the
//!   flagged task scope except via explicit human abort (logged, never
//!   penalised)." See [`SoloFlight`] / [`SoloFlightState`] and
//!   [`Scheduler::abort`].
//! * **CG-15** — "Solo-flight outcomes SHALL update the calibration ledger as
//!   practice events, not assessments." See [`PracticeEvent`] and
//!   [`Scheduler::complete`] — every emitted record carries
//!   [`EventKind::Practice`] and is flagged non-penalising.
//!
//! Determinism (**CG-4 / CG-13**): the spacing algorithm is a pure function of
//! the seed events and the [`ExpansionPolicy`]. No LLM, no clock reads, no
//! randomness — given the same seeds it always yields the same schedule.

use chrono::Duration;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

/// A calibration-ledger seed for one person + task scope. The scheduler reads
/// these (never the assessment scores — CG-15/CG-23) to anchor the first
/// solo-flight and to count prior practice so intervals expand correctly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedEvent {
    /// The person the solo flight is planned for.
    pub actor: ActorId,
    /// The flagged task scope from which the agent withdraws (CG-14).
    pub task: TaskId,
    /// When this person last practised the scope (their ledger anchor).
    pub last_practiced: Timestamp,
    /// How many practice sessions already completed for this scope. Drives the
    /// expanding interval — every prior session pushes the next one further out.
    pub prior_sessions: u32,
}

/// The expanding-interval spacing rule (CG-13).
///
/// The interval before the *n*-th planned session (counting from the seed's
/// `prior_sessions` as the starting index) is:
///
/// ```text
/// interval(n) = base * factor^n          // truncated toward zero, integer days
/// interval(n) = min(interval(n), cap)    // never exceed the ceiling
/// ```
///
/// Each successive session is therefore spaced strictly further out than the
/// last (until the `cap_days` ceiling), implementing expanding retrieval
/// practice. The computation uses only integers, so it is bit-for-bit
/// deterministic across platforms (CG-4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpansionPolicy {
    /// Days before the very first session (n = 0).
    pub base_days: u32,
    /// Multiplicative growth factor numerator, expressed as a percentage so the
    /// rule stays integer-only and deterministic. e.g. `200` = ×2.0 per step.
    pub factor_percent: u32,
    /// Upper bound on any single interval, in days.
    pub cap_days: u32,
}

impl Default for ExpansionPolicy {
    /// A sensible default: 7 days, doubling each session, capped at 90 days.
    fn default() -> Self {
        Self { base_days: 7, factor_percent: 200, cap_days: 90 }
    }
}

impl ExpansionPolicy {
    /// Deterministic interval (in whole days) before the `n`-th session.
    ///
    /// `interval(n) = clamp(base * (factor_percent/100)^n, .., cap)`.
    /// Integer-only with explicit saturation so it never panics or diverges.
    pub fn interval_days(&self, n: u32) -> u32 {
        // base, scaled up by the percentage factor applied `n` times.
        // Work in u64 to delay saturation, then clamp to the cap.
        let mut value: u64 = self.base_days as u64;
        for _ in 0..n {
            value = value.saturating_mul(self.factor_percent as u64) / 100;
            if value >= self.cap_days as u64 {
                return self.cap_days;
            }
        }
        value.min(self.cap_days as u64) as u32
    }
}

/// One planned solo-flight session in the schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedSession {
    pub actor: ActorId,
    pub task: TaskId,
    /// Session index within this person's expanding ladder (0-based, offset by
    /// the seed's `prior_sessions`).
    pub index: u32,
    /// Deterministic scheduled start, computed from the seed anchor.
    pub scheduled_at: Timestamp,
    /// The interval (days) that produced this session — for audit / testing.
    pub interval_days: u32,
}

/// Lifecycle of a single solo flight (CG-14). The agent is *withdrawn* for the
/// flagged scope while a flight is `Active`; the only ways out are a normal
/// `Completed` (success or not — still practice) or an explicit, logged
/// human `Aborted`.
///
/// ```text
///                 plan()
///   (none) ────────────────▶ Active
///                              │  │
///              complete(...)   │  │   abort(reason)  [explicit human action]
///                              ▼  ▼
///                        Completed  Aborted
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SoloFlightState {
    /// Agent withdrawn from the flagged scope; person flies solo.
    Active,
    /// Flight ran its course. Outcome recorded as practice (CG-15).
    Completed,
    /// A human explicitly pulled the agent back in. Logged, never penalised
    /// (CG-14).
    Aborted { reason: String },
}

/// A running solo flight bound to a planned session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoloFlight {
    pub actor: ActorId,
    pub task: TaskId,
    pub index: u32,
    pub state: SoloFlightState,
}

impl SoloFlight {
    /// Begin a solo flight for a planned session. The agent is now unavailable
    /// for `session.task` (CG-14).
    pub fn begin(session: &PlannedSession) -> Self {
        Self {
            actor: session.actor.clone(),
            task: session.task,
            index: session.index,
            state: SoloFlightState::Active,
        }
    }

    /// Is the agent currently withdrawn for this flight's scope? (CG-14)
    pub fn agent_withdrawn(&self) -> bool {
        matches!(self.state, SoloFlightState::Active)
    }
}

/// What kind of ledger event a flight produces. There is intentionally **no**
/// `Assessment` variant: the API design makes recording a solo flight as an
/// assessment unrepresentable (CG-15 / CG-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    /// Developmental practice. Never scored, never penalising.
    Practice,
}

/// How a flight ended — both feed the ledger as practice (CG-15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlightOutcome {
    /// The person finished the solo flight (regardless of how it went).
    Flown,
    /// A human explicitly aborted; the agent was pulled back in (CG-14).
    Aborted { reason: String },
}

/// A calibration-ledger update emitted by the scheduler. Always a practice
/// event; `penalised` is always `false` by construction (CG-14 / CG-15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PracticeEvent {
    pub actor: ActorId,
    pub task: TaskId,
    pub index: u32,
    pub kind: EventKind,
    pub outcome: FlightOutcome,
    /// Invariant: always `false`. Solo flights and aborts are never penalised.
    pub penalised: bool,
}

impl PracticeEvent {
    fn new(flight: &SoloFlight, outcome: FlightOutcome) -> Self {
        Self {
            actor: flight.actor.clone(),
            task: flight.task,
            index: flight.index,
            kind: EventKind::Practice,
            outcome,
            penalised: false,
        }
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    #[error("solo flight is not active (state already terminal)")]
    NotActive,
    #[error("invalid expansion policy: {0}")]
    InvalidPolicy(String),
}

/// The withdrawal scheduler (W11).
///
/// Pure planner + a thin lifecycle/recording surface. Holds no mutable global
/// state; all methods are deterministic functions of their inputs.
#[derive(Debug, Clone)]
pub struct Scheduler {
    policy: ExpansionPolicy,
}

impl Scheduler {
    /// Build a scheduler from an expansion policy (CG-13).
    pub fn new(policy: ExpansionPolicy) -> Result<Self, ScheduleError> {
        if policy.base_days == 0 {
            return Err(ScheduleError::InvalidPolicy("base_days must be > 0".into()));
        }
        if policy.factor_percent <= 100 {
            return Err(ScheduleError::InvalidPolicy(
                "factor_percent must be > 100 so intervals expand".into(),
            ));
        }
        if policy.cap_days < policy.base_days {
            return Err(ScheduleError::InvalidPolicy(
                "cap_days must be >= base_days".into(),
            ));
        }
        // factor_percent > 100 is necessary but not sufficient: integer
        // truncation can leave a small base permanently stuck (e.g.
        // base=1, factor=150 -> 1*150/100 = 1 forever). Require the first
        // growth step to actually exceed base_days, otherwise the ladder never
        // expands and the CG-13 guarantee would be false. (Holds while below
        // the cap; once capped the interval is constant by design.)
        let first_step = (policy.base_days as u64) * (policy.factor_percent as u64) / 100;
        if first_step <= policy.base_days as u64 && policy.base_days < policy.cap_days {
            return Err(ScheduleError::InvalidPolicy(format!(
                "base_days {} too small for factor_percent {}: integer truncation \
                 leaves intervals non-expanding",
                policy.base_days, policy.factor_percent
            )));
        }
        Ok(Self { policy })
    }

    /// Plan `count` spaced solo-flight sessions for each seed event (CG-13).
    ///
    /// Deterministic: sessions are produced in seed order, and each person's
    /// session times follow the expanding-interval ladder anchored at their
    /// `last_practiced` timestamp, offset by `prior_sessions`.
    pub fn plan(&self, seeds: &[SeedEvent], count: u32) -> Vec<PlannedSession> {
        let mut sessions = Vec::new();
        for seed in seeds {
            // Anchor accumulates forward through the expanding intervals so each
            // session lands strictly later than the previous one.
            let mut anchor = seed.last_practiced.0;
            for step in 0..count {
                // Saturating so an extreme prior_sessions never panics/wraps
                // to an *earlier* index (which would un-expand the ladder).
                let index = seed.prior_sessions.saturating_add(step);
                let days = self.policy.interval_days(index);
                // chrono's `+` panics on overflow; use the checked path and
                // saturate so plan() stays a total, deterministic function
                // even for anchors near the DateTime range limit (CG-4).
                anchor = anchor
                    .checked_add_signed(Duration::days(days as i64))
                    .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC);
                sessions.push(PlannedSession {
                    actor: seed.actor.clone(),
                    task: seed.task,
                    index,
                    scheduled_at: Timestamp(anchor),
                    interval_days: days,
                });
            }
        }
        sessions
    }

    /// Complete a solo flight normally. Returns the practice event to apply to
    /// the calibration ledger (CG-15) and the terminal flight.
    pub fn complete(&self, flight: SoloFlight) -> Result<(SoloFlight, PracticeEvent), ScheduleError> {
        if !flight.agent_withdrawn() {
            return Err(ScheduleError::NotActive);
        }
        let event = PracticeEvent::new(&flight, FlightOutcome::Flown);
        let done = SoloFlight { state: SoloFlightState::Completed, ..flight };
        Ok((done, event))
    }

    /// Explicit human abort (CG-14): pull the agent back into the flagged
    /// scope. The abort is recorded as a practice event, never penalised
    /// (CG-15) — the returned event has `penalised == false`.
    pub fn abort(
        &self,
        flight: SoloFlight,
        reason: impl Into<String>,
    ) -> Result<(SoloFlight, PracticeEvent), ScheduleError> {
        if !flight.agent_withdrawn() {
            return Err(ScheduleError::NotActive);
        }
        let reason = reason.into();
        let event = PracticeEvent::new(&flight, FlightOutcome::Aborted { reason: reason.clone() });
        let aborted = SoloFlight { state: SoloFlightState::Aborted { reason }, ..flight };
        Ok((aborted, event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn ts(rfc3339: &str) -> Timestamp {
        Timestamp(
            chrono::DateTime::parse_from_rfc3339(rfc3339)
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }

    fn policy() -> ExpansionPolicy {
        ExpansionPolicy { base_days: 7, factor_percent: 200, cap_days: 90 }
    }

    // ---- CG-13: expanding-interval determinism ----------------------------

    #[test]
    fn intervals_expand_strictly_until_cap() {
        let p = policy();
        // 7, 14, 28, 56, then capped at 90.
        assert_eq!(p.interval_days(0), 7);
        assert_eq!(p.interval_days(1), 14);
        assert_eq!(p.interval_days(2), 28);
        assert_eq!(p.interval_days(3), 56);
        assert_eq!(p.interval_days(4), 90);
        assert_eq!(p.interval_days(50), 90); // never diverges past the cap
    }

    #[test]
    fn intervals_are_monotonically_non_decreasing() {
        let p = policy();
        let mut prev = 0;
        for n in 0..20 {
            let cur = p.interval_days(n);
            assert!(cur >= prev, "interval must not shrink at step {n}");
            prev = cur;
        }
    }

    #[test]
    fn plan_is_deterministic_and_spaced() {
        let sched = Scheduler::new(policy()).unwrap();
        let task = Uuid::new_v4();
        let seeds = vec![SeedEvent {
            actor: "alice".into(),
            task,
            last_practiced: ts("2026-01-01T00:00:00Z"),
            prior_sessions: 0,
        }];

        let a = sched.plan(&seeds, 4);
        let b = sched.plan(&seeds, 4);
        assert_eq!(a, b, "planning must be deterministic");

        assert_eq!(a.len(), 4);
        // Cumulative offsets from 2026-01-01: +7, +21, +49, +105 days.
        assert_eq!(a[0].scheduled_at, ts("2026-01-08T00:00:00Z"));
        assert_eq!(a[1].scheduled_at, ts("2026-01-22T00:00:00Z"));
        assert_eq!(a[2].scheduled_at, ts("2026-02-19T00:00:00Z"));
        assert_eq!(a[3].scheduled_at, ts("2026-04-16T00:00:00Z"));

        // Strictly increasing schedule times.
        for w in a.windows(2) {
            assert!(w[1].scheduled_at.0 > w[0].scheduled_at.0);
        }
    }

    #[test]
    fn prior_sessions_offset_the_ladder() {
        let sched = Scheduler::new(policy()).unwrap();
        let task = Uuid::new_v4();
        let seeds = vec![SeedEvent {
            actor: "bob".into(),
            task,
            last_practiced: ts("2026-01-01T00:00:00Z"),
            prior_sessions: 2, // already practised twice -> start at interval(2)=28
        }];
        let plan = sched.plan(&seeds, 1);
        assert_eq!(plan[0].index, 2);
        assert_eq!(plan[0].interval_days, 28);
        assert_eq!(plan[0].scheduled_at, ts("2026-01-29T00:00:00Z"));
    }

    #[test]
    fn plan_keyed_per_actor() {
        let sched = Scheduler::new(policy()).unwrap();
        let seeds = vec![
            SeedEvent {
                actor: "alice".into(),
                task: Uuid::new_v4(),
                last_practiced: ts("2026-01-01T00:00:00Z"),
                prior_sessions: 0,
            },
            SeedEvent {
                actor: "bob".into(),
                task: Uuid::new_v4(),
                last_practiced: ts("2026-01-01T00:00:00Z"),
                prior_sessions: 0,
            },
        ];
        let plan = sched.plan(&seeds, 2);
        assert_eq!(plan.len(), 4);
        assert_eq!(plan[0].actor, "alice");
        assert_eq!(plan[2].actor, "bob");
    }

    #[test]
    fn rejects_non_expanding_policy() {
        assert!(Scheduler::new(ExpansionPolicy {
            base_days: 7,
            factor_percent: 100, // not expanding
            cap_days: 90
        })
        .is_err());
        assert!(Scheduler::new(ExpansionPolicy {
            base_days: 0,
            factor_percent: 200,
            cap_days: 90
        })
        .is_err());
        // Truncation trap: base too small for the factor -> never expands.
        assert!(Scheduler::new(ExpansionPolicy {
            base_days: 1,
            factor_percent: 150,
            cap_days: 90
        })
        .is_err());
        // But a small base whose ladder is immediately capped is fine.
        assert!(Scheduler::new(ExpansionPolicy {
            base_days: 1,
            factor_percent: 150,
            cap_days: 1
        })
        .is_ok());
    }

    #[test]
    fn plan_saturates_instead_of_panicking_on_extreme_inputs() {
        let sched = Scheduler::new(policy()).unwrap();
        let seeds = vec![SeedEvent {
            actor: "alice".into(),
            task: Uuid::new_v4(),
            last_practiced: ts("2026-01-01T00:00:00Z"),
            prior_sessions: u32::MAX,
        }];
        // Must not panic and must not wrap to an earlier index.
        let plan = sched.plan(&seeds, 3);
        assert_eq!(plan[0].index, u32::MAX);
        assert_eq!(plan[1].index, u32::MAX); // saturated, never wraps to 0
        assert_eq!(plan[2].index, u32::MAX);
    }

    // ---- CG-14: withdrawal + explicit abort -------------------------------

    #[test]
    fn agent_is_withdrawn_while_active() {
        let sched = Scheduler::new(policy()).unwrap();
        let task = Uuid::new_v4();
        let seeds = vec![SeedEvent {
            actor: "alice".into(),
            task,
            last_practiced: ts("2026-01-01T00:00:00Z"),
            prior_sessions: 0,
        }];
        let session = &sched.plan(&seeds, 1)[0];
        let flight = SoloFlight::begin(session);
        assert!(flight.agent_withdrawn());
    }

    #[test]
    fn abort_is_explicit_and_logged_never_penalised() {
        let sched = Scheduler::new(policy()).unwrap();
        let task = Uuid::new_v4();
        let session = PlannedSession {
            actor: "alice".into(),
            task,
            index: 0,
            scheduled_at: ts("2026-01-08T00:00:00Z"),
            interval_days: 7,
        };
        let flight = SoloFlight::begin(&session);
        let (aborted, event) = sched.abort(flight, "production incident").unwrap();

        assert!(matches!(aborted.state, SoloFlightState::Aborted { .. }));
        assert!(!aborted.agent_withdrawn());
        assert_eq!(event.kind, EventKind::Practice);
        assert!(!event.penalised, "abort must never be penalised (CG-14)");
        assert!(matches!(event.outcome, FlightOutcome::Aborted { .. }));
    }

    #[test]
    fn cannot_abort_terminal_flight() {
        let sched = Scheduler::new(policy()).unwrap();
        let flight = SoloFlight {
            actor: "alice".into(),
            task: Uuid::new_v4(),
            index: 0,
            state: SoloFlightState::Completed,
        };
        assert_eq!(sched.abort(flight, "late"), Err(ScheduleError::NotActive));
    }

    // ---- CG-15: outcomes are practice, not assessments --------------------

    #[test]
    fn completion_records_practice_event() {
        let sched = Scheduler::new(policy()).unwrap();
        let flight = SoloFlight {
            actor: "alice".into(),
            task: Uuid::new_v4(),
            index: 3,
            state: SoloFlightState::Active,
        };
        let (done, event) = sched.complete(flight).unwrap();
        assert!(matches!(done.state, SoloFlightState::Completed));
        assert_eq!(event.kind, EventKind::Practice);
        assert!(!event.penalised);
        assert_eq!(event.outcome, FlightOutcome::Flown);
        assert_eq!(event.index, 3);
    }
}
