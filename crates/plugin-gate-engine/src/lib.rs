//! W2 — Gate engine: guarded Kanban transitions.
//!
//! Implements SoftDevSpec §2.2 row W2 ("Guarded Kanban transitions;
//! emits/validates approval tokens") and the following Conversation-core
//! requirements:
//!
//!   * **CG-1** — every gate presents a digest before any challenge
//!     (instruction-first). This engine issues an approval *token* only after
//!     a digest has been presented; [`GateToken`] carries the digest summary it
//!     was issued against so the audit trail proves digest-before-challenge.
//!   * **CG-4** — all pass/fail logic is deterministic. Token validation is a
//!     pure HMAC comparison via [`wyrtloom_core::security::SecurityModule`]; no
//!     LLM participates in the pass/fail decision.
//!   * **CG-24** — a gate approval token SHALL carry a blame-allocation notice:
//!     *passage ≠ liability transfer*. Every [`GateToken`] embeds a
//!     [`BlameNotice`] and the notice text is bound into the HMAC, so the
//!     notice cannot be stripped without invalidating the token.
//!   * **CG-28** — all gate events SHALL be logged via the call logger for
//!     audit. Both successful and refused guarded transitions emit a
//!     [`wyrtloom_core::logger::CallLog`] through the injected
//!     [`wyrtloom_core::logger::CallLogger`].
//!
//! ## Token model
//!
//! A gate approval token authorises exactly one Kanban transition of one task,
//! by one actor, into one target stage. The authenticated message is the tuple
//! `(task, from, to, actor, blame_notice, digest)` serialised canonically and
//! stamped with `SecurityModule::stamp` (HMAC-SHA256). Validation recomputes
//! the same message and calls `SecurityModule::is_valid`; a token presented for
//! a different task / stage / actor (or with a tampered blame notice) recomputes
//! to a different message and is rejected. This binds *passage ≠ liability*
//! cryptographically: the blame notice is not advisory metadata, it is part of
//! what the gate signed.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use wyrtloom_core::kanban::{is_legal_transition, KanbanBoard, KanbanError, TaskState};
use wyrtloom_core::logger::{CallLog, CallLogger, CallOutcome, LogError};
use wyrtloom_core::provider::Usage;
use wyrtloom_core::security::{SecurityModule, Stamp};
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

/// The canonical blame-allocation notice carried by every gate token (CG-24).
///
/// Passage of a gate is *not* a transfer of liability for downstream agent
/// defects to the human who passed it. The notice is recorded in the token and
/// bound into its HMAC so it travels with — and cannot be detached from — the
/// approval. Incident tooling links defects to the system-level review template
/// named here rather than to the gate-passer.
pub const BLAME_NOTICE_TEXT: &str =
    "Gate passage does not transfer liability for agent defects to the passer. \
     Override and approval stamps are remediation signals, not culpability markers. \
     Incident review is system-level (moral-crumple-zone guard, D15.5).";

/// Default system-level incident review template that defects are linked to
/// (CG-24). Concrete tooling may override this per workflow profile.
pub const DEFAULT_REVIEW_TEMPLATE: &str = "review-template:system-level/default";

/// Blame-allocation notice embedded in (and HMAC-bound to) every gate token.
///
/// Implements CG-24: passage ≠ liability transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlameNotice {
    /// Human-readable notice. Defaults to [`BLAME_NOTICE_TEXT`].
    pub notice: String,
    /// Identifier of the system-level review template incidents link to.
    pub review_template: String,
}

impl Default for BlameNotice {
    fn default() -> Self {
        Self {
            notice: BLAME_NOTICE_TEXT.to_string(),
            review_template: DEFAULT_REVIEW_TEMPLATE.to_string(),
        }
    }
}

/// An approval token authorising one guarded Kanban transition.
///
/// The token is meaningless without the [`SecurityModule`] that issued it: the
/// `stamp` is an HMAC over the other fields, so the token cannot be forged or
/// repurposed for a different `(task, from, to, actor)` tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateToken {
    /// Task the transition applies to.
    pub task: TaskId,
    /// State the task is expected to be in when the token is redeemed.
    pub from: TaskState,
    /// Target state this token authorises a move into.
    pub to: TaskState,
    /// Actor (human or agent) the token is bound to.
    pub actor: ActorId,
    /// Blame-allocation notice (CG-24), HMAC-bound into the stamp.
    pub blame: BlameNotice,
    /// Digest summary presented at the gate before this token was issued (CG-1).
    pub digest_summary: String,
    /// HMAC-SHA256 stamp over the canonical message, via `SecurityModule::stamp`.
    pub stamp: Stamp,
}

impl GateToken {
    /// Canonical authenticated message: every field except the stamp itself.
    ///
    /// Deterministic (CG-4): a fixed serialisation of fixed inputs. The blame
    /// notice and digest summary are included, so tampering with either changes
    /// the message and invalidates the stamp.
    fn message(
        task: TaskId,
        from: &TaskState,
        to: &TaskState,
        actor: &ActorId,
        blame: &BlameNotice,
        digest_summary: &str,
    ) -> Vec<u8> {
        // A length-prefixed, field-tagged encoding avoids ambiguity between,
        // e.g., actor="a" task ending "b" and actor="ab" — no field boundary
        // can be shifted without changing the bytes.
        let mut msg = Vec::new();
        let mut push = |tag: &str, bytes: &[u8]| {
            msg.extend_from_slice(tag.as_bytes());
            msg.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            msg.extend_from_slice(bytes);
        };
        push("task", task.as_bytes());
        push("from", from.to_string().as_bytes());
        push("to", to.to_string().as_bytes());
        push("actor", actor.as_bytes());
        push("blame_notice", blame.notice.as_bytes());
        push("blame_template", blame.review_template.as_bytes());
        push("digest", digest_summary.as_bytes());
        msg
    }
}

/// Errors raised while issuing or redeeming gate tokens.
#[derive(Error, Debug)]
pub enum GateError {
    /// CG-1: a token may not be issued before a digest is presented.
    #[error("no digest presented before challenge (CG-1 violation)")]
    DigestRequired,
    /// A token was requested for a move the workflow does not permit.
    #[error("refusing to issue token for illegal transition {from:?}→{to:?}")]
    IllegalTransition { from: TaskState, to: TaskState },
    /// The presented token is not a valid HMAC for this exact transition.
    #[error("gate token is invalid, forged, or does not match the requested transition")]
    InvalidToken,
    /// A guarded transition was attempted without any token.
    #[error("guarded transition refused: no approval token presented")]
    TokenRequired,
    /// The board's current state does not match the source state the token was
    /// issued against — e.g. a stale token replayed after the task moved on.
    #[error("stage mismatch: board is in {board_state:?}, token was issued from {token_from:?}")]
    StageMismatch {
        /// The task's actual current state on the board.
        board_state: TaskState,
        /// The source state the token authorises leaving from.
        token_from: TaskState,
    },
    /// Underlying Kanban board rejected the transition.
    #[error(transparent)]
    Kanban(#[from] KanbanError),
    /// Audit logging failed; a gate decision must never go unlogged (CG-28),
    /// so a logging failure fails the operation rather than proceeding silently.
    #[error("gate audit logging failed (CG-28): {0}")]
    Audit(#[from] LogError),
}

/// Provenance string recorded in the audit log's `provider` field so gate
/// events are filterable alongside LLM call logs.
pub const GATE_AUDIT_PROVIDER: &str = "wyrtloom-gate-engine";

/// W2 gate engine. Issues and validates approval tokens and drives guarded
/// transitions on any [`KanbanBoard`], logging every decision (CG-28).
pub struct GateEngine<'a> {
    security: &'a SecurityModule,
    logger: &'a dyn CallLogger,
}

impl<'a> GateEngine<'a> {
    /// Construct a gate engine over a shared security root-of-trust and audit
    /// logger.
    pub fn new(security: &'a SecurityModule, logger: &'a dyn CallLogger) -> Self {
        Self { security, logger }
    }

    /// Issue an approval token for a `from→to` transition of `task` by `actor`,
    /// using the default blame notice (CG-24).
    ///
    /// `digest_summary` is the instruction-first digest presented at the gate
    /// (CG-1); it must be non-empty — a token cannot be minted before a digest
    /// is shown. The notice is bound into the HMAC.
    pub fn issue_token(
        &self,
        task: TaskId,
        from: TaskState,
        to: TaskState,
        actor: ActorId,
        digest_summary: &str,
    ) -> Result<GateToken, GateError> {
        self.issue_token_with_blame(task, from, to, actor, digest_summary, BlameNotice::default())
    }

    /// Like [`issue_token`](Self::issue_token) but with an explicit blame notice
    /// (e.g. a workflow-specific review template).
    pub fn issue_token_with_blame(
        &self,
        task: TaskId,
        from: TaskState,
        to: TaskState,
        actor: ActorId,
        digest_summary: &str,
        blame: BlameNotice,
    ) -> Result<GateToken, GateError> {
        // CG-1: instruction-first — refuse to issue a token with no digest.
        if digest_summary.trim().is_empty() {
            return Err(GateError::DigestRequired);
        }
        // Defence-in-depth: never mint an approval for a move the workflow does
        // not permit. Legality is owned by core's `is_legal_transition`; the
        // board re-checks at redemption, but refusing here keeps illegal
        // approvals out of the audit trail entirely.
        if !is_legal_transition(&from, &to) {
            return Err(GateError::IllegalTransition { from, to });
        }
        let msg = GateToken::message(task, &from, &to, &actor, &blame, digest_summary);
        let stamp = self.security.stamp(&msg);
        Ok(GateToken {
            task,
            from,
            to,
            actor,
            blame,
            digest_summary: digest_summary.to_string(),
            stamp,
        })
    }

    /// Deterministically verify the token's HMAC (CG-4): confirms the token is
    /// authentic and internally intact — none of its fields (task, from, to,
    /// actor, blame notice, digest) have been tampered with since issuance.
    ///
    /// This proves *what the gate signed*; it does NOT by itself check the token
    /// against a particular request. Matching a token to a concrete
    /// `task / to / actor` request and to the board's current state is done by
    /// [`guarded_transition`](Self::guarded_transition), which is the only
    /// supported redemption path.
    pub fn validate(&self, token: &GateToken) -> Result<(), GateError> {
        let msg = GateToken::message(
            token.task,
            &token.from,
            &token.to,
            &token.actor,
            &token.blame,
            &token.digest_summary,
        );
        if self.security.is_valid(&token.stamp, &msg) {
            Ok(())
        } else {
            Err(GateError::InvalidToken)
        }
    }

    /// Drive a guarded transition on `board`. The transition is refused unless a
    /// `token` is present and validates for this exact move. Every outcome —
    /// refusal or success — is logged via the call logger (CG-28).
    ///
    /// `token` is `Option` so an *ungated* attempt (no token) is a first-class,
    /// auditable refusal rather than a programming error.
    pub fn guarded_transition(
        &self,
        board: &dyn KanbanBoard,
        token: Option<&GateToken>,
        task: TaskId,
        to: TaskState,
        actor: ActorId,
        reason: Option<String>,
    ) -> Result<(), GateError> {
        // 1. A token must be present.
        let token = match token {
            Some(t) => t,
            None => {
                self.audit(task, CallOutcome::Failed(
                    "ungated transition refused: no approval token".into(),
                ))?;
                return Err(GateError::TokenRequired);
            }
        };

        // 2. The token must authorise this exact target stage and actor.
        if token.to != to || token.task != task || token.actor != actor {
            self.audit(task, CallOutcome::Failed(format!(
                "token/request mismatch: token authorises {}→{} for {}, requested →{} for {}",
                token.from, token.to, token.actor, to, actor,
            )))?;
            return Err(GateError::InvalidToken);
        }

        // 3. The token's HMAC must verify (deterministic; CG-4).
        if let Err(e) = self.validate(token) {
            self.audit(task, CallOutcome::Failed(
                "approval token failed HMAC validation".into(),
            ))?;
            return Err(e);
        }

        // 4. Cross-check the board's current state matches the token's `from`,
        //    so a token minted for an earlier state cannot be replayed later.
        let current = match board.get(task) {
            Ok(t) => t.state,
            Err(e) => {
                // CG-28: even a board-lookup failure on a guarded transition is
                // an auditable gate refusal — log it before returning.
                self.audit(task, CallOutcome::Failed(format!(
                    "board lookup failed during guarded transition: {}",
                    e,
                )))?;
                return Err(GateError::Kanban(e));
            }
        };
        if current != token.from {
            self.audit(task, CallOutcome::Failed(format!(
                "stage mismatch: board is {}, token issued from {}",
                current, token.from,
            )))?;
            return Err(GateError::StageMismatch {
                board_state: current,
                token_from: token.from.clone(),
            });
        }

        // 5. Perform the underlying transition.
        match board.transition(task, to.clone(), actor, reason) {
            Ok(()) => {
                self.audit(task, CallOutcome::Completed)?;
                Ok(())
            }
            Err(e) => {
                self.audit(task, CallOutcome::Failed(format!(
                    "board rejected guarded transition →{}: {}",
                    to, e,
                )))?;
                Err(GateError::Kanban(e))
            }
        }
    }

    /// Emit one audit entry for a gate decision (CG-28). Failures here are
    /// propagated so a gate decision is never silently unlogged.
    fn audit(&self, task: TaskId, outcome: CallOutcome) -> Result<(), GateError> {
        let entry = CallLog {
            task,
            profile: "gate".into(),
            provider: GATE_AUDIT_PROVIDER.into(),
            model: "n/a".into(),
            usage: Usage { input_tokens: 0, output_tokens: 0, cost: None },
            outcome,
            at: Timestamp::now(),
        };
        // `?` converts LogError → GateError::Audit via the `From` impl.
        self.logger.record(entry)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use uuid::Uuid;
    use wyrtloom_core::logger::CallLog;

    // ── In-test fake logger (records entries in memory) ──────────────────────
    #[derive(Default)]
    struct FakeLogger {
        entries: Mutex<Vec<CallLog>>,
    }
    impl CallLogger for FakeLogger {
        fn record(&self, entry: CallLog) -> Result<(), LogError> {
            self.entries.lock().unwrap().push(entry);
            Ok(())
        }
    }
    impl FakeLogger {
        fn count(&self) -> usize {
            self.entries.lock().unwrap().len()
        }
        fn last(&self) -> CallLog {
            self.entries.lock().unwrap().last().unwrap().clone()
        }
    }

    // A logger that always fails — to prove gate decisions fail closed (CG-28).
    struct FailingLogger;
    impl CallLogger for FailingLogger {
        fn record(&self, _entry: CallLog) -> Result<(), LogError> {
            Err(LogError::Storage("disk full".into()))
        }
    }

    fn task_id() -> TaskId {
        Uuid::new_v4()
    }

    // ── CG-24: blame notice is present and bound to the token ────────────────
    #[test]
    fn token_carries_blame_allocation_notice() {
        let sec = SecurityModule::new();
        let log = FakeLogger::default();
        let eng = GateEngine::new(&sec, &log);
        let t = eng
            .issue_token(task_id(), TaskState::Running, TaskState::Done, "human:a".into(), "digest v1")
            .unwrap();
        assert!(t.blame.notice.contains("does not transfer liability"));
        assert_eq!(t.blame.review_template, DEFAULT_REVIEW_TEMPLATE);
    }

    #[test]
    fn tampering_with_blame_notice_invalidates_token() {
        let sec = SecurityModule::new();
        let log = FakeLogger::default();
        let eng = GateEngine::new(&sec, &log);
        let mut t = eng
            .issue_token(task_id(), TaskState::Running, TaskState::Done, "human:a".into(), "d")
            .unwrap();
        // Stripping/altering the notice must break HMAC validation (CG-24).
        t.blame.notice = "passage transfers all blame to you".into();
        assert!(matches!(eng.validate(&t), Err(GateError::InvalidToken)));
    }

    // ── CG-1: instruction-first — no token without a digest ──────────────────
    #[test]
    fn token_issue_requires_a_digest() {
        let sec = SecurityModule::new();
        let log = FakeLogger::default();
        let eng = GateEngine::new(&sec, &log);
        let err = eng
            .issue_token(task_id(), TaskState::Running, TaskState::Done, "human:a".into(), "   ")
            .unwrap_err();
        assert!(matches!(err, GateError::DigestRequired));
    }

    // ── Illegal moves are refused at issue time (defence-in-depth) ───────────
    #[test]
    fn token_for_illegal_transition_is_refused() {
        let sec = SecurityModule::new();
        let log = FakeLogger::default();
        let eng = GateEngine::new(&sec, &log);
        // Backlog→Done is not a legal Kanban transition.
        let err = eng
            .issue_token(task_id(), TaskState::Backlog, TaskState::Done, "human:a".into(), "d")
            .unwrap_err();
        assert!(matches!(err, GateError::IllegalTransition { .. }));
    }

    // ── Token validity / forgery (CG-4 determinism) ──────────────────────────
    #[test]
    fn valid_token_validates() {
        let sec = SecurityModule::new();
        let log = FakeLogger::default();
        let eng = GateEngine::new(&sec, &log);
        let t = eng
            .issue_token(task_id(), TaskState::Running, TaskState::Done, "human:a".into(), "d")
            .unwrap();
        assert!(eng.validate(&t).is_ok());
    }

    #[test]
    fn token_for_different_actor_is_rejected() {
        let sec = SecurityModule::new();
        let log = FakeLogger::default();
        let eng = GateEngine::new(&sec, &log);
        let mut t = eng
            .issue_token(task_id(), TaskState::Running, TaskState::Done, "human:a".into(), "d")
            .unwrap();
        t.actor = "human:b".into();
        assert!(matches!(eng.validate(&t), Err(GateError::InvalidToken)));
    }

    #[test]
    fn token_for_different_target_stage_is_rejected() {
        let sec = SecurityModule::new();
        let log = FakeLogger::default();
        let eng = GateEngine::new(&sec, &log);
        let mut t = eng
            .issue_token(task_id(), TaskState::Running, TaskState::Done, "human:a".into(), "d")
            .unwrap();
        t.to = TaskState::Blocked;
        assert!(matches!(eng.validate(&t), Err(GateError::InvalidToken)));
    }

    #[test]
    fn forged_stamp_is_rejected() {
        let sec = SecurityModule::new();
        let log = FakeLogger::default();
        let eng = GateEngine::new(&sec, &log);
        let mut t = eng
            .issue_token(task_id(), TaskState::Running, TaskState::Done, "human:a".into(), "d")
            .unwrap();
        t.stamp = Stamp([0u8; 32]);
        assert!(matches!(eng.validate(&t), Err(GateError::InvalidToken)));
    }

    // ── CG-28: every decision is logged; logging failure fails closed ────────
    #[test]
    fn logging_failure_fails_the_gate_closed() {
        let sec = SecurityModule::new();
        let log = FailingLogger;
        let eng = GateEngine::new(&sec, &log);
        // An ungated attempt must emit an audit entry; if logging fails the
        // operation must surface the failure, not proceed.
        let board = StubBoard;
        let err = eng
            .guarded_transition(&board, None, task_id(), TaskState::Done, "human:a".into(), None)
            .unwrap_err();
        assert!(matches!(err, GateError::Audit(_)));
    }

    // Minimal board stub for the logging-failure path (never reached).
    struct StubBoard;
    impl KanbanBoard for StubBoard {
        fn create(&self, _t: wyrtloom_core::kanban::NewTask) -> Result<TaskId, KanbanError> {
            unreachable!()
        }
        fn transition(
            &self,
            _id: TaskId,
            _to: TaskState,
            _actor: ActorId,
            _reason: Option<String>,
        ) -> Result<(), KanbanError> {
            unreachable!()
        }
        fn claim(&self, _id: TaskId, _w: ActorId) -> Result<(), KanbanError> {
            unreachable!()
        }
        fn get(&self, id: TaskId) -> Result<wyrtloom_core::kanban::Task, KanbanError> {
            Err(KanbanError::NotFound(id))
        }
        fn block(
            &self,
            _id: TaskId,
            _a: ActorId,
            _r: wyrtloom_core::kanban::BlockReason,
        ) -> Result<(), KanbanError> {
            unreachable!()
        }
    }

    // ── CORE INTEGRATION TEST: real SqliteKanbanBoard, real SqliteCallLogger ─
    //
    // Drives a real Kanban transition gated by a token: an ungated attempt is
    // refused, a gated one succeeds, and both events are logged.
    #[test]
    fn integration_gated_transition_against_real_board_and_logger() {
        use plugin_kanban_sqlite::SqliteKanbanBoard;
        use plugin_logger_sqlite::SqliteCallLogger;

        let sec = SecurityModule::new();
        let audit_log = SqliteCallLogger::in_memory().unwrap();
        let eng = GateEngine::new(&sec, &audit_log);

        let board = SqliteKanbanBoard::in_memory().unwrap();

        // Move a task into Running so Running→Done is a legal guarded gate.
        let id = board
            .create(wyrtloom_core::kanban::NewTask {
                title: "ship it".into(),
                actor: "human:owner".into(),
                depends_on: vec![],
            })
            .unwrap();
        board.transition(id, TaskState::Todo, "human:owner".into(), None).unwrap();
        board.transition(id, TaskState::Ready, "human:owner".into(), None).unwrap();
        board.claim(id, "agent:w".into()).unwrap();
        board.transition(id, TaskState::Running, "agent:w".into(), None).unwrap();
        assert_eq!(board.get(id).unwrap().state, TaskState::Running);

        // (a) Ungated transition is REFUSED and leaves state unchanged.
        let err = eng
            .guarded_transition(&board, None, id, TaskState::Done, "human:owner".into(), None)
            .unwrap_err();
        assert!(matches!(err, GateError::TokenRequired));
        assert_eq!(board.get(id).unwrap().state, TaskState::Running);

        // (b) A token for the WRONG actor is refused (HMAC mismatch path).
        let token = eng
            .issue_token(id, TaskState::Running, TaskState::Done, "human:owner".into(), "digest: done criteria")
            .unwrap();
        let wrong = eng
            .guarded_transition(&board, Some(&token), id, TaskState::Done, "human:impostor".into(), None)
            .unwrap_err();
        assert!(matches!(wrong, GateError::InvalidToken));
        assert_eq!(board.get(id).unwrap().state, TaskState::Running);

        // (c) The valid, matching token SUCCEEDS.
        eng.guarded_transition(&board, Some(&token), id, TaskState::Done, "human:owner".into(), Some("approved".into()))
            .unwrap();
        assert_eq!(board.get(id).unwrap().state, TaskState::Done);

        // (d) Every gate decision was logged via the CallLogger (CG-28):
        //     three gate events (refusal, mismatch, success).
        let logs = audit_log.all_logs().unwrap();
        let gate_events: Vec<_> = logs
            .iter()
            .filter(|l| l.provider == GATE_AUDIT_PROVIDER && l.task == id)
            .collect();
        assert_eq!(gate_events.len(), 3, "expected 3 gate audit events");
        assert!(matches!(gate_events[0].outcome, CallOutcome::Failed(_)));
        assert!(matches!(gate_events[1].outcome, CallOutcome::Failed(_)));
        assert!(matches!(gate_events[2].outcome, CallOutcome::Completed));
    }

    // ── Guarded transition with the in-test fake logger (counts events) ──────
    #[test]
    fn guarded_success_emits_single_completed_event() {
        use plugin_kanban_sqlite::SqliteKanbanBoard;
        let sec = SecurityModule::new();
        let log = FakeLogger::default();
        let eng = GateEngine::new(&sec, &log);
        let board = SqliteKanbanBoard::in_memory().unwrap();

        let id = board
            .create(wyrtloom_core::kanban::NewTask {
                title: "t".into(),
                actor: "h".into(),
                depends_on: vec![],
            })
            .unwrap();
        // Backlog→Todo is a legal transition we can gate.
        let token = eng
            .issue_token(id, TaskState::Backlog, TaskState::Todo, "human:a".into(), "d")
            .unwrap();
        eng.guarded_transition(&board, Some(&token), id, TaskState::Todo, "human:a".into(), None)
            .unwrap();
        assert_eq!(log.count(), 1);
        assert!(matches!(log.last().outcome, CallOutcome::Completed));
    }

    // ── Replay guard: a token minted for an earlier state can't be reused ────
    #[test]
    fn stale_token_for_wrong_current_state_is_rejected() {
        use plugin_kanban_sqlite::SqliteKanbanBoard;
        let sec = SecurityModule::new();
        let log = FakeLogger::default();
        let eng = GateEngine::new(&sec, &log);
        let board = SqliteKanbanBoard::in_memory().unwrap();

        let id = board
            .create(wyrtloom_core::kanban::NewTask {
                title: "t".into(),
                actor: "h".into(),
                depends_on: vec![],
            })
            .unwrap();
        // Token says Todo→Ready, but the board is still in Backlog.
        let token = eng
            .issue_token(id, TaskState::Todo, TaskState::Ready, "human:a".into(), "d")
            .unwrap();
        let err = eng
            .guarded_transition(&board, Some(&token), id, TaskState::Ready, "human:a".into(), None)
            .unwrap_err();
        assert!(matches!(err, GateError::StageMismatch { .. }));
        assert_eq!(board.get(id).unwrap().state, TaskState::Backlog);
    }
}
