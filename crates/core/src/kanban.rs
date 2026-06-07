use crate::types::{ActorId, TaskId, Timestamp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Backlog,
    Todo,
    Ready,
    Running,
    Blocked,
    Done,
    Archived,
}

impl std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockReason {
    pub reason: String,
    pub blocked_by: BlockedBy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockedBy {
    Human(ActorId),
    Dependency(TaskId),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub from: TaskState,
    pub to: TaskState,
    pub actor: ActorId,
    pub at: Timestamp,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    pub title: String,
    pub state: TaskState,
    pub actor: Option<ActorId>,
    pub depends_on: Vec<TaskId>,
    pub block_reason: Option<BlockReason>,
    pub history: Vec<StateChange>,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone)]
pub struct NewTask {
    pub title: String,
    pub actor: ActorId,
    pub depends_on: Vec<TaskId>,
}

#[derive(Error, Debug)]
pub enum KanbanError {
    #[error("illegal transition from {from:?} to {to:?}")]
    IllegalTransition { from: TaskState, to: TaskState },
    #[error("task dependencies are not all done")]
    DependenciesNotDone,
    #[error("task is already claimed by another worker")]
    AlreadyClaimed,
    #[error("a block reason is required for this transition")]
    BlockReasonRequired,
    #[error("task not found: {0}")]
    NotFound(TaskId),
    #[error("storage error: {0}")]
    Storage(String),
}

/// Legal transitions (from, to).
pub fn is_legal_transition(from: &TaskState, to: &TaskState) -> bool {
    matches!(
        (from, to),
        (TaskState::Backlog,  TaskState::Todo)
        | (TaskState::Todo,   TaskState::Ready)
        | (TaskState::Todo,   TaskState::Backlog)
        | (TaskState::Ready,  TaskState::Running)
        | (TaskState::Ready,  TaskState::Backlog)
        | (TaskState::Running, TaskState::Done)
        | (TaskState::Running, TaskState::Blocked)
        | (TaskState::Running, TaskState::Todo)
        | (TaskState::Blocked, TaskState::Running)
        | (TaskState::Blocked, TaskState::Todo)
        | (TaskState::Blocked, TaskState::Done)
        | (TaskState::Done,   TaskState::Archived)
    )
}

/// Interface contract — storage implementations must satisfy this.
pub trait KanbanBoard: Send + Sync {
    fn create(&self, task: NewTask) -> Result<TaskId, KanbanError>;
    fn transition(
        &self,
        id: TaskId,
        to: TaskState,
        actor: ActorId,
        reason: Option<String>,
    ) -> Result<(), KanbanError>;
    fn claim(&self, id: TaskId, worker: ActorId) -> Result<(), KanbanError>;
    fn get(&self, id: TaskId) -> Result<Task, KanbanError>;
    fn block(
        &self,
        id: TaskId,
        actor: ActorId,
        reason: BlockReason,
    ) -> Result<(), KanbanError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_legal(from: TaskState, to: TaskState, expect: bool) {
        assert_eq!(
            is_legal_transition(&from, &to),
            expect,
            "transition {:?} → {:?} expected legal={}",
            from, to, expect
        );
    }

    #[test]
    fn legal_transitions_pass() {
        check_legal(TaskState::Backlog,  TaskState::Todo,     true);
        check_legal(TaskState::Todo,     TaskState::Ready,    true);
        check_legal(TaskState::Ready,    TaskState::Running,  true);
        check_legal(TaskState::Running,  TaskState::Done,     true);
        check_legal(TaskState::Running,  TaskState::Blocked,  true);
        check_legal(TaskState::Blocked,  TaskState::Running,  true);
        check_legal(TaskState::Done,     TaskState::Archived, true);
    }

    #[test]
    fn illegal_transitions_fail() {
        check_legal(TaskState::Backlog, TaskState::Running,  false);
        check_legal(TaskState::Done,    TaskState::Running,  false);
        check_legal(TaskState::Done,    TaskState::Todo,     false);
        check_legal(TaskState::Archived, TaskState::Todo,   false);
    }

    #[test]
    fn task_state_display() {
        assert_eq!(TaskState::Running.to_string(), "Running");
    }
}
