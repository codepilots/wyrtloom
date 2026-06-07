use rusqlite::{params, Connection};
use std::sync::Mutex;
use uuid::Uuid;
use wyrtloom_core::kanban::{
    BlockReason, BlockedBy, is_legal_transition, KanbanBoard, KanbanError, NewTask, StateChange,
    Task, TaskState,
};
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

pub struct SqliteKanbanBoard {
    conn: Mutex<Connection>,
}

impl SqliteKanbanBoard {
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        let board = Self { conn: Mutex::new(conn) };
        board.init_schema()?;
        Ok(board)
    }

    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tasks (
                id           TEXT PRIMARY KEY,
                title        TEXT NOT NULL,
                state        TEXT NOT NULL,
                actor        TEXT,
                depends_on   TEXT NOT NULL DEFAULT '[]',
                block_reason TEXT,
                created_at   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS history (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id   TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state   TEXT NOT NULL,
                actor      TEXT NOT NULL,
                at         TEXT NOT NULL,
                reason     TEXT
            );",
        )
    }

    fn state_from_str(s: &str) -> Option<TaskState> {
        match s {
            "Backlog"  => Some(TaskState::Backlog),
            "Todo"     => Some(TaskState::Todo),
            "Ready"    => Some(TaskState::Ready),
            "Running"  => Some(TaskState::Running),
            "Blocked"  => Some(TaskState::Blocked),
            "Done"     => Some(TaskState::Done),
            "Archived" => Some(TaskState::Archived),
            _          => None,
        }
    }
}

impl KanbanBoard for SqliteKanbanBoard {
    fn create(&self, task: NewTask) -> Result<TaskId, KanbanError> {
        let id = Uuid::new_v4();
        let conn = self.conn.lock().unwrap();
        let depends_json =
            serde_json::to_string(&task.depends_on).map_err(|e| KanbanError::Storage(e.to_string()))?;
        conn.execute(
            "INSERT INTO tasks (id, title, state, actor, depends_on, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id.to_string(),
                task.title,
                "Backlog",
                task.actor,
                depends_json,
                Timestamp::now().0.to_rfc3339(),
            ],
        )
        .map_err(|e| KanbanError::Storage(e.to_string()))?;
        Ok(id)
    }

    fn transition(
        &self,
        id: TaskId,
        to: TaskState,
        actor: ActorId,
        reason: Option<String>,
    ) -> Result<(), KanbanError> {
        let task = self.get(id)?;

        if !is_legal_transition(&task.state, &to) {
            return Err(KanbanError::IllegalTransition { from: task.state, to });
        }

        // todo→ready: all dependencies must be done
        if to == TaskState::Ready && !task.depends_on.is_empty() {
            for dep_id in &task.depends_on {
                let dep = self.get(*dep_id)?;
                if dep.state != TaskState::Done {
                    return Err(KanbanError::DependenciesNotDone);
                }
            }
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE tasks SET state = ?1, actor = NULL WHERE id = ?2",
            params![format!("{:?}", to), id.to_string()],
        )
        .map_err(|e| KanbanError::Storage(e.to_string()))?;

        conn.execute(
            "INSERT INTO history (task_id, from_state, to_state, actor, at, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id.to_string(),
                format!("{:?}", task.state),
                format!("{:?}", to),
                actor,
                Timestamp::now().0.to_rfc3339(),
                reason,
            ],
        )
        .map_err(|e| KanbanError::Storage(e.to_string()))?;
        Ok(())
    }

    fn claim(&self, id: TaskId, worker: ActorId) -> Result<(), KanbanError> {
        let conn = self.conn.lock().unwrap();
        // Atomic: only update if actor IS NULL (not already claimed)
        let rows = conn
            .execute(
                "UPDATE tasks SET actor = ?1 WHERE id = ?2 AND actor IS NULL AND state = 'Ready'",
                params![worker, id.to_string()],
            )
            .map_err(|e| KanbanError::Storage(e.to_string()))?;
        if rows == 0 {
            return Err(KanbanError::AlreadyClaimed);
        }
        Ok(())
    }

    fn get(&self, id: TaskId) -> Result<Task, KanbanError> {
        let conn = self.conn.lock().unwrap();
        let (title, state_str, actor, depends_json, block_json, created_at_str): (
            String, String, Option<String>, String, Option<String>, String,
        ) = conn
            .query_row(
                "SELECT title, state, actor, depends_on, block_reason, created_at
                 FROM tasks WHERE id = ?1",
                params![id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => KanbanError::NotFound(id),
                other => KanbanError::Storage(other.to_string()),
            })?;

        let state = Self::state_from_str(&state_str)
            .ok_or_else(|| KanbanError::Storage(format!("unknown state: {}", state_str)))?;

        let depends_on: Vec<TaskId> = serde_json::from_str(&depends_json)
            .map_err(|e| KanbanError::Storage(e.to_string()))?;

        let block_reason: Option<BlockReason> = block_json
            .as_deref()
            .map(|s| serde_json::from_str(s))
            .transpose()
            .map_err(|e| KanbanError::Storage(e.to_string()))?;

        let history = {
            let mut stmt = conn
                .prepare(
                    "SELECT from_state, to_state, actor, at, reason
                     FROM history WHERE task_id = ?1 ORDER BY id",
                )
                .map_err(|e| KanbanError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(params![id.to_string()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                })
                .map_err(|e| KanbanError::Storage(e.to_string()))?;
            let mut history = vec![];
            for row in rows {
                let (from_s, to_s, actor, at_s, reason) =
                    row.map_err(|e| KanbanError::Storage(e.to_string()))?;
                let from =
                    Self::state_from_str(&from_s).unwrap_or(TaskState::Backlog);
                let to = Self::state_from_str(&to_s).unwrap_or(TaskState::Backlog);
                let at = chrono::DateTime::parse_from_rfc3339(&at_s)
                    .map(|dt| Timestamp(dt.with_timezone(&chrono::Utc)))
                    .unwrap_or_else(|_| Timestamp::now());
                history.push(StateChange { from, to, actor, at, reason });
            }
            history
        };

        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| Timestamp(dt.with_timezone(&chrono::Utc)))
            .unwrap_or_else(|_| Timestamp::now());

        Ok(Task { id, title, state, actor, depends_on, block_reason, history, created_at })
    }

    fn block(
        &self,
        id: TaskId,
        actor: ActorId,
        reason: BlockReason,
    ) -> Result<(), KanbanError> {
        let task = self.get(id)?;
        if !is_legal_transition(&task.state, &TaskState::Blocked) {
            return Err(KanbanError::IllegalTransition {
                from: task.state,
                to: TaskState::Blocked,
            });
        }
        let reason_json =
            serde_json::to_string(&reason).map_err(|e| KanbanError::Storage(e.to_string()))?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE tasks SET state = 'Blocked', block_reason = ?1 WHERE id = ?2",
            params![reason_json, id.to_string()],
        )
        .map_err(|e| KanbanError::Storage(e.to_string()))?;
        conn.execute(
            "INSERT INTO history (task_id, from_state, to_state, actor, at, reason)
             VALUES (?1, ?2, 'Blocked', ?3, ?4, ?5)",
            params![
                id.to_string(),
                format!("{:?}", task.state),
                actor,
                Timestamp::now().0.to_rfc3339(),
                reason.reason,
            ],
        )
        .map_err(|e| KanbanError::Storage(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrtloom_core::kanban::KanbanError;

    fn board() -> SqliteKanbanBoard {
        SqliteKanbanBoard::in_memory().unwrap()
    }

    fn new_task(title: &str) -> NewTask {
        NewTask { title: title.into(), actor: "human:test".into(), depends_on: vec![] }
    }

    #[test]
    fn create_and_retrieve_task() {
        let b = board();
        let id = b.create(new_task("hello")).unwrap();
        let task = b.get(id).unwrap();
        assert_eq!(task.title, "hello");
        assert_eq!(task.state, TaskState::Backlog);
    }

    #[test]
    fn legal_transition_succeeds() {
        let b = board();
        let id = b.create(new_task("t")).unwrap();
        b.transition(id, TaskState::Todo, "agent:x".into(), None).unwrap();
        assert_eq!(b.get(id).unwrap().state, TaskState::Todo);
    }

    #[test]
    fn illegal_transition_is_rejected() {
        let b = board();
        let id = b.create(new_task("t")).unwrap();
        let err = b.transition(id, TaskState::Running, "agent:x".into(), None).unwrap_err();
        assert!(matches!(err, KanbanError::IllegalTransition { .. }));
    }

    #[test]
    fn claim_is_atomic() {
        let b = board();
        let id = b.create(new_task("t")).unwrap();
        b.transition(id, TaskState::Todo, "agent:x".into(), None).unwrap();
        b.transition(id, TaskState::Ready, "agent:x".into(), None).unwrap();
        b.claim(id, "agent:x".into()).unwrap();
        let err = b.claim(id, "agent:y".into()).unwrap_err();
        assert!(matches!(err, KanbanError::AlreadyClaimed));
    }

    #[test]
    fn history_is_append_only_audit() {
        let b = board();
        let id = b.create(new_task("t")).unwrap();
        b.transition(id, TaskState::Todo, "human:alice".into(), Some("init".into())).unwrap();
        let task = b.get(id).unwrap();
        assert_eq!(task.history.len(), 1);
        assert_eq!(task.history[0].actor, "human:alice");
    }

    #[test]
    fn block_records_reason() {
        let b = board();
        let id = b.create(new_task("t")).unwrap();
        b.transition(id, TaskState::Todo, "a".into(), None).unwrap();
        b.transition(id, TaskState::Ready, "a".into(), None).unwrap();
        b.claim(id, "agent:w".into()).unwrap();
        // Transition to Running first
        b.transition(id, TaskState::Running, "agent:w".into(), None).unwrap();
        b.block(
            id,
            "agent:w".into(),
            BlockReason {
                reason: "need human input".into(),
                blocked_by: BlockedBy::Human("human:alice".into()),
            },
        )
        .unwrap();
        let task = b.get(id).unwrap();
        assert_eq!(task.state, TaskState::Blocked);
        assert!(task.block_reason.is_some());
    }

    #[test]
    fn not_found_returns_typed_error() {
        let b = board();
        let err = b.get(Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, KanbanError::NotFound(_)));
    }

    #[test]
    fn todo_to_ready_blocked_by_unfinished_dependency() {
        let b = board();
        let dep_id = b.create(new_task("dep")).unwrap();
        let task_id = b
            .create(NewTask {
                title: "main".into(),
                actor: "h".into(),
                depends_on: vec![dep_id],
            })
            .unwrap();
        b.transition(task_id, TaskState::Todo, "a".into(), None).unwrap();
        let err = b
            .transition(task_id, TaskState::Ready, "a".into(), None)
            .unwrap_err();
        assert!(matches!(err, KanbanError::DependenciesNotDone));
    }
}
