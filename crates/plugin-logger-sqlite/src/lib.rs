/// SQLite call-logger plugin.
///
/// Security hardening (see CHANGELOG.md):
///   010 – open() validates the path to prevent traversal.
///   011 – Unknown outcome strings return a Storage error rather than
///         silently mapping to Completed.
use rusqlite::{params, Connection};
use std::sync::Mutex;
use wyrtloom_core::logger::{CallLog, CallLogger, CallOutcome, LogError};
use wyrtloom_core::storage::validate_db_path;
use wyrtloom_core::types::Timestamp;

pub struct SqliteCallLogger {
    conn: Mutex<Connection>,
}

impl SqliteCallLogger {
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            validate_db_path(path).map_err(|e| {
                rusqlite::Error::InvalidPath(std::path::PathBuf::from(e))
            })?;
            Connection::open(path)?
        };
        let logger = Self { conn: Mutex::new(conn) };
        logger.init_schema()?;
        Ok(logger)
    }

    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        self.conn.lock().unwrap().execute_batch(
            "CREATE TABLE IF NOT EXISTS call_logs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id       TEXT NOT NULL,
                profile       TEXT NOT NULL,
                provider      TEXT NOT NULL,
                model         TEXT NOT NULL,
                input_tokens  INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cost_microdollars INTEGER,
                cost_currency TEXT,
                outcome       TEXT NOT NULL,
                outcome_detail TEXT,
                at            TEXT NOT NULL
            );",
        )
    }

    pub fn all_logs(&self) -> Result<Vec<CallLog>, LogError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT task_id, profile, provider, model,
                        input_tokens, output_tokens,
                        cost_microdollars, cost_currency,
                        outcome, outcome_detail, at
                 FROM call_logs ORDER BY id",
            )
            .map_err(|_| LogError::Storage("prepare failed".into()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, String>(10)?,
                ))
            })
            .map_err(|_| LogError::Storage("query failed".into()))?;

        let mut logs = vec![];
        for row in rows {
            let (task_id_str, profile, provider, model,
                 input_tokens, output_tokens,
                 cost_microdollars, cost_currency,
                 outcome_str, outcome_detail, at_str) =
                row.map_err(|_| LogError::Storage("row read failed".into()))?;

            let task = task_id_str
                .parse()
                .map_err(|_| LogError::Storage("integrity error: malformed task_id".into()))?;

            let cost = cost_microdollars.zip(cost_currency).map(|(amt, cur)| {
                wyrtloom_core::types::Money { amount_microdollars: amt, currency: cur }
            });

            // 011 — unknown outcome is an integrity violation, not silently Completed.
            let outcome = match outcome_str.as_str() {
                "Completed" => CallOutcome::Completed,
                "Failed"    => CallOutcome::Failed(outcome_detail.unwrap_or_default()),
                "Partial"   => CallOutcome::Partial(outcome_detail.unwrap_or_default()),
                other => return Err(LogError::Storage(
                    format!("integrity error: unknown outcome '{}'", other)
                )),
            };

            // 011 — invalid timestamp is an integrity error.
            let at = chrono::DateTime::parse_from_rfc3339(&at_str)
                .map(|dt| Timestamp(dt.with_timezone(&chrono::Utc)))
                .map_err(|_| LogError::Storage(format!("integrity error: malformed timestamp")))?;

            logs.push(CallLog {
                task,
                profile,
                provider,
                model,
                usage: wyrtloom_core::provider::Usage { input_tokens, output_tokens, cost },
                outcome,
                at,
            });
        }
        Ok(logs)
    }
}


impl CallLogger for SqliteCallLogger {
    fn record(&self, entry: CallLog) -> Result<(), LogError> {
        let (outcome_str, outcome_detail) = match &entry.outcome {
            CallOutcome::Completed  => ("Completed", None),
            CallOutcome::Failed(s)  => ("Failed", Some(s.clone())),
            CallOutcome::Partial(s) => ("Partial", Some(s.clone())),
        };

        let (cost_microdollars, cost_currency) = match &entry.usage.cost {
            Some(m) => (Some(m.amount_microdollars), Some(m.currency.clone())),
            None    => (None, None),
        };

        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO call_logs
                 (task_id, profile, provider, model,
                  input_tokens, output_tokens,
                  cost_microdollars, cost_currency,
                  outcome, outcome_detail, at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    entry.task.to_string(),
                    entry.profile,
                    entry.provider,
                    entry.model,
                    entry.usage.input_tokens,
                    entry.usage.output_tokens,
                    cost_microdollars,
                    cost_currency,
                    outcome_str,
                    outcome_detail,
                    entry.at.0.to_rfc3339(),
                ],
            )
            .map_err(|_| LogError::Storage("insert failed".into()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrtloom_core::logger::{CallLog, CallOutcome};
    use wyrtloom_core::provider::Usage;
    use wyrtloom_core::types::Timestamp;
    use uuid::Uuid;

    fn logger() -> SqliteCallLogger {
        SqliteCallLogger::in_memory().unwrap()
    }

    fn sample(outcome: CallOutcome) -> CallLog {
        CallLog {
            task: Uuid::new_v4(),
            profile: "default".into(),
            provider: "ollama".into(),
            model: "llama3.2".into(),
            usage: Usage { input_tokens: 10, output_tokens: 20, cost: None },
            outcome,
            at: Timestamp::now(),
        }
    }

    #[test]
    fn completed_call_is_recorded() {
        let l = logger();
        l.record(sample(CallOutcome::Completed)).unwrap();
        let logs = l.all_logs().unwrap();
        assert_eq!(logs.len(), 1);
        assert!(matches!(logs[0].outcome, CallOutcome::Completed));
    }

    #[test]
    fn failed_call_is_not_dropped() {
        let l = logger();
        l.record(sample(CallOutcome::Failed("timeout".into()))).unwrap();
        let logs = l.all_logs().unwrap();
        assert!(matches!(&logs[0].outcome, CallOutcome::Failed(s) if s == "timeout"));
    }

    #[test]
    fn partial_call_is_recorded() {
        let l = logger();
        l.record(sample(CallOutcome::Partial("truncated".into()))).unwrap();
        let logs = l.all_logs().unwrap();
        assert!(matches!(&logs[0].outcome, CallOutcome::Partial(_)));
    }

    #[test]
    fn cost_nullable_stored_correctly() {
        let l = logger();
        let mut entry = sample(CallOutcome::Completed);
        entry.usage.cost = None;
        l.record(entry).unwrap();
        let logs = l.all_logs().unwrap();
        assert!(logs[0].usage.cost.is_none());
    }

    #[test]
    fn all_required_fields_are_stored() {
        let l = logger();
        let entry = sample(CallOutcome::Completed);
        let task_id = entry.task;
        l.record(entry).unwrap();
        let logs = l.all_logs().unwrap();
        assert_eq!(logs[0].task, task_id);
        assert_eq!(logs[0].provider, "ollama");
        assert_eq!(logs[0].model, "llama3.2");
    }

    // 010 — path traversal is rejected
    #[test]
    fn path_with_parent_traversal_is_rejected() {
        let result = SqliteCallLogger::open("../etc/sensitive.db");
        assert!(result.is_err());
    }
}
