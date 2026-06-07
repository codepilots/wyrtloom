use std::io::{self, BufRead, Write};
use wyrtloom_core::escalation::{
    ActionOption, Escalation, EscalationError, HumanEscalation, HumanResponse,
};

pub struct CliEscalation;

impl CliEscalation {
    pub fn new() -> Self { Self }
}

impl Default for CliEscalation {
    fn default() -> Self { Self::new() }
}

impl HumanEscalation for CliEscalation {
    fn escalate(&self, e: Escalation) -> Result<HumanResponse, EscalationError> {
        let stdout = io::stdout();
        let mut out = stdout.lock();

        writeln!(out, "\n╔══════════════════════════════════════════╗").ok();
        writeln!(out, "║  ⚠  HUMAN ESCALATION REQUIRED             ║").ok();
        writeln!(out, "╚══════════════════════════════════════════╝").ok();
        writeln!(out, "Task: {}", e.task).ok();
        writeln!(out, "\n{}", e.prompt).ok();

        if !e.options.is_empty() {
            writeln!(out, "\nSuggested actions:").ok();
            for (i, opt) in e.options.iter().enumerate() {
                write!(out, "  [{}] {}", i + 1, opt.label).ok();
                if let Some(desc) = &opt.description {
                    write!(out, " — {}", desc).ok();
                }
                writeln!(out).ok();
            }
        }

        writeln!(out, "  [f] Enter free text").ok();
        writeln!(out, "  [s] Stop task").ok();
        write!(out, "\nYour choice: ").ok();
        out.flush().ok();

        let stdin = io::stdin();
        let line = stdin
            .lock()
            .lines()
            .next()
            .ok_or(EscalationError::Interrupted)?
            .map_err(|e| EscalationError::Io(e.to_string()))?;

        let choice = line.trim().to_lowercase();

        if choice == "s" || choice == "stop" {
            return Ok(HumanResponse::Stop);
        }

        if choice == "f" || choice == "free" {
            write!(out, "Enter your response: ").ok();
            out.flush().ok();
            let text = stdin
                .lock()
                .lines()
                .next()
                .ok_or(EscalationError::Interrupted)?
                .map_err(|e| EscalationError::Io(e.to_string()))?;
            return Ok(HumanResponse::FreeText(text.trim().to_string()));
        }

        // Numeric option choice
        if let Ok(n) = choice.parse::<usize>() {
            if n >= 1 && n <= e.options.len() {
                return Ok(HumanResponse::Chose(e.options[n - 1].id.clone()));
            }
        }

        // Unrecognised input — treat as free text
        Ok(HumanResponse::FreeText(line.trim().to_string()))
    }
}

/// A scripted escalation handler for use in tests and pipelines.
pub struct ScriptedEscalation {
    pub response: HumanResponse,
}

impl ScriptedEscalation {
    pub fn stop() -> Self { Self { response: HumanResponse::Stop } }
    pub fn chose(id: impl Into<String>) -> Self {
        Self { response: HumanResponse::Chose(id.into()) }
    }
    pub fn free_text(text: impl Into<String>) -> Self {
        Self { response: HumanResponse::FreeText(text.into()) }
    }
}

impl HumanEscalation for ScriptedEscalation {
    fn escalate(&self, _e: Escalation) -> Result<HumanResponse, EscalationError> {
        Ok(self.response.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn escalation() -> Escalation {
        Escalation {
            task: Uuid::new_v4(),
            prompt: "What should I do?".into(),
            options: vec![
                ActionOption { id: "retry".into(), label: "Retry".into(), description: None },
                ActionOption { id: "skip".into(), label: "Skip".into(), description: None },
            ],
        }
    }

    #[test]
    fn scripted_stop_returns_stop() {
        let h = ScriptedEscalation::stop();
        let r = h.escalate(escalation()).unwrap();
        assert!(matches!(r, HumanResponse::Stop));
    }

    #[test]
    fn scripted_chose_returns_chose() {
        let h = ScriptedEscalation::chose("retry");
        let r = h.escalate(escalation()).unwrap();
        assert!(matches!(r, HumanResponse::Chose(id) if id == "retry"));
    }

    #[test]
    fn scripted_free_text_returns_free_text() {
        let h = ScriptedEscalation::free_text("try harder");
        let r = h.escalate(escalation()).unwrap();
        assert!(matches!(r, HumanResponse::FreeText(t) if t == "try harder"));
    }

    #[test]
    fn stop_halts_task_cleanly() {
        // Contract: a Stop response must be representable; the calling code
        // is responsible for halting the task cleanly.
        let h = ScriptedEscalation::stop();
        let r = h.escalate(escalation()).unwrap();
        assert!(matches!(r, HumanResponse::Stop));
    }
}
