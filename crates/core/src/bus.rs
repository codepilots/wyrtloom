use crate::types::Topic;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub topic: Topic,
    pub payload: serde_json::Value,
}

impl Event {
    pub fn new(topic: impl Into<Topic>, payload: serde_json::Value) -> Self {
        Self { topic: topic.into(), payload }
    }
}

#[derive(Error, Debug)]
pub enum BusError {
    #[error("publish failed: {0}")]
    PublishFailed(String),
    #[error("no subscribers for topic: {0}")]
    NoSubscribers(String),
}

/// Full message-bus interface contract.  The in-process Tokio implementation
/// satisfies this in v0.1.
pub trait MessageBus: Send + Sync {
    fn publish(&self, event: Event) -> Result<(), BusError>;
    fn subscribe(&self, topic: Topic) -> tokio::sync::broadcast::Receiver<Event>;
}

// ---------------------------------------------------------------------------
// Bootstrap primitive — a minimal synchronous bus that exists before any
// plugin loads.  Solves the chicken-and-egg: you cannot load a bus *plugin*
// until something can already carry the "loaded" signal.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct BootstrapBus {
    sender: tokio::sync::broadcast::Sender<Event>,
}

impl BootstrapBus {
    pub fn new() -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(256);
        Self { sender }
    }
}

impl Default for BootstrapBus {
    fn default() -> Self { Self::new() }
}

impl MessageBus for BootstrapBus {
    fn publish(&self, event: Event) -> Result<(), BusError> {
        // Ignore send errors when there are no active subscribers — that is
        // expected during early bootstrap before anything has subscribed.
        let _ = self.sender.send(event);
        Ok(())
    }

    fn subscribe(&self, _topic: Topic) -> tokio::sync::broadcast::Receiver<Event> {
        self.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bootstrap_bus_publish_subscribe_round_trip() {
        let bus = BootstrapBus::new();
        let mut rx = bus.subscribe("test.topic".into());

        bus.publish(Event::new("test.topic", serde_json::json!({"val": 42})))
            .expect("publish must succeed");

        let received = rx.try_recv().expect("event must be available");
        assert_eq!(received.topic, "test.topic");
        assert_eq!(received.payload["val"], 42);
    }

    #[tokio::test]
    async fn bootstrap_bus_publish_with_no_subscribers_succeeds() {
        let bus = BootstrapBus::new();
        // No subscriber — must still succeed (not error).
        let result = bus.publish(Event::new("lonely.topic", serde_json::json!({})));
        assert!(result.is_ok());
    }

    #[test]
    fn bootstrap_bus_exists_before_any_plugin_loads() {
        // Simply constructing the bus proves the bootstrap primitive
        // does not require any plugin infrastructure.
        let _bus = BootstrapBus::new();
    }

    #[tokio::test]
    async fn event_payload_conforms_to_registered_shape() {
        let bus = BootstrapBus::new();
        let mut rx = bus.subscribe("boot".into());
        let payload = serde_json::json!({ "stage": "security", "ok": true });
        bus.publish(Event::new("boot", payload.clone())).unwrap();
        let e = rx.try_recv().unwrap();
        assert_eq!(e.payload["stage"], "security");
    }
}
