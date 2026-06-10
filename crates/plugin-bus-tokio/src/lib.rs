/// Tokio broadcast-channel message bus with per-topic channel isolation.
///
/// Security hardening (see CHANGELOG.md):
///   015 – Each topic gets its own broadcast channel so a subscriber to
///         "metrics" cannot receive events published to "security" or any
///         other topic it did not explicitly subscribe to.
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::broadcast;
use wyrtloom_core::bus::{BusError, Event, MessageBus};
use wyrtloom_core::types::Topic;

pub struct TokioMessageBus {
    /// Per-topic senders.  A new channel is lazily created on first publish
    /// or subscribe to a topic.
    channels: Mutex<HashMap<Topic, broadcast::Sender<Event>>>,
    capacity: usize,
}

impl TokioMessageBus {
    pub fn new(capacity: usize) -> Self {
        Self { channels: Mutex::new(HashMap::new()), capacity }
    }

    fn get_or_create_sender(&self, topic: &str) -> broadcast::Sender<Event> {
        let mut map = self.channels.lock().unwrap();
        if let Some(tx) = map.get(topic) {
            tx.clone()
        } else {
            let (tx, _) = broadcast::channel(self.capacity);
            map.insert(topic.to_string(), tx.clone());
            tx
        }
    }
}

impl Default for TokioMessageBus {
    fn default() -> Self { Self::new(1024) }
}

impl MessageBus for TokioMessageBus {
    fn publish(&self, event: Event) -> Result<(), BusError> {
        let tx = self.get_or_create_sender(&event.topic);
        let _ = tx.send(event);
        Ok(())
    }

    fn subscribe(&self, topic: Topic) -> broadcast::Receiver<Event> {
        self.get_or_create_sender(&topic).subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrtloom_core::bus::MessageBus;

    #[tokio::test]
    async fn publish_and_receive_on_same_topic() {
        let bus = TokioMessageBus::default();
        let mut rx = bus.subscribe("t".into());

        bus.publish(Event::new("t", serde_json::json!({"x": 1}))).unwrap();

        let e = rx.recv().await.unwrap();
        assert_eq!(e.topic, "t");
        assert_eq!(e.payload["x"], 1);
    }

    #[tokio::test]
    async fn multiple_subscribers_receive_event() {
        let bus = TokioMessageBus::default();
        let mut rx1 = bus.subscribe("t".into());
        let mut rx2 = bus.subscribe("t".into());

        bus.publish(Event::new("t", serde_json::json!({}))).unwrap();

        assert!(rx1.recv().await.is_ok());
        assert!(rx2.recv().await.is_ok());
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_ok() {
        let bus = TokioMessageBus::default();
        assert!(bus.publish(Event::new("empty", serde_json::json!({}))).is_ok());
    }

    // 015 — topic isolation: subscriber to "a" must not receive events for "b"
    #[tokio::test]
    async fn subscriber_does_not_receive_other_topics() {
        let bus = TokioMessageBus::default();
        let mut rx_a = bus.subscribe("topic-a".into());

        bus.publish(Event::new("topic-b", serde_json::json!({"secret": true}))).unwrap();

        // No event should be available on topic-a's receiver.
        assert!(rx_a.try_recv().is_err());
    }

    #[tokio::test]
    async fn each_topic_is_isolated() {
        let bus = TokioMessageBus::default();
        let mut rx_metrics  = bus.subscribe("metrics".into());
        let mut rx_security = bus.subscribe("security".into());

        bus.publish(Event::new("security", serde_json::json!({"alert": "injection"}))).unwrap();

        // metrics subscriber must not see the security event.
        assert!(rx_metrics.try_recv().is_err());
        // security subscriber must see it.
        assert!(rx_security.try_recv().is_ok());
    }
}
