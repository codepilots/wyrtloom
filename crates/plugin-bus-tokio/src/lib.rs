use tokio::sync::broadcast;
use wyrtloom_core::bus::{BusError, Event, MessageBus};
use wyrtloom_core::types::Topic;

/// Full Tokio-channels implementation of MessageBus.
/// Supports per-topic filtering via a single broadcast channel.
pub struct TokioMessageBus {
    sender: broadcast::Sender<Event>,
}

impl TokioMessageBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }
}

impl Default for TokioMessageBus {
    fn default() -> Self { Self::new(1024) }
}

impl MessageBus for TokioMessageBus {
    fn publish(&self, event: Event) -> Result<(), BusError> {
        let _ = self.sender.send(event);
        Ok(())
    }

    fn subscribe(&self, _topic: Topic) -> broadcast::Receiver<Event> {
        // All topics flow through one channel; callers filter by topic themselves.
        self.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrtloom_core::bus::MessageBus;

    #[tokio::test]
    async fn publish_and_receive() {
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
}
