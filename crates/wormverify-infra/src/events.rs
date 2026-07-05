//! A broadcast-based [`EventSink`] enabling GraphQL subscriptions and fan-out.

use async_trait::async_trait;
use tokio::sync::broadcast;

use wormverify_core::domain::DomainEvent;
use wormverify_core::ports::EventSink;

/// Fans domain events out to any number of subscribers via a broadcast channel.
pub struct BroadcastEventSink {
    sender: broadcast::Sender<DomainEvent>,
}

impl BroadcastEventSink {
    /// Creates a sink with the given channel capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Subscribes to the event stream.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<DomainEvent> {
        self.sender.subscribe()
    }
}

impl Default for BroadcastEventSink {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[async_trait]
impl EventSink for BroadcastEventSink {
    async fn publish(&self, event: DomainEvent) {
        // A send error only means there are no active subscribers; that is fine.
        let _ = self.sender.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormverify_core::domain::MessageId;

    #[tokio::test]
    async fn subscribers_receive_published_events() {
        let sink = BroadcastEventSink::new(8);
        let mut rx = sink.subscribe();
        let id = MessageId([1u8; 32]);
        sink.publish(DomainEvent::MessageObserved { id }).await;
        let received = rx.recv().await.unwrap();
        assert_eq!(received, DomainEvent::MessageObserved { id });
    }

    #[tokio::test]
    async fn publish_without_subscribers_is_ok() {
        let sink = BroadcastEventSink::new(8);
        sink.publish(DomainEvent::MessageObserved {
            id: MessageId([0u8; 32]),
        })
        .await;
    }
}
