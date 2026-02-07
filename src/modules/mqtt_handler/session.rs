//! MQTT session management.
//!
//! This module handles MQTT client sessions, including:
//! - Session state persistence
//! - Subscription management
//! - QoS message tracking
//! - Will message handling

use crate::modules::mqtt_handler::config::ProtocolVersion;
use crate::modules::mqtt_handler::packet::{Properties, Publish, QoS};
use crate::modules::mqtt_handler::topic::TopicFilter;
use bytes::Bytes;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// A unique session identifier.
pub type SessionId = String;

/// Client session state.
#[derive(Debug)]
pub struct Session {
    /// Client identifier.
    pub client_id: String,
    /// Protocol version.
    pub protocol_version: ProtocolVersion,
    /// Whether this is a clean session.
    pub clean_session: bool,
    /// Session expiry interval (MQTT 5.0).
    pub expiry_interval: Duration,
    /// Keep-alive interval.
    pub keep_alive: Duration,
    /// When the session was created.
    pub created_at: Instant,
    /// When the client last sent a message.
    pub last_activity: Instant,
    /// Subscriptions with their QoS levels.
    pub subscriptions: HashMap<String, SubscriptionState>,
    /// Pending outbound messages (QoS 1/2).
    pub pending_outbound: VecDeque<PendingMessage>,
    /// Pending inbound messages (QoS 2).
    pub pending_inbound: HashMap<u16, InboundMessage>,
    /// Next packet identifier.
    packet_id_counter: AtomicU16,
    /// Will message.
    pub will: Option<WillMessage>,
    /// Maximum inflight messages.
    pub receive_maximum: u16,
    /// Currently inflight message count.
    pub inflight_count: u16,
    /// Properties from CONNECT.
    pub properties: Properties,
}

impl Session {
    /// Create a new session.
    pub fn new(client_id: String, protocol_version: ProtocolVersion) -> Self {
        Self {
            client_id,
            protocol_version,
            clean_session: true,
            expiry_interval: Duration::ZERO,
            keep_alive: Duration::from_secs(60),
            created_at: Instant::now(),
            last_activity: Instant::now(),
            subscriptions: HashMap::new(),
            pending_outbound: VecDeque::new(),
            pending_inbound: HashMap::new(),
            packet_id_counter: AtomicU16::new(1),
            will: None,
            receive_maximum: 65535,
            inflight_count: 0,
            properties: Properties::new(),
        }
    }

    /// Get the next packet identifier.
    pub fn next_packet_id(&self) -> u16 {
        loop {
            let id = self.packet_id_counter.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    /// Update last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        if self.clean_session && self.expiry_interval.is_zero() {
            return false; // Active clean session
        }

        self.last_activity.elapsed() > self.expiry_interval
    }

    /// Add a subscription.
    pub fn subscribe(&mut self, filter: String, qos: QoS, options: SubscriptionOptions) {
        self.subscriptions.insert(
            filter,
            SubscriptionState {
                qos,
                options,
                subscription_id: None,
            },
        );
    }

    /// Remove a subscription.
    pub fn unsubscribe(&mut self, filter: &str) -> bool {
        self.subscriptions.remove(filter).is_some()
    }

    /// Queue an outbound message.
    pub fn queue_outbound(&mut self, message: PendingMessage) {
        self.pending_outbound.push_back(message);
    }

    /// Get the next pending outbound message.
    pub fn next_outbound(&mut self) -> Option<PendingMessage> {
        if self.inflight_count >= self.receive_maximum {
            return None;
        }
        self.pending_outbound.pop_front()
    }

    /// Record an inbound QoS 2 message.
    pub fn record_inbound(&mut self, packet_id: u16, publish: Publish) {
        self.pending_inbound.insert(
            packet_id,
            InboundMessage {
                publish,
                state: QoS2State::Received,
                timestamp: Instant::now(),
            },
        );
    }

    /// Complete an inbound QoS 2 message (PUBCOMP received).
    pub fn complete_inbound(&mut self, packet_id: u16) -> Option<InboundMessage> {
        self.pending_inbound.remove(&packet_id)
    }

    /// Check if we have a pending inbound message.
    pub fn has_inbound(&self, packet_id: u16) -> bool {
        self.pending_inbound.contains_key(&packet_id)
    }

    /// Clear all pending messages (for clean session).
    pub fn clear_pending(&mut self) {
        self.pending_outbound.clear();
        self.pending_inbound.clear();
        self.inflight_count = 0;
    }
}

/// Subscription state.
#[derive(Debug, Clone)]
pub struct SubscriptionState {
    /// Maximum QoS for this subscription.
    pub qos: QoS,
    /// Subscription options.
    pub options: SubscriptionOptions,
    /// Subscription identifier (MQTT 5.0).
    pub subscription_id: Option<u32>,
}

/// Subscription options.
#[derive(Debug, Clone, Default)]
pub struct SubscriptionOptions {
    /// No local flag (don't receive own messages).
    pub no_local: bool,
    /// Retain as published flag.
    pub retain_as_published: bool,
    /// Retain handling option.
    pub retain_handling: RetainHandling,
}

/// Retain handling options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RetainHandling {
    /// Send retained messages at subscribe time.
    #[default]
    SendAtSubscribe = 0,
    /// Send retained messages only for new subscriptions.
    SendIfNewSubscription = 1,
    /// Don't send retained messages.
    DontSend = 2,
}

/// A pending outbound message.
#[derive(Debug, Clone)]
pub struct PendingMessage {
    /// Packet identifier.
    pub packet_id: u16,
    /// The publish message.
    pub publish: Publish,
    /// QoS 2 state.
    pub qos2_state: Option<QoS2State>,
    /// When the message was queued.
    pub timestamp: Instant,
    /// Number of delivery attempts.
    pub attempts: u32,
}

/// An inbound QoS 2 message.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// The publish message.
    pub publish: Publish,
    /// Current state in QoS 2 flow.
    pub state: QoS2State,
    /// When the message was received.
    pub timestamp: Instant,
}

/// QoS 2 message state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoS2State {
    /// PUBLISH received, waiting for PUBREC.
    Received,
    /// PUBREC sent/received, waiting for PUBREL.
    Released,
    /// PUBREL sent/received, waiting for PUBCOMP.
    Complete,
}

/// Will message configuration.
#[derive(Debug, Clone)]
pub struct WillMessage {
    /// Topic for the will message.
    pub topic: String,
    /// Payload of the will message.
    pub payload: Bytes,
    /// QoS level.
    pub qos: QoS,
    /// Retain flag.
    pub retain: bool,
    /// Delay interval before publishing (MQTT 5.0).
    pub delay_interval: Duration,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

/// Session manager.
#[derive(Debug)]
pub struct SessionManager {
    /// Active sessions keyed by client ID.
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    /// Maximum number of sessions.
    max_sessions: usize,
    /// Default session expiry interval.
    #[allow(dead_code)]
    default_expiry: Duration,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(max_sessions: usize, default_expiry: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_sessions,
            default_expiry,
        }
    }

    /// Get or create a session for a client.
    pub async fn get_or_create(
        &self,
        client_id: &str,
        protocol_version: ProtocolVersion,
        clean_session: bool,
    ) -> (Session, bool) {
        let mut sessions = self.sessions.write().await;

        let session_present = if clean_session {
            // Remove existing session if any
            sessions.remove(client_id);
            false
        } else {
            sessions.contains_key(client_id)
        };

        if let Some(session) = sessions.get_mut(client_id) {
            session.touch();
            let existing = std::mem::replace(
                session,
                Session::new(client_id.to_string(), protocol_version),
            );
            return (existing, session_present);
        }

        let session = Session::new(client_id.to_string(), protocol_version);
        (session, session_present)
    }

    /// Store a session.
    pub async fn store(&self, session: Session) {
        let mut sessions = self.sessions.write().await;

        // Check capacity
        if sessions.len() >= self.max_sessions && !sessions.contains_key(&session.client_id) {
            // Remove expired sessions first
            sessions.retain(|_, s| !s.is_expired());

            // If still at capacity, remove oldest
            if sessions.len() >= self.max_sessions {
                if let Some(oldest) = sessions
                    .iter()
                    .min_by_key(|(_, s)| s.last_activity)
                    .map(|(k, _)| k.clone())
                {
                    sessions.remove(&oldest);
                }
            }
        }

        sessions.insert(session.client_id.clone(), session);
    }

    /// Remove a session.
    pub async fn remove(&self, client_id: &str) -> Option<Session> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(client_id)
    }

    /// Get session count.
    pub async fn count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Clean up expired sessions.
    pub async fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, s| !s.is_expired());
        before - sessions.len()
    }

    /// Get all client IDs with subscriptions matching a topic.
    pub async fn find_subscribers(&self, topic: &str) -> Vec<(String, QoS)> {
        let sessions = self.sessions.read().await;
        let mut subscribers = Vec::new();

        for (client_id, session) in sessions.iter() {
            for (filter, state) in &session.subscriptions {
                if let Ok(topic_filter) = TopicFilter::new(filter.clone()) {
                    if topic_filter.matches_str(topic) {
                        subscribers.push((client_id.clone(), state.qos));
                        break;
                    }
                }
            }
        }

        subscribers
    }

    /// Get all subscriptions for a client.
    pub async fn get_subscriptions(&self, client_id: &str) -> HashSet<String> {
        let sessions = self.sessions.read().await;
        sessions
            .get(client_id)
            .map(|s| s.subscriptions.keys().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(10_000, Duration::from_secs(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new("test-client".to_string(), ProtocolVersion::V311);
        assert_eq!(session.client_id, "test-client");
        assert!(session.clean_session);
        assert!(session.subscriptions.is_empty());
    }

    #[test]
    fn test_packet_id_generation() {
        let session = Session::new("test".to_string(), ProtocolVersion::V311);

        let id1 = session.next_packet_id();
        let id2 = session.next_packet_id();
        let id3 = session.next_packet_id();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, 0);
    }

    #[test]
    fn test_subscription_management() {
        let mut session = Session::new("test".to_string(), ProtocolVersion::V311);

        session.subscribe(
            "test/#".to_string(),
            QoS::AtLeastOnce,
            SubscriptionOptions::default(),
        );
        assert_eq!(session.subscriptions.len(), 1);

        session.subscribe(
            "sensor/+/temp".to_string(),
            QoS::ExactlyOnce,
            SubscriptionOptions::default(),
        );
        assert_eq!(session.subscriptions.len(), 2);

        assert!(session.unsubscribe("test/#"));
        assert_eq!(session.subscriptions.len(), 1);

        assert!(!session.unsubscribe("nonexistent"));
    }

    #[test]
    fn test_pending_messages() {
        let mut session = Session::new("test".to_string(), ProtocolVersion::V311);
        session.receive_maximum = 2;

        let msg1 = PendingMessage {
            packet_id: 1,
            publish: Publish::new("test", "data1"),
            qos2_state: None,
            timestamp: Instant::now(),
            attempts: 0,
        };

        let msg2 = PendingMessage {
            packet_id: 2,
            publish: Publish::new("test", "data2"),
            qos2_state: None,
            timestamp: Instant::now(),
            attempts: 0,
        };

        session.queue_outbound(msg1);
        session.queue_outbound(msg2);

        assert!(session.next_outbound().is_some());
        session.inflight_count = 2;

        // Should return None when at receive_maximum
        assert!(session.next_outbound().is_none());
    }

    #[test]
    fn test_qos2_inbound_tracking() {
        let mut session = Session::new("test".to_string(), ProtocolVersion::V311);

        let publish = Publish::new("test", "data").with_qos(QoS::ExactlyOnce, 123);
        session.record_inbound(123, publish);

        assert!(session.has_inbound(123));
        assert!(!session.has_inbound(456));

        let msg = session.complete_inbound(123);
        assert!(msg.is_some());
        assert!(!session.has_inbound(123));
    }

    #[tokio::test]
    async fn test_session_manager() {
        let manager = SessionManager::new(100, Duration::from_secs(3600));

        let (session, present) = manager
            .get_or_create("client1", ProtocolVersion::V311, true)
            .await;
        assert!(!present);
        assert_eq!(session.client_id, "client1");

        manager.store(session).await;
        assert_eq!(manager.count().await, 1);

        let (_, present) = manager
            .get_or_create("client1", ProtocolVersion::V311, false)
            .await;
        assert!(present);
    }

    #[tokio::test]
    async fn test_session_manager_cleanup() {
        let manager = SessionManager::new(100, Duration::from_secs(0));

        let mut session1 = Session::new("client1".to_string(), ProtocolVersion::V311);
        session1.clean_session = false;
        session1.expiry_interval = Duration::from_millis(1);

        manager.store(session1).await;
        assert_eq!(manager.count().await, 1);

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(10)).await;

        let cleaned = manager.cleanup_expired().await;
        assert_eq!(cleaned, 1);
        assert_eq!(manager.count().await, 0);
    }

    #[tokio::test]
    async fn test_find_subscribers() {
        let manager = SessionManager::new(100, Duration::from_secs(3600));

        let mut session = Session::new("client1".to_string(), ProtocolVersion::V311);
        session.subscribe(
            "sensor/#".to_string(),
            QoS::AtLeastOnce,
            SubscriptionOptions::default(),
        );
        manager.store(session).await;

        let subscribers = manager.find_subscribers("sensor/temp").await;
        assert_eq!(subscribers.len(), 1);
        assert_eq!(subscribers[0].0, "client1");
        assert_eq!(subscribers[0].1, QoS::AtLeastOnce);

        let subscribers = manager.find_subscribers("other/topic").await;
        assert!(subscribers.is_empty());
    }

    #[test]
    fn test_will_message() {
        let will = WillMessage {
            topic: "client/status".to_string(),
            payload: Bytes::from("offline"),
            qos: QoS::AtLeastOnce,
            retain: true,
            delay_interval: Duration::from_secs(30),
            properties: Properties::new(),
        };

        let mut session = Session::new("test".to_string(), ProtocolVersion::V5);
        session.will = Some(will);

        assert!(session.will.is_some());
        assert_eq!(session.will.as_ref().unwrap().topic, "client/status");
    }

    #[test]
    fn test_clear_pending() {
        let mut session = Session::new("test".to_string(), ProtocolVersion::V311);

        session.queue_outbound(PendingMessage {
            packet_id: 1,
            publish: Publish::new("test", "data"),
            qos2_state: None,
            timestamp: Instant::now(),
            attempts: 0,
        });

        session.record_inbound(2, Publish::new("test", "data"));
        session.inflight_count = 5;

        session.clear_pending();

        assert!(session.pending_outbound.is_empty());
        assert!(session.pending_inbound.is_empty());
        assert_eq!(session.inflight_count, 0);
    }
}
