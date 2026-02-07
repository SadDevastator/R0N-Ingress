//! MQTT handler implementing ModuleContract.

use super::config::{BackendConfig, ListenerConfig, MqttHandlerConfig, ProtocolVersion};
use super::error::MqttResult;
use super::packet::{
    ConnAck, Connect, ConnectReasonCode, MqttPacket, Properties, PubAck, PubComp, PubRec, PubRel,
    Publish, QoS, SubAck, Subscribe, UnsubAck, Unsubscribe,
};
use super::session::{Session, SessionManager, SubscriptionOptions, WillMessage};
use super::topic::{TopicFilter, TopicName, TopicTree};
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use bytes::{Buf, BytesMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Statistics for the MQTT handler.
#[derive(Debug, Default)]
pub struct MqttStats {
    /// Total connections.
    pub connections_total: AtomicU64,
    /// Active connections.
    pub connections_active: AtomicU64,
    /// Total messages received.
    pub messages_received: AtomicU64,
    /// Total messages sent.
    pub messages_sent: AtomicU64,
    /// PUBLISH messages received.
    pub publish_received: AtomicU64,
    /// PUBLISH messages sent.
    pub publish_sent: AtomicU64,
    /// SUBSCRIBE messages received.
    pub subscribe_received: AtomicU64,
    /// UNSUBSCRIBE messages received.
    pub unsubscribe_received: AtomicU64,
    /// Total bytes received.
    pub bytes_received: AtomicU64,
    /// Total bytes sent.
    pub bytes_sent: AtomicU64,
    /// Failed authentications.
    pub auth_failures: AtomicU64,
    /// Active subscriptions.
    pub subscriptions_active: AtomicU64,
    /// MQTT 3.1.1 connections.
    pub mqtt311_connections: AtomicU64,
    /// MQTT 5.0 connections.
    pub mqtt5_connections: AtomicU64,
}

impl MqttStats {
    /// Create new stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a connection.
    pub fn connection_opened(&self, protocol_version: ProtocolVersion) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.connections_active.fetch_add(1, Ordering::Relaxed);
        match protocol_version {
            ProtocolVersion::V31 | ProtocolVersion::V311 => {
                self.mqtt311_connections.fetch_add(1, Ordering::Relaxed);
            },
            ProtocolVersion::V5 => {
                self.mqtt5_connections.fetch_add(1, Ordering::Relaxed);
            },
        }
    }

    /// Record a connection closed.
    pub fn connection_closed(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record bytes.
    pub fn record_bytes(&self, received: u64, sent: u64) {
        self.bytes_received.fetch_add(received, Ordering::Relaxed);
        self.bytes_sent.fetch_add(sent, Ordering::Relaxed);
    }

    /// Record a received message.
    pub fn message_received(&self) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a sent message.
    pub fn message_sent(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a PUBLISH received.
    pub fn publish_received(&self) {
        self.publish_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a PUBLISH sent.
    pub fn publish_sent(&self) {
        self.publish_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a SUBSCRIBE received.
    pub fn subscribe_received(&self) {
        self.subscribe_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an UNSUBSCRIBE received.
    pub fn unsubscribe_received(&self) {
        self.unsubscribe_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an authentication failure.
    pub fn auth_failed(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Update subscription count.
    pub fn set_subscriptions(&self, count: u64) {
        self.subscriptions_active.store(count, Ordering::Relaxed);
    }
}

/// Topic router for MQTT.
#[derive(Debug)]
pub struct TopicRouter {
    /// Routes by topic filter.
    routes: Vec<TopicRoute>,
    /// Default backend.
    default_backend: Option<BackendConfig>,
    /// Subscription tree for efficient matching.
    subscriptions: TopicTree<ClientSubscription>,
}

/// A topic route.
#[derive(Debug, Clone)]
pub struct TopicRoute {
    /// Route name.
    pub name: String,
    /// Topic filter.
    pub filter: TopicFilter,
    /// Backend to route to.
    pub backend: BackendConfig,
    /// Priority.
    pub priority: i32,
    /// Topic transformation.
    pub topic_transform: Option<String>,
}

/// A client subscription.
#[derive(Debug, Clone)]
pub struct ClientSubscription {
    /// Client ID.
    pub client_id: String,
    /// QoS level.
    pub qos: QoS,
}

impl TopicRouter {
    /// Create a new topic router.
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            default_backend: None,
            subscriptions: TopicTree::new(),
        }
    }

    /// Add a route.
    pub fn add_route(&mut self, route: TopicRoute) {
        self.routes.push(route);
        self.routes.sort_by_key(|r| std::cmp::Reverse(r.priority));
    }

    /// Set default backend.
    pub fn set_default_backend(&mut self, backend: BackendConfig) {
        self.default_backend = Some(backend);
    }

    /// Find a route for a topic.
    pub fn find_route(&self, topic: &str) -> Option<&TopicRoute> {
        self.routes
            .iter()
            .find(|route| route.filter.matches_str(topic))
    }

    /// Find route or default.
    pub fn route_or_default(&self, topic: &str) -> Option<&BackendConfig> {
        self.find_route(topic)
            .map(|r| &r.backend)
            .or(self.default_backend.as_ref())
    }

    /// Add a client subscription.
    pub fn subscribe(&mut self, client_id: &str, filter: &TopicFilter, qos: QoS) {
        self.subscriptions.insert(
            filter,
            ClientSubscription {
                client_id: client_id.to_string(),
                qos,
            },
        );
    }

    /// Remove all subscriptions for a client.
    pub fn unsubscribe_all(&mut self, client_id: &str) {
        self.subscriptions.remove_if(|s| s.client_id == client_id);
    }

    /// Find all subscribers for a topic.
    pub fn find_subscribers(&self, topic: &TopicName) -> Vec<ClientSubscription> {
        self.subscriptions.find_matches(topic)
    }
}

impl Default for TopicRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection state.
#[derive(Debug)]
#[allow(dead_code)]
struct ConnectionState {
    /// Client ID.
    client_id: String,
    /// Protocol version.
    protocol_version: u8,
    /// Whether connected.
    connected: bool,
    /// Session.
    session: Session,
}

/// MQTT handler module.
#[derive(Debug)]
pub struct MqttHandler {
    /// Configuration.
    config: MqttHandlerConfig,
    /// Topic router.
    router: Arc<RwLock<TopicRouter>>,
    /// Session manager.
    sessions: Arc<SessionManager>,
    /// Current status.
    status: ModuleStatus,
    /// Statistics.
    stats: Arc<MqttStats>,
    /// Shutdown sender.
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Active listener handles.
    listener_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl MqttHandler {
    /// Create a new MQTT handler.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(MqttHandlerConfig::default())
    }

    /// Create an MQTT handler with custom configuration.
    #[must_use]
    pub fn with_config(config: MqttHandlerConfig) -> Self {
        let sessions = Arc::new(SessionManager::new(
            config.session.max_sessions,
            Duration::from_secs(config.session.expiry_interval as u64),
        ));

        Self {
            config,
            router: Arc::new(RwLock::new(TopicRouter::new())),
            sessions,
            status: ModuleStatus::Stopped,
            stats: Arc::new(MqttStats::new()),
            shutdown_tx: None,
            listener_handles: Vec::new(),
        }
    }

    /// Get statistics.
    #[must_use]
    pub fn stats(&self) -> &Arc<MqttStats> {
        &self.stats
    }

    /// Handle an MQTT connection.
    async fn handle_connection(
        mut stream: TcpStream,
        config: MqttHandlerConfig,
        router: Arc<RwLock<TopicRouter>>,
        sessions: Arc<SessionManager>,
        stats: Arc<MqttStats>,
    ) {
        let peer_addr = stream.peer_addr().ok().map(|a| a.to_string());
        debug!(peer = ?peer_addr, "New MQTT connection");

        let mut buf = BytesMut::with_capacity(config.limits.max_packet_size);
        let mut state: Option<ConnectionState> = None;
        let mut protocol_version: u8 = 4; // Default to MQTT 3.1.1

        loop {
            // Read data
            let mut temp_buf = vec![0u8; 8192];

            let timeout = if state.is_none() {
                config.limits.connect_timeout
            } else {
                config.limits.idle_timeout
            };

            match tokio::time::timeout(timeout, stream.read(&mut temp_buf)).await {
                Ok(Ok(0)) => {
                    debug!("Connection closed by client");
                    break;
                },
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&temp_buf[..n]);
                    stats.record_bytes(n as u64, 0);
                },
                Ok(Err(e)) => {
                    debug!(error = %e, "Read error");
                    break;
                },
                Err(_) => {
                    debug!("Connection timeout");
                    break;
                },
            }

            // Try to parse packets from buffer
            while buf.has_remaining() {
                // Check if we have enough data for packet header
                if buf.remaining() < 2 {
                    break;
                }

                // Peek at remaining length to determine full packet size
                let packet_size = match Self::peek_packet_size(&buf) {
                    Some(size) => size,
                    None => break, // Need more data
                };

                if packet_size > config.limits.max_packet_size {
                    error!(
                        size = packet_size,
                        max = config.limits.max_packet_size,
                        "Packet too large"
                    );
                    // Send disconnect and close
                    break;
                }

                if buf.remaining() < packet_size {
                    break; // Need more data
                }

                // Parse packet
                let mut packet_buf = buf.split_to(packet_size).freeze();
                stats.message_received();

                let packet = match MqttPacket::parse(&mut packet_buf, protocol_version) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(error = %e, "Failed to parse MQTT packet");
                        break;
                    },
                };

                // Handle packet based on state
                let response = match state.as_mut() {
                    None => {
                        // Must be CONNECT
                        match packet {
                            MqttPacket::Connect(connect) => {
                                protocol_version = connect.protocol_level;
                                Self::handle_connect(connect, &config, &sessions, &stats).await
                            },
                            _ => {
                                warn!("Expected CONNECT, got {:?}", packet.packet_type());
                                break;
                            },
                        }
                    },
                    Some(conn) => Self::handle_packet(packet, conn, &router, &config, &stats).await,
                };

                // Process response
                match response {
                    PacketResult::Respond(packets) => {
                        for pkt in packets {
                            let data = pkt.serialize(protocol_version);
                            stats.record_bytes(0, data.len() as u64);
                            stats.message_sent();
                            if let Err(e) = stream.write_all(&data).await {
                                debug!(error = %e, "Write error");
                                break;
                            }
                        }
                    },
                    PacketResult::Connected(session, version) => {
                        let pv =
                            ProtocolVersion::from_level(version).unwrap_or(ProtocolVersion::V311);
                        stats.connection_opened(pv);

                        // Send CONNACK
                        let connack = MqttPacket::ConnAck(ConnAck::success(false));
                        let data = connack.serialize(version);
                        stats.record_bytes(0, data.len() as u64);
                        stats.message_sent();
                        if let Err(e) = stream.write_all(&data).await {
                            debug!(error = %e, "Write error");
                            break;
                        }

                        state = Some(ConnectionState {
                            client_id: session.client_id.clone(),
                            protocol_version: version,
                            connected: true,
                            session: *session,
                        });
                    },
                    PacketResult::Disconnect => {
                        debug!("Client disconnected");
                        break;
                    },
                    PacketResult::Error(code) => {
                        let connack = MqttPacket::ConnAck(ConnAck::error(code));
                        let data = connack.serialize(protocol_version);
                        let _ = stream.write_all(&data).await;
                        break;
                    },
                    PacketResult::None => {},
                }
            }
        }

        // Cleanup on disconnect
        if let Some(conn) = state.take() {
            debug!(client_id = %conn.client_id, "Client disconnected");
            stats.connection_closed();

            // Remove subscriptions
            let mut router = router.write().await;
            router.unsubscribe_all(&conn.client_id);

            // Handle will message if needed
            if let Some(ref will) = conn.session.will {
                debug!(topic = %will.topic, "Publishing will message");
                // In a full implementation, we'd publish the will message here
            }

            // Store or remove session based on clean_session flag
            if !conn.session.clean_session {
                sessions.store(conn.session).await;
            } else {
                sessions.remove(&conn.client_id).await;
            }
        }
    }

    /// Peek at packet size without consuming buffer.
    fn peek_packet_size(buf: &[u8]) -> Option<usize> {
        if buf.len() < 2 {
            return None;
        }

        let mut remaining_length: usize = 0;
        let mut multiplier: usize = 1;
        let mut i = 1;

        loop {
            if i >= buf.len() {
                return None; // Need more data
            }

            let byte = buf[i];
            remaining_length += ((byte & 0x7F) as usize) * multiplier;
            multiplier *= 128;
            i += 1;

            if (byte & 0x80) == 0 {
                break;
            }

            if i > 4 {
                return None; // Malformed
            }
        }

        Some(i + remaining_length)
    }

    /// Handle CONNECT packet.
    async fn handle_connect(
        connect: Connect,
        config: &MqttHandlerConfig,
        sessions: &SessionManager,
        stats: &MqttStats,
    ) -> PacketResult {
        // Validate protocol version
        let version = ProtocolVersion::from_level(connect.protocol_level);
        if version.is_none() {
            stats.auth_failed();
            return PacketResult::Error(ConnectReasonCode::UnsupportedProtocolVersion);
        }
        let version = version.unwrap();

        // Check if version is supported
        if !config.protocol.versions.contains(&version) {
            return PacketResult::Error(ConnectReasonCode::UnsupportedProtocolVersion);
        }

        // Validate client ID
        if connect.client_id.is_empty() && !config.security.allow_anonymous {
            return PacketResult::Error(ConnectReasonCode::ClientIdentifierNotValid);
        }

        if connect.client_id.len() > config.limits.max_client_id_len {
            return PacketResult::Error(ConnectReasonCode::ClientIdentifierNotValid);
        }

        // Validate authentication
        if config.security.require_auth && connect.username.is_none() {
            stats.auth_failed();
            return PacketResult::Error(ConnectReasonCode::BadUserNameOrPassword);
        }
        // In a full implementation, we'd validate credentials here

        // Get or create session
        let (mut session, _session_present) = sessions
            .get_or_create(&connect.client_id, version, connect.clean_session)
            .await;

        session.clean_session = connect.clean_session;
        session.keep_alive = Duration::from_secs(connect.keep_alive as u64);

        // Set will message
        if let Some(will) = connect.will {
            session.will = Some(WillMessage {
                topic: will.topic,
                payload: will.payload,
                qos: will.qos,
                retain: will.retain,
                delay_interval: Duration::ZERO,
                properties: will.properties,
            });
        }

        // Copy properties from CONNECT
        session.properties = connect.properties;

        // Set MQTT 5.0 specific options
        if connect.protocol_level >= 5 {
            if let Some(expiry) = session.properties.session_expiry_interval() {
                session.expiry_interval = Duration::from_secs(expiry as u64);
            }
            if let Some(recv_max) = session.properties.receive_maximum() {
                session.receive_maximum = recv_max;
            }
        }

        info!(
            client_id = %connect.client_id,
            version = ?version,
            clean_session = %connect.clean_session,
            "Client connected"
        );

        PacketResult::Connected(Box::new(session), connect.protocol_level)
    }

    /// Handle a packet from a connected client.
    async fn handle_packet(
        packet: MqttPacket,
        state: &mut ConnectionState,
        router: &RwLock<TopicRouter>,
        config: &MqttHandlerConfig,
        stats: &MqttStats,
    ) -> PacketResult {
        state.session.touch();

        match packet {
            MqttPacket::Publish(publish) => {
                Self::handle_publish(publish, state, router, config, stats).await
            },
            MqttPacket::PubAck(puback) => Self::handle_puback(puback, state),
            MqttPacket::PubRec(pubrec) => Self::handle_pubrec(pubrec, state),
            MqttPacket::PubRel(pubrel) => Self::handle_pubrel(pubrel, state),
            MqttPacket::PubComp(pubcomp) => Self::handle_pubcomp(pubcomp, state),
            MqttPacket::Subscribe(subscribe) => {
                Self::handle_subscribe(subscribe, state, router, config, stats).await
            },
            MqttPacket::Unsubscribe(unsubscribe) => {
                Self::handle_unsubscribe(unsubscribe, state, router, stats).await
            },
            MqttPacket::PingReq => PacketResult::Respond(vec![MqttPacket::PingResp]),
            MqttPacket::Disconnect(_) => {
                // Clear will message on clean disconnect
                state.session.will = None;
                PacketResult::Disconnect
            },
            _ => {
                warn!("Unexpected packet type: {:?}", packet.packet_type());
                PacketResult::None
            },
        }
    }

    /// Handle PUBLISH packet.
    async fn handle_publish(
        publish: Publish,
        state: &mut ConnectionState,
        router: &RwLock<TopicRouter>,
        config: &MqttHandlerConfig,
        stats: &MqttStats,
    ) -> PacketResult {
        stats.publish_received();

        // Validate topic
        if publish.topic.len() > config.limits.max_topic_len {
            warn!(topic = %publish.topic, "Topic too long");
            return PacketResult::None;
        }

        if TopicName::validate(&publish.topic).is_err() {
            warn!(topic = %publish.topic, "Invalid topic name");
            return PacketResult::None;
        }

        // Check QoS limit
        if (publish.qos as u8) > config.protocol.max_qos {
            warn!(qos = ?publish.qos, max = config.protocol.max_qos, "QoS exceeds maximum");
            return PacketResult::None;
        }

        // Check retain flag
        if publish.retain && !config.protocol.retain_available {
            warn!("Retain not available");
            return PacketResult::None;
        }

        // Route the message to subscribers
        let topic = match TopicName::new(&publish.topic) {
            Ok(t) => t,
            Err(_) => return PacketResult::None,
        };

        let router = router.read().await;
        let subscribers = router.find_subscribers(&topic);
        drop(router);

        debug!(
            topic = %publish.topic,
            subscribers = %subscribers.len(),
            qos = ?publish.qos,
            "Processing PUBLISH"
        );

        // In a full implementation, we'd deliver to subscribers and route to backends

        // Send acknowledgment based on QoS
        match publish.qos {
            QoS::AtMostOnce => PacketResult::None,
            QoS::AtLeastOnce => {
                if let Some(packet_id) = publish.packet_id {
                    PacketResult::Respond(vec![MqttPacket::PubAck(PubAck::new(packet_id))])
                } else {
                    PacketResult::None
                }
            },
            QoS::ExactlyOnce => {
                if let Some(packet_id) = publish.packet_id {
                    state.session.record_inbound(packet_id, publish);
                    PacketResult::Respond(vec![MqttPacket::PubRec(PubRec::new(packet_id))])
                } else {
                    PacketResult::None
                }
            },
        }
    }

    /// Handle PUBACK packet.
    fn handle_puback(puback: PubAck, state: &mut ConnectionState) -> PacketResult {
        debug!(packet_id = puback.packet_id, "Received PUBACK");
        // Remove from pending outbound
        state.session.inflight_count = state.session.inflight_count.saturating_sub(1);
        PacketResult::None
    }

    /// Handle PUBREC packet.
    fn handle_pubrec(pubrec: PubRec, _state: &mut ConnectionState) -> PacketResult {
        debug!(packet_id = pubrec.packet_id, "Received PUBREC");
        PacketResult::Respond(vec![MqttPacket::PubRel(PubRel::new(pubrec.packet_id))])
    }

    /// Handle PUBREL packet.
    fn handle_pubrel(pubrel: PubRel, state: &mut ConnectionState) -> PacketResult {
        debug!(packet_id = pubrel.packet_id, "Received PUBREL");
        state.session.complete_inbound(pubrel.packet_id);
        PacketResult::Respond(vec![MqttPacket::PubComp(PubComp::new(pubrel.packet_id))])
    }

    /// Handle PUBCOMP packet.
    fn handle_pubcomp(pubcomp: PubComp, state: &mut ConnectionState) -> PacketResult {
        debug!(packet_id = pubcomp.packet_id, "Received PUBCOMP");
        state.session.inflight_count = state.session.inflight_count.saturating_sub(1);
        PacketResult::None
    }

    /// Handle SUBSCRIBE packet.
    async fn handle_subscribe(
        subscribe: Subscribe,
        state: &mut ConnectionState,
        router: &RwLock<TopicRouter>,
        config: &MqttHandlerConfig,
        stats: &MqttStats,
    ) -> PacketResult {
        stats.subscribe_received();

        let mut reason_codes = Vec::with_capacity(subscribe.subscriptions.len());
        let mut router = router.write().await;

        for sub in &subscribe.subscriptions {
            // Validate topic filter
            let filter = match TopicFilter::new(&sub.topic_filter) {
                Ok(f) => f,
                Err(e) => {
                    warn!(filter = %sub.topic_filter, error = %e, "Invalid topic filter");
                    reason_codes.push(0x80); // Unspecified error
                    continue;
                },
            };

            // Check wildcards allowed
            if filter.has_wildcards() && !config.protocol.wildcard_subscription {
                reason_codes.push(0xA2); // Wildcard subscriptions not supported
                continue;
            }

            // Check subscription limit
            if state.session.subscriptions.len() >= config.limits.max_subscriptions {
                reason_codes.push(0x97); // Quota exceeded
                continue;
            }

            // Grant QoS (may be lower than requested based on config)
            let granted_qos = std::cmp::min(sub.options.qos as u8, config.protocol.max_qos);
            let qos = QoS::from_u8(granted_qos).unwrap_or(QoS::AtMostOnce);

            // Add subscription
            state.session.subscribe(
                sub.topic_filter.clone(),
                qos,
                SubscriptionOptions {
                    no_local: sub.options.no_local,
                    retain_as_published: sub.options.retain_as_published,
                    ..Default::default()
                },
            );

            router.subscribe(&state.client_id, &filter, qos);

            debug!(
                client_id = %state.client_id,
                filter = %sub.topic_filter,
                qos = granted_qos,
                "Subscription added"
            );

            reason_codes.push(granted_qos);
        }

        PacketResult::Respond(vec![MqttPacket::SubAck(SubAck {
            packet_id: subscribe.packet_id,
            reason_codes,
            properties: Properties::new(),
        })])
    }

    /// Handle UNSUBSCRIBE packet.
    async fn handle_unsubscribe(
        unsubscribe: Unsubscribe,
        state: &mut ConnectionState,
        router: &RwLock<TopicRouter>,
        stats: &MqttStats,
    ) -> PacketResult {
        stats.unsubscribe_received();

        let mut reason_codes = Vec::with_capacity(unsubscribe.topic_filters.len());
        let mut router = router.write().await;

        for filter_str in &unsubscribe.topic_filters {
            if state.session.unsubscribe(filter_str) {
                debug!(
                    client_id = %state.client_id,
                    filter = %filter_str,
                    "Subscription removed"
                );
                reason_codes.push(0x00); // Success
            } else {
                reason_codes.push(0x11); // No subscription existed
            }

            // Also remove from router
            if let Ok(_filter) = TopicFilter::new(filter_str.clone()) {
                router
                    .subscriptions
                    .remove_if(|s| s.client_id == state.client_id);
            }
        }

        PacketResult::Respond(vec![MqttPacket::UnsubAck(UnsubAck {
            packet_id: unsubscribe.packet_id,
            reason_codes,
            properties: Properties::new(),
        })])
    }

    /// Start a listener.
    async fn start_listener(
        listener_config: ListenerConfig,
        config: MqttHandlerConfig,
        router: Arc<RwLock<TopicRouter>>,
        sessions: Arc<SessionManager>,
        stats: Arc<MqttStats>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        let addr = match listener_config.socket_addr() {
            Some(addr) => addr,
            None => {
                error!(
                    address = %listener_config.address,
                    port = %listener_config.port,
                    "Invalid listener address"
                );
                return;
            },
        };

        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(address = %addr, error = %e, "Failed to bind listener");
                return;
            },
        };

        info!(
            address = %addr,
            tls = %listener_config.tls,
            websocket = %listener_config.websocket,
            "MQTT listener started"
        );

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            debug!(peer = %peer, "New MQTT connection");

                            let config = config.clone();
                            let router = Arc::clone(&router);
                            let sessions = Arc::clone(&sessions);
                            let stats = Arc::clone(&stats);

                            tokio::spawn(async move {
                                Self::handle_connection(
                                    stream,
                                    config,
                                    router,
                                    sessions,
                                    stats,
                                ).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "Accept error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!(address = %addr, "Listener shutting down");
                    break;
                }
            }
        }
    }

    /// Initialize routes from configuration.
    #[allow(dead_code)]
    async fn init_routes(&self) -> MqttResult<()> {
        let mut router = self.router.write().await;

        for route_config in &self.config.routes {
            let filter = TopicFilter::new(&route_config.topic_filter)?;
            router.add_route(TopicRoute {
                name: route_config.name.clone(),
                filter,
                backend: route_config.backend.clone(),
                priority: route_config.priority,
                topic_transform: route_config.topic_transform.clone(),
            });
        }

        if let Some(ref backend) = self.config.default_backend {
            router.set_default_backend(backend.clone());
        }

        Ok(())
    }
}

/// Result of handling a packet.
#[derive(Debug)]
enum PacketResult {
    /// Send response packets.
    Respond(Vec<MqttPacket>),
    /// Client connected successfully.
    Connected(Box<Session>, u8),
    /// Client disconnected.
    Disconnect,
    /// Connection error.
    Error(ConnectReasonCode),
    /// No response needed.
    None,
}

impl Default for MqttHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for MqttHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("mqtt-handler")
            .description("MQTT 3.1.1 and MQTT 5.0 protocol handler with topic routing")
            .version(1, 0, 0)
            .author("R0N Team")
            .capability(Capability::Custom("mqtt".to_string()))
            .capability(Capability::Custom("mqtt311".to_string()))
            .capability(Capability::Custom("mqtt5".to_string()))
            .capability(Capability::Custom("topic-routing".to_string()))
            .capability(Capability::Custom("qos".to_string()))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        if self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Stopped".to_string(),
            });
        }

        // Parse configuration if provided
        if let Some(config_toml) = config.get_string("config_toml") {
            self.config = toml::from_str(config_toml)
                .map_err(|e| ModuleError::ConfigError(format!("Invalid config: {e}")))?;
        }

        // Validate configuration
        if self.config.listeners.is_empty() {
            return Err(ModuleError::ConfigError(
                "At least one listener is required".to_string(),
            ));
        }

        // Initialize router (we need a runtime for async)
        // Routes will be initialized when start() is called

        self.status = ModuleStatus::Initializing;
        info!(
            listeners = %self.config.listeners.len(),
            routes = %self.config.routes.len(),
            "MQTT handler initialized"
        );

        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Initializing && self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Initializing or Stopped".to_string(),
            });
        }

        // Check we have a runtime
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(ModuleError::ConfigError(
                "No tokio runtime available".to_string(),
            ));
        }

        let (shutdown_tx, _) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // Initialize routes
        let router = Arc::clone(&self.router);
        let config = self.config.clone();
        tokio::spawn(async move {
            let mut router = router.write().await;
            for route_config in &config.routes {
                if let Ok(filter) = TopicFilter::new(&route_config.topic_filter) {
                    router.add_route(TopicRoute {
                        name: route_config.name.clone(),
                        filter,
                        backend: route_config.backend.clone(),
                        priority: route_config.priority,
                        topic_transform: route_config.topic_transform.clone(),
                    });
                }
            }
            if let Some(ref backend) = config.default_backend {
                router.set_default_backend(backend.clone());
            }
        });

        // Start listeners
        for listener_config in self.config.listeners.clone() {
            let config = self.config.clone();
            let router = Arc::clone(&self.router);
            let sessions = Arc::clone(&self.sessions);
            let stats = Arc::clone(&self.stats);
            let shutdown_rx = mpsc::channel::<()>(1).1;

            let handle = tokio::spawn(async move {
                Self::start_listener(
                    listener_config,
                    config,
                    router,
                    sessions,
                    stats,
                    shutdown_rx,
                )
                .await;
            });

            self.listener_handles.push(handle);
        }

        self.status = ModuleStatus::Running;
        info!(
            listeners = %self.listener_handles.len(),
            "MQTT handler started"
        );

        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Ok(()); // Already stopped
        }

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }

        // Abort listener handles
        for handle in self.listener_handles.drain(..) {
            handle.abort();
        }

        self.status = ModuleStatus::Stopped;
        info!("MQTT handler stopped");

        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut payload = MetricsPayload::new();

        payload.counter(
            "connections_total",
            self.stats.connections_total.load(Ordering::Relaxed),
        );
        payload.gauge(
            "connections_active",
            self.stats.connections_active.load(Ordering::Relaxed) as f64,
        );
        payload.counter(
            "messages_received",
            self.stats.messages_received.load(Ordering::Relaxed),
        );
        payload.counter(
            "messages_sent",
            self.stats.messages_sent.load(Ordering::Relaxed),
        );
        payload.counter(
            "publish_received",
            self.stats.publish_received.load(Ordering::Relaxed),
        );
        payload.counter(
            "publish_sent",
            self.stats.publish_sent.load(Ordering::Relaxed),
        );
        payload.counter(
            "subscribe_received",
            self.stats.subscribe_received.load(Ordering::Relaxed),
        );
        payload.counter(
            "bytes_received",
            self.stats.bytes_received.load(Ordering::Relaxed),
        );
        payload.counter("bytes_sent", self.stats.bytes_sent.load(Ordering::Relaxed));
        payload.counter(
            "mqtt311_connections",
            self.stats.mqtt311_connections.load(Ordering::Relaxed),
        );
        payload.counter(
            "mqtt5_connections",
            self.stats.mqtt5_connections.load(Ordering::Relaxed),
        );

        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_creation() {
        let handler = MqttHandler::new();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_handler_manifest() {
        let handler = MqttHandler::new();
        let manifest = handler.manifest();
        assert_eq!(manifest.name, "mqtt-handler");
    }

    #[test]
    fn test_handler_with_config() {
        let config = MqttHandlerConfig {
            enabled: true,
            listeners: vec![ListenerConfig {
                port: 1883,
                ..Default::default()
            }],
            ..Default::default()
        };
        let handler = MqttHandler::with_config(config);
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_handler_init() {
        let mut handler = MqttHandler::new();
        let config = ModuleConfig::new();
        assert!(handler.init(config).is_ok());
        assert_eq!(handler.status(), ModuleStatus::Initializing);
    }

    #[test]
    fn test_handler_init_invalid_state() {
        let mut handler = MqttHandler::new();
        let config = ModuleConfig::new();
        handler.status = ModuleStatus::Running;
        let result = handler.init(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_topic_router() {
        let mut router = TopicRouter::new();

        let filter = TopicFilter::new("sensor/#").unwrap();
        router.add_route(TopicRoute {
            name: "sensors".to_string(),
            filter,
            backend: BackendConfig {
                address: "127.0.0.1".to_string(),
                port: 1884,
                tls: false,
                client_id_prefix: None,
                connect_timeout: None,
            },
            priority: 10,
            topic_transform: None,
        });

        let route = router.find_route("sensor/temp");
        assert!(route.is_some());
        assert_eq!(route.unwrap().name, "sensors");

        let route = router.find_route("device/temp");
        assert!(route.is_none());
    }

    #[test]
    fn test_topic_router_subscriptions() {
        let mut router = TopicRouter::new();

        let filter = TopicFilter::new("sensor/+/temp").unwrap();
        router.subscribe("client1", &filter, QoS::AtLeastOnce);

        let topic = TopicName::new("sensor/living/temp").unwrap();
        let subs = router.find_subscribers(&topic);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].client_id, "client1");
    }

    #[test]
    fn test_stats() {
        let stats = MqttStats::new();

        stats.connection_opened(ProtocolVersion::V311);
        assert_eq!(stats.connections_total.load(Ordering::Relaxed), 1);
        assert_eq!(stats.connections_active.load(Ordering::Relaxed), 1);
        assert_eq!(stats.mqtt311_connections.load(Ordering::Relaxed), 1);

        stats.publish_received();
        assert_eq!(stats.publish_received.load(Ordering::Relaxed), 1);

        stats.connection_closed();
        assert_eq!(stats.connections_active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_peek_packet_size() {
        // PINGREQ: 0xC0, 0x00 (type 12, remaining length 0)
        let buf = vec![0xC0, 0x00];
        assert_eq!(MqttHandler::peek_packet_size(&buf), Some(2));

        // PUBLISH with 127 byte payload
        let buf = vec![0x30, 0x7F];
        assert_eq!(MqttHandler::peek_packet_size(&buf), Some(2 + 127));

        // PUBLISH with 128 byte payload (variable length encoding)
        let buf = vec![0x30, 0x80, 0x01];
        assert_eq!(MqttHandler::peek_packet_size(&buf), Some(3 + 128));

        // Incomplete buffer
        let buf = vec![0x30];
        assert_eq!(MqttHandler::peek_packet_size(&buf), None);
    }

    #[test]
    fn test_handler_heartbeat() {
        let mut handler = MqttHandler::new();

        // Not running - heartbeat returns false
        assert!(!handler.heartbeat());

        // Set to running
        handler.status = ModuleStatus::Running;
        assert!(handler.heartbeat());
    }

    #[test]
    fn test_handler_metrics() {
        let handler = MqttHandler::new();

        // Record some stats
        handler.stats.connection_opened(ProtocolVersion::V5);
        handler.stats.publish_received();
        handler.stats.message_received();

        let metrics = handler.metrics();

        assert_eq!(*metrics.counters.get("connections_total").unwrap(), 1);
        assert_eq!(*metrics.counters.get("mqtt5_connections").unwrap(), 1);
        assert_eq!(*metrics.counters.get("publish_received").unwrap(), 1);
    }

    #[test]
    fn test_handler_stop_when_stopped() {
        let mut handler = MqttHandler::new();
        // Should not error when already stopped
        assert!(handler.stop().is_ok());
    }

    #[tokio::test]
    async fn test_topic_router_unsubscribe_all() {
        let mut router = TopicRouter::new();

        let filter1 = TopicFilter::new("a/#").unwrap();
        let filter2 = TopicFilter::new("b/#").unwrap();

        router.subscribe("client1", &filter1, QoS::AtMostOnce);
        router.subscribe("client1", &filter2, QoS::AtMostOnce);
        router.subscribe("client2", &filter1, QoS::AtMostOnce);

        router.unsubscribe_all("client1");

        let topic_a = TopicName::new("a/test").unwrap();
        let subs_a = router.find_subscribers(&topic_a);

        // Only client2 should remain
        assert_eq!(subs_a.len(), 1);
        assert_eq!(subs_a[0].client_id, "client2");
    }
}
