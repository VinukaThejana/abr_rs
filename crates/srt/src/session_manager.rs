use crate::cookie::CookieGenerator;
use crate::handshake::Handshake;
use crate::session::{HandshakeAction, HandshakeSession};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Represents an action that the session manager has determined should be taken in response to a
/// received datagram
pub enum RoutedAction {
    /// Send a datagram to the specified peer
    SendTo { bytes: Vec<u8>, to: SocketAddr },

    /// A session has been established with the specified peer, and the local socket ID for that
    /// session is provided
    Established { peer: SocketAddr, socket_id: u32 },

    /// The datagram should be ignored, as it does not correspond to any known session or handshake
    Ignore,
}

/// Represents a session that is being tracked by the session manager, along with the time of the
/// last activity for that session
struct TrackedSession {
    /// The handshake session that is being tracked
    session: HandshakeSession,

    /// The time of the last activity for this session
    last_activity: Instant,
}

/// Manages SRT sessions, including tracking active sessions, handling incomming datagrams, and
/// evicting stale sessions
pub struct SessionManager {
    /// A map of active sessions, keyed by the peer's socket address
    sessions: HashMap<SocketAddr, TrackedSession>,

    /// A generator for cookies used in the handshake process
    cookies: CookieGenerator,

    /// The next socket ID to be allocated for a new session
    next_socket_id: AtomicU32,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            cookies: CookieGenerator::new(),
            next_socket_id: AtomicU32::new(1000),
        }
    }

    pub fn handle_datagram(&mut self, buffer: &[u8], from: SocketAddr) -> RoutedAction {
        self.evict_stale_sessions();

        let incomming = match Handshake::parse(buffer) {
            Ok(handshake) => handshake,
            Err(_) => return RoutedAction::Ignore,
        };

        let is_new_peer = !self.sessions.contains_key(&from);
        let socket_id_for_new_peer = if is_new_peer {
            self.allocate_socket_id()
        } else {
            0
        };

        let tracked = self.sessions.entry(from).or_insert_with(|| TrackedSession {
            session: HandshakeSession::new(from, socket_id_for_new_peer),
            last_activity: Instant::now(),
        });
        tracked.last_activity = Instant::now();

        let action = tracked.session.on_packet(&incomming, &self.cookies);
        let socket_id = tracked.session.local_socket_id();

        match action {
            HandshakeAction::Reply(reply) => RoutedAction::SendTo {
                bytes: reply.to_bytes().to_vec(),
                to: from,
            },
            HandshakeAction::Established => RoutedAction::Established {
                peer: from,
                socket_id,
            },
            HandshakeAction::Reject => RoutedAction::Ignore,
        }
    }

    fn allocate_socket_id(&self) -> u32 {
        self.next_socket_id.fetch_add(1, Ordering::Relaxed)
    }

    fn evict_stale_sessions(&mut self) {
        let now = Instant::now();
        self.sessions
            .retain(|_, tracked| now.duration_since(tracked.last_activity) < SESSION_TIMEOUT);
    }
}
