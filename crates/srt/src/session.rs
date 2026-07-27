use crate::cookie::CookieGenerator;
use crate::handshake::{Handshake, HandshakeType};
use std::net::SocketAddr;

/// Represents the current state of an SRT connection
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum ConnectionState {
    /// No valid packet has been received yet. Waiting for the peer's first `INDUCTION` request
    AwaitingInduction,
    /// Replied to the peer's `INDUCTION` request with a cookie. Waiting for the peer's `CONCLUSION`
    /// request
    AwaitingConclusion,
    /// Cookie verified, connection established. Ready to send and receive data.
    Connected,
}

/// Represents the action to take after processing a handshake packet
#[derive(Debug)]
pub(crate) enum HandshakeAction {
    /// Reply to the peer with the given handshake packet
    Reply(Handshake),
    /// The handshake has been successfully established
    Established,
    /// The handshake request should be rejected
    Reject,
}

pub(crate) struct HandshakeSession {
    state: ConnectionState,
    peer_addr: SocketAddr,
    local_socket_id: u32,
}

impl HandshakeSession {
    pub(crate) fn new(peer_addr: SocketAddr, local_socket_id: u32) -> Self {
        Self {
            state: ConnectionState::AwaitingInduction,
            peer_addr,
            local_socket_id,
        }
    }

    pub(crate) fn state(&self) -> ConnectionState {
        self.state
    }
    pub(crate) fn local_socket_id(&self) -> u32 {
        self.local_socket_id
    }

    /// Feeds one incomming, already parsed handshake into the state machine, advancing (or
    /// rejecting) as appropriate
    pub(crate) fn on_packet(
        &mut self,
        incomming: &Handshake,
        cookies: &CookieGenerator,
    ) -> HandshakeAction {
        match (self.state, incomming.handshake_type) {
            (ConnectionState::AwaitingInduction, HandshakeType::Induction) => {
                let cookie = cookies.generate(self.peer_addr);
                self.state = ConnectionState::AwaitingConclusion;

                HandshakeAction::Reply(self.build_reply(
                    HandshakeType::Induction,
                    cookie,
                    incomming,
                ))
            }

            (ConnectionState::AwaitingConclusion, HandshakeType::Conclusion) => {
                if cookies.verify(self.peer_addr, incomming.syn_cookie) {
                    self.state = ConnectionState::Connected;
                    HandshakeAction::Established
                } else {
                    HandshakeAction::Reject
                }
            }

            (ConnectionState::AwaitingConclusion, HandshakeType::Induction) => {
                let cookie = cookies.generate(self.peer_addr);

                HandshakeAction::Reply(self.build_reply(
                    HandshakeType::Induction,
                    cookie,
                    incomming,
                ))
            }

            _ => HandshakeAction::Reject,
        }
    }

    fn build_reply(
        &mut self,
        handshake_type: HandshakeType,
        cookie: u32,
        incomming: &Handshake,
    ) -> Handshake {
        Handshake {
            version: incomming.version,
            encryption_field: 0,
            extension_field: 0,
            initial_sequence_number: incomming.initial_sequence_number,
            max_transmission_unit: incomming.max_transmission_unit,
            max_flow_window_size: incomming.max_flow_window_size,
            handshake_type,
            srt_socket_id: self.local_socket_id,
            syn_cookie: cookie,
            peer_ip: incomming.peer_ip,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_handshake(handshake_type: HandshakeType, syn_cookie: u32) -> Handshake {
        Handshake {
            version: 4,
            encryption_field: 0,
            extension_field: 0,
            initial_sequence_number: 12345,
            max_transmission_unit: 1500,
            max_flow_window_size: 8192,
            handshake_type,
            srt_socket_id: 999,
            syn_cookie,
            peer_ip: [0u8; 16],
        }
    }

    fn peer_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345)
    }

    fn session() -> HandshakeSession {
        HandshakeSession::new(peer_addr(), 42)
    }

    #[test]
    fn new_session_starts_in_awaiting_induction() {
        let s = session();
        assert_eq!(s.state(), ConnectionState::AwaitingInduction);
        assert_eq!(s.local_socket_id(), 42);
    }

    #[test]
    fn induction_from_awaiting_induction_replies_and_advances_state() {
        let mut s = session();
        let cookies = CookieGenerator::new();
        let incoming = test_handshake(HandshakeType::Induction, 0);

        let action = s.on_packet(&incoming, &cookies);

        match action {
            HandshakeAction::Reply(reply) => {
                assert_eq!(reply.handshake_type, HandshakeType::Induction);
                assert_eq!(reply.srt_socket_id, 42);
                assert_eq!(reply.version, incoming.version);
                assert_eq!(
                    reply.initial_sequence_number,
                    incoming.initial_sequence_number
                );
                assert_eq!(reply.max_transmission_unit, incoming.max_transmission_unit);
                assert_eq!(reply.max_flow_window_size, incoming.max_flow_window_size);
                assert_eq!(reply.encryption_field, 0);
                assert_eq!(reply.extension_field, 0);
            }
            other => panic!("expected Reply, got {other:?}"),
        }
        assert_eq!(s.state(), ConnectionState::AwaitingConclusion);
    }

    #[test]
    fn duplicate_induction_while_awaiting_conclusion_replies_again_without_changing_state() {
        let mut s = session();
        let cookies = CookieGenerator::new();

        let first = test_handshake(HandshakeType::Induction, 0);
        s.on_packet(&first, &cookies);
        assert_eq!(s.state(), ConnectionState::AwaitingConclusion);

        let second = test_handshake(HandshakeType::Induction, 0);
        let action = s.on_packet(&second, &cookies);

        assert!(matches!(action, HandshakeAction::Reply(_)));
        assert_eq!(s.state(), ConnectionState::AwaitingConclusion);
    }

    #[test]
    fn valid_conclusion_establishes_connection() {
        let mut s = session();
        let cookies = CookieGenerator::new();

        let induction = test_handshake(HandshakeType::Induction, 0);
        let cookie = match s.on_packet(&induction, &cookies) {
            HandshakeAction::Reply(reply) => reply.syn_cookie,
            other => panic!("expected Reply, got {other:?}"),
        };

        let conclusion = test_handshake(HandshakeType::Conclusion, cookie);
        let action = s.on_packet(&conclusion, &cookies);

        assert!(matches!(action, HandshakeAction::Established));
        assert_eq!(s.state(), ConnectionState::Connected);
    }

    #[test]
    fn conclusion_with_invalid_cookie_is_rejected() {
        let mut s = session();
        let cookies = CookieGenerator::new();

        let induction = test_handshake(HandshakeType::Induction, 0);
        s.on_packet(&induction, &cookies);

        let bad_conclusion = test_handshake(HandshakeType::Conclusion, 0xDEAD_BEEF);
        let action = s.on_packet(&bad_conclusion, &cookies);

        assert!(matches!(action, HandshakeAction::Reject));
        assert_eq!(s.state(), ConnectionState::AwaitingConclusion);
    }

    #[test]
    fn conclusion_before_induction_is_rejected() {
        let mut s = session();
        let cookies = CookieGenerator::new();

        let conclusion = test_handshake(HandshakeType::Conclusion, 0);
        let action = s.on_packet(&conclusion, &cookies);

        assert!(matches!(action, HandshakeAction::Reject));
        assert_eq!(s.state(), ConnectionState::AwaitingInduction);
    }

    #[test]
    fn any_packet_once_connected_is_rejected() {
        let mut s = session();
        let cookies = CookieGenerator::new();

        let induction = test_handshake(HandshakeType::Induction, 0);
        let cookie = match s.on_packet(&induction, &cookies) {
            HandshakeAction::Reply(reply) => reply.syn_cookie,
            other => panic!("expected Reply, got {other:?}"),
        };
        let conclusion = test_handshake(HandshakeType::Conclusion, cookie);
        s.on_packet(&conclusion, &cookies);
        assert_eq!(s.state(), ConnectionState::Connected);

        let extra = test_handshake(HandshakeType::Induction, 0);
        let action = s.on_packet(&extra, &cookies);
        assert!(matches!(action, HandshakeAction::Reject));
        assert_eq!(s.state(), ConnectionState::Connected);
    }
}
