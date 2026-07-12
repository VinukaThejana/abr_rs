use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Cookie window in seconds. Cookies are valid for this duration after generation.
const COOKIE_WINDOW_SECS: u64 = 60;

/// Generates and verifies cookies for one server instance
pub(crate) struct CookieGenerator {
    secret: u64,
}

impl CookieGenerator {
    /// Creates a new `CookieGenerator` instance with a given secret
    pub(crate) fn with_secret(secret: u64) -> Self {
        Self { secret }
    }

    /// Creates a new `CookieGenerator` instance with a random secret
    pub(crate) fn new() -> Self {
        Self::with_secret(rand::random())
    }

    /// Generates a cookie for a given peer address. The cookie is valid for the current time window.
    pub(crate) fn generate(&self, peer: SocketAddr) -> u32 {
        self.cookie_for(peer, self.current_window())
    }

    /// Checks whether a given `cookie` is a valid cookie for `peer` right now, or was it valid in
    /// the immediately preceding time window
    pub(crate) fn verify(&self, peer: SocketAddr, cookie: u32) -> bool {
        let current_window = self.current_window();
        cookie == self.cookie_for(peer, current_window)
            || cookie == self.cookie_for(peer, current_window.wrapping_sub(1))
    }

    fn current_window(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before UNIX_EPOCH")
            .as_secs();

        now / COOKIE_WINDOW_SECS
    }

    fn cookie_for(&self, peer: SocketAddr, window: u64) -> u32 {
        let mut hasher = DefaultHasher::new();

        self.secret.hash(&mut hasher);
        peer.hash(&mut hasher);
        window.hash(&mut hasher);

        hasher.finish() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    fn peer_v4() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 42), 9000))
    }

    fn peer_v4_other() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000))
    }

    fn peer_v6() -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5000, 0, 0))
    }

    #[test]
    fn generate_is_deterministic_for_same_peer() {
        let cg = CookieGenerator::with_secret(0xDEAD);
        let a = cg.generate(peer_v4());
        let b = cg.generate(peer_v4());
        assert_eq!(
            a, b,
            "same secret + same peer should produce the same cookie"
        );
    }

    #[test]
    fn verify_accepts_freshly_generated_cookie() {
        let cg = CookieGenerator::with_secret(42);
        let cookie = cg.generate(peer_v4());
        assert!(
            cg.verify(peer_v4(), cookie),
            "a cookie should verify immediately after generation"
        );
    }

    #[test]
    fn verify_accepts_cookie_from_previous_window() {
        let cg = CookieGenerator::with_secret(99);
        let window = cg.current_window();
        // Simulate a cookie that was generated one window ago
        let old_cookie = cg.cookie_for(peer_v4(), window.wrapping_sub(1));
        assert!(
            cg.verify(peer_v4(), old_cookie),
            "cookie from the immediately preceding window should still verify"
        );
    }

    #[test]
    fn verify_rejects_arbitrary_cookie() {
        let cg = CookieGenerator::with_secret(42);
        // A random value is astronomically unlikely to collide with a valid cookie
        assert!(
            !cg.verify(peer_v4(), 0x0000_0000),
            "an arbitrary zero cookie should not verify (unless astronomically unlucky)"
        );
    }

    #[test]
    fn verify_rejects_cookie_for_different_peer() {
        let cg = CookieGenerator::with_secret(42);
        let cookie = cg.generate(peer_v4());
        assert!(
            !cg.verify(peer_v4_other(), cookie),
            "a cookie generated for one peer must not verify for a different peer"
        );
    }

    #[test]
    fn verify_rejects_cookie_from_expired_window() {
        let cg = CookieGenerator::with_secret(42);
        let window = cg.current_window();
        // Two windows ago — outside the accepted range (current and current-1)
        let expired_cookie = cg.cookie_for(peer_v4(), window.wrapping_sub(2));
        assert!(
            !cg.verify(peer_v4(), expired_cookie),
            "cookie from two windows ago should be rejected"
        );
    }

    #[test]
    fn different_peers_produce_different_cookies() {
        let cg = CookieGenerator::with_secret(42);
        let c1 = cg.generate(peer_v4());
        let c2 = cg.generate(peer_v4_other());
        assert_ne!(c1, c2, "distinct peers should yield distinct cookies");
    }

    #[test]
    fn different_secrets_produce_different_cookies() {
        let g1 = CookieGenerator::with_secret(1);
        let g2 = CookieGenerator::with_secret(2);
        let c1 = g1.generate(peer_v4());
        let c2 = g2.generate(peer_v4());
        assert_ne!(
            c1, c2,
            "generators with different secrets should produce different cookies"
        );
    }

    #[test]
    fn different_port_produces_different_cookie() {
        let cg = CookieGenerator::with_secret(42);
        let p1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 42), 9000));
        let p2 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 42), 9001));
        assert_ne!(
            cg.generate(p1),
            cg.generate(p2),
            "same IP but different port should produce a different cookie"
        );
    }

    #[test]
    fn generate_and_verify_ipv6_peer() {
        let cg = CookieGenerator::with_secret(0xCAFE);
        let cookie = cg.generate(peer_v6());
        assert!(cg.verify(peer_v6(), cookie));
    }

    #[test]
    fn ipv4_and_ipv6_produce_different_cookies() {
        let cg = CookieGenerator::with_secret(42);
        let c4 = cg.generate(peer_v4());
        let c6 = cg.generate(peer_v6());
        assert_ne!(
            c4, c6,
            "IPv4 and IPv6 peers should produce different cookies"
        );
    }

    #[test]
    fn cookie_does_not_verify_across_generators() {
        let g1 = CookieGenerator::with_secret(1);
        let g2 = CookieGenerator::with_secret(2);
        let cookie = g1.generate(peer_v4());
        assert!(
            !g2.verify(peer_v4(), cookie),
            "a cookie from one generator must not verify on another"
        );
    }

    #[test]
    fn with_secret_stores_secret() {
        let cg = CookieGenerator::with_secret(12345);
        assert_eq!(cg.secret, 12345);
    }

    #[test]
    fn new_produces_working_generator() {
        let cg = CookieGenerator::new();
        let cookie = cg.generate(peer_v4());
        assert!(
            cg.verify(peer_v4(), cookie),
            "generator from new() should produce verifiable cookies"
        );
    }

    #[test]
    fn cookie_for_same_inputs_is_deterministic() {
        let cg = CookieGenerator::with_secret(77);
        let c1 = cg.cookie_for(peer_v4(), 100);
        let c2 = cg.cookie_for(peer_v4(), 100);
        assert_eq!(c1, c2);
    }

    #[test]
    fn cookie_for_different_windows_differ() {
        let cg = CookieGenerator::with_secret(77);
        let c1 = cg.cookie_for(peer_v4(), 100);
        let c2 = cg.cookie_for(peer_v4(), 101);
        assert_ne!(
            c1, c2,
            "different time windows should produce different cookies"
        );
    }

    #[test]
    fn zero_secret_still_functional() {
        let cg = CookieGenerator::with_secret(0);
        let cookie = cg.generate(peer_v4());
        assert!(cg.verify(peer_v4(), cookie));
    }

    #[test]
    fn max_secret_still_functional() {
        let cg = CookieGenerator::with_secret(u64::MAX);
        let cookie = cg.generate(peer_v4());
        assert!(cg.verify(peer_v4(), cookie));
    }
}
