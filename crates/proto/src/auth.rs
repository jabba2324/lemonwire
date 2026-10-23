//! Signed messages for the mutual-auth login handshake (spec §3).
//!
//! Every message carries a domain-separation tag and binds both public keys, so a
//! signature made for one index or one step can't be replayed against another.

use crate::keys::{KeyError, KeyPair, PublicKey};

pub const PROTOCOL: &str = "lemonwire-v1";

/// What the server signs in its challenge response.
pub fn server_challenge_message(client_pub: &str, nonce: &str) -> Vec<u8> {
    format!("{PROTOCOL}|server-challenge|{client_pub}|{nonce}").into_bytes()
}

/// What the client signs to log in.
pub fn client_login_message(server_pub: &str, client_pub: &str, nonce: &str) -> Vec<u8> {
    format!("{PROTOCOL}|client-login|{server_pub}|{client_pub}|{nonce}").into_bytes()
}

/// Server side: sign a challenge for `client_pub`.
pub fn sign_challenge(server: &KeyPair, client_pub: &str, nonce: &str) -> String {
    server.sign(&server_challenge_message(client_pub, nonce))
}

/// Client side: check the server's challenge signature against the pinned server key.
pub fn verify_challenge(
    pinned_server: &PublicKey,
    client_pub: &str,
    nonce: &str,
    server_sig: &str,
) -> Result<(), KeyError> {
    pinned_server.verify(&server_challenge_message(client_pub, nonce), server_sig)
}

/// Client side: sign the login message.
pub fn sign_login(client: &KeyPair, server_pub: &str, nonce: &str) -> String {
    let client_pub = client.public().to_b64();
    client.sign(&client_login_message(server_pub, &client_pub, nonce))
}

/// Server side: check a client's login signature.
pub fn verify_login(
    server_pub: &str,
    client: &PublicKey,
    nonce: &str,
    signature: &str,
) -> Result<(), KeyError> {
    client.verify(
        &client_login_message(server_pub, &client.to_b64(), nonce),
        signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Setup {
        server: KeyPair,
        client: KeyPair,
        nonce: String,
    }

    fn setup() -> Setup {
        Setup {
            server: KeyPair::generate().unwrap(),
            client: KeyPair::generate().unwrap(),
            nonce: crate::keys::random_token().unwrap(),
        }
    }

    #[test]
    fn full_handshake() {
        let s = setup();
        let client_pub = s.client.public().to_b64();
        let server_pub = s.server.public().to_b64();

        let server_sig = sign_challenge(&s.server, &client_pub, &s.nonce);
        verify_challenge(&s.server.public(), &client_pub, &s.nonce, &server_sig).unwrap();

        let login_sig = sign_login(&s.client, &server_pub, &s.nonce);
        verify_login(&server_pub, &s.client.public(), &s.nonce, &login_sig).unwrap();
    }

    #[test]
    fn challenge_from_wrong_server_rejected() {
        let s = setup();
        let impostor = KeyPair::generate().unwrap();
        let client_pub = s.client.public().to_b64();
        let sig = sign_challenge(&impostor, &client_pub, &s.nonce);
        assert!(verify_challenge(&s.server.public(), &client_pub, &s.nonce, &sig).is_err());
    }

    #[test]
    fn challenge_for_other_client_rejected() {
        let s = setup();
        let other = KeyPair::generate().unwrap().public().to_b64();
        let sig = sign_challenge(&s.server, &other, &s.nonce);
        let client_pub = s.client.public().to_b64();
        assert!(verify_challenge(&s.server.public(), &client_pub, &s.nonce, &sig).is_err());
    }

    #[test]
    fn login_for_other_server_rejected() {
        let s = setup();
        let other_server = KeyPair::generate().unwrap().public().to_b64();
        let server_pub = s.server.public().to_b64();
        let sig = sign_login(&s.client, &other_server, &s.nonce);
        assert!(verify_login(&server_pub, &s.client.public(), &s.nonce, &sig).is_err());
    }

    #[test]
    fn login_with_wrong_nonce_rejected() {
        let s = setup();
        let server_pub = s.server.public().to_b64();
        let sig = sign_login(&s.client, &server_pub, &s.nonce);
        let other_nonce = crate::keys::random_token().unwrap();
        assert!(verify_login(&server_pub, &s.client.public(), &other_nonce, &sig).is_err());
    }

    #[test]
    fn challenge_signature_is_not_a_login_signature() {
        // Domain separation: a server challenge signature can't be reused as a login.
        let s = setup();
        let server_pub = s.server.public().to_b64();
        let client_pub = s.client.public().to_b64();
        let sig = sign_challenge(&s.client, &client_pub, &s.nonce);
        assert!(verify_login(&server_pub, &s.client.public(), &s.nonce, &sig).is_err());
    }
}
