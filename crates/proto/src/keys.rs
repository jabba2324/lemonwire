//! Ed25519 key pairs, encoded as URL-safe base64 without padding.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("not valid base64")]
    Base64,
    #[error("wrong length: expected {expected} bytes, got {got}")]
    Length { expected: usize, got: usize },
    #[error("not a valid Ed25519 public key")]
    InvalidPoint,
    #[error("bad signature")]
    BadSignature,
    #[error("system random number generator failed")]
    Rng,
}

pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, KeyError> {
    URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|_| KeyError::Base64)
}

fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], KeyError> {
    let v = b64_decode(s)?;
    v.as_slice().try_into().map_err(|_| KeyError::Length {
        expected: N,
        got: v.len(),
    })
}

/// `n` bytes from the OS random number generator.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], KeyError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| KeyError::Rng)?;
    Ok(buf)
}

/// A random 32-byte value as base64: used for nonces, session tokens, invites and passkeys.
pub fn random_token() -> Result<String, KeyError> {
    Ok(b64_encode(&random_bytes::<32>()?))
}

/// A public key. Parsing checks that it is a valid curve point.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn from_b64(s: &str) -> Result<Self, KeyError> {
        let bytes = decode_fixed::<32>(s)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::InvalidPoint)?;
        // Reject small-order points (e.g. the identity), which can't be a real key.
        if key.is_weak() {
            return Err(KeyError::InvalidPoint);
        }
        Ok(Self(key))
    }

    pub fn to_b64(&self) -> String {
        b64_encode(self.0.as_bytes())
    }

    /// Short, human-comparable fingerprint: first 10 bytes of sha256(base64 key),
    /// as hex in groups of four, e.g. `a1b2:c3d4:e5f6:0718:293a`.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.to_b64())
    }

    pub fn verify(&self, message: &[u8], signature_b64: &str) -> Result<(), KeyError> {
        let sig = decode_fixed::<64>(signature_b64).map_err(|_| KeyError::BadSignature)?;
        let sig = Signature::from_bytes(&sig);
        self.0
            .verify(message, &sig)
            .map_err(|_| KeyError::BadSignature)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", self.to_b64())
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_b64())
    }
}

/// Fingerprint of a base64 public key string (see [`PublicKey::fingerprint`]).
pub fn fingerprint(pubkey_b64: &str) -> String {
    let digest = Sha256::digest(pubkey_b64.as_bytes());
    let hex = hex::encode(&digest[..10]);
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("hex is ascii"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A secret key. Debug output never shows the key material.
#[derive(Clone)]
pub struct KeyPair(SigningKey);

impl KeyPair {
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self(SigningKey::from_bytes(&random_bytes::<32>()?)))
    }

    pub fn from_secret_b64(s: &str) -> Result<Self, KeyError> {
        Ok(Self(SigningKey::from_bytes(&decode_fixed::<32>(s)?)))
    }

    pub fn secret_b64(&self) -> String {
        b64_encode(self.0.as_bytes())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> String {
        b64_encode(&self.0.sign(message).to_bytes())
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyPair(public={}, secret=<redacted>)", self.public())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_sign() {
        let kp = KeyPair::generate().unwrap();
        let again = KeyPair::from_secret_b64(&kp.secret_b64()).unwrap();
        assert_eq!(kp.public(), again.public());
        let pk = PublicKey::from_b64(&kp.public().to_b64()).unwrap();
        let sig = kp.sign(b"hello");
        assert!(pk.verify(b"hello", &sig).is_ok());
        assert_eq!(pk.verify(b"hellp", &sig), Err(KeyError::BadSignature));
        assert_eq!(pk.verify(b"hello", "AAAA"), Err(KeyError::BadSignature));
    }

    #[test]
    fn rejects_bad_public_keys() {
        assert_eq!(PublicKey::from_b64("!!"), Err(KeyError::Base64));
        assert!(matches!(
            PublicKey::from_b64(&b64_encode(&[1u8; 31])),
            Err(KeyError::Length { .. })
        ));
        // The identity point is a valid encoding but a weak key.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            PublicKey::from_b64(&b64_encode(&identity)),
            Err(KeyError::InvalidPoint)
        );
    }

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint("abc");
        assert_eq!(fp.len(), 24);
        assert_eq!(fp.split(':').count(), 5);
        assert_eq!(fp, fingerprint("abc"));
        assert_ne!(fp, fingerprint("abd"));
    }

    #[test]
    fn debug_hides_secret() {
        let kp = KeyPair::generate().unwrap();
        assert!(!format!("{kp:?}").contains(&kp.secret_b64()));
    }
}
