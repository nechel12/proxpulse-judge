//! Ed25519 signatures on /judge answers.
//!
//! Over plain HTTP the checked proxy sees the request (that is what the
//! anonymity test needs) but could also rewrite the answer. The signature
//! covers the body together with the checker's `nonce` and `direct_ip`, so
//! a rewritten or replayed answer fails verification in the checker.

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

/// Prefix of the signed message; bump when its layout changes.
pub const SIGNATURE_CONTEXT: &[u8] = b"proxpulse-judge-v1\n";

#[derive(Clone)]
pub struct Signer {
    key: SigningKey,
    /// Base64 public key, served at /key.
    pub public_key: String,
    /// Short id of the public key, sent with every signature.
    pub key_id: String,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private key.
        f.debug_struct("Signer")
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl Signer {
    /// From `SIGNING_KEY`: 32 random bytes in base64, e.g. from
    /// `openssl rand -base64 32`.
    pub fn from_seed_b64(seed: &str) -> Result<Self, String> {
        let bytes = STANDARD
            .decode(seed.trim())
            .map_err(|_| "SIGNING_KEY is not valid base64".to_string())?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "SIGNING_KEY must be 32 bytes (openssl rand -base64 32)".to_string())?;
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        let digest = Sha256::digest(public);
        let key_id = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            key,
            public_key: STANDARD.encode(public),
            key_id,
        })
    }

    /// Base64 signature of [`message`].
    pub fn sign(&self, nonce: &str, direct_ip: &str, body: &[u8]) -> String {
        STANDARD.encode(self.key.sign(&message(nonce, direct_ip, body)).to_bytes())
    }
}

/// `proxpulse-judge-v1\n<nonce>\n<direct_ip>\n<body>`; absent values are
/// empty strings.
pub fn message(nonce: &str, direct_ip: &str, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        SIGNATURE_CONTEXT.len() + nonce.len() + direct_ip.len() + body.len() + 2,
    );
    m.extend_from_slice(SIGNATURE_CONTEXT);
    m.extend_from_slice(nonce.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(direct_ip.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(body);
    m
}

/// A nonce is 8–64 characters of `[A-Za-z0-9_-]`; anything else is ignored.
pub fn valid_nonce(n: &str) -> bool {
    (8..=64).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    const SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn signs_body_nonce_and_direct_ip() {
        let s = Signer::from_seed_b64(SEED).unwrap();
        let sig = s.sign("nonce1234", "1.2.3.4", b"{\"a\":1}");
        let public: [u8; 32] = STANDARD.decode(&s.public_key).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&public).unwrap();
        let sig = Signature::from_slice(&STANDARD.decode(sig).unwrap()).unwrap();
        assert!(
            vk.verify(&message("nonce1234", "1.2.3.4", b"{\"a\":1}"), &sig)
                .is_ok()
        );
        assert!(
            vk.verify(&message("nonce1234", "5.6.7.8", b"{\"a\":1}"), &sig)
                .is_err()
        );
        assert!(
            vk.verify(&message("nonce1234", "1.2.3.4", b"{\"a\":2}"), &sig)
                .is_err()
        );
        assert_eq!(s.key_id.len(), 8);
        assert!(!format!("{s:?}").contains(SEED));
    }

    /// Shared with the checker's `judge_sig` tests: both sides must agree.
    #[test]
    fn known_vector() {
        let s = Signer::from_seed_b64(SEED).unwrap();
        let sig = s.sign(
            "0123456789abcdef01234567",
            "203.0.113.7",
            b"{\"anonymity\":\"elite\"}",
        );
        assert_eq!(
            sig,
            "bKJP4sGEk2X3TrUbVqV0thXJWq21c5/D/Dg+mP3Tv+BJ6mbj7nJ5r9oOUXwFITETF1oT8/78dJSUh32a964eAA=="
        );
        assert_eq!(s.public_key, "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=");
    }

    #[test]
    fn rejects_bad_keys_and_nonces() {
        assert!(Signer::from_seed_b64("not base64!").is_err());
        assert!(Signer::from_seed_b64("AAEC").is_err());
        assert!(valid_nonce("abcDEF12_-"));
        assert!(!valid_nonce("short"));
        assert!(!valid_nonce("has space 123"));
        assert!(!valid_nonce(&"x".repeat(65)));
    }
}
