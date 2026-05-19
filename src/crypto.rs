use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, SomaError> {
    let key_bytes: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| SomaError::InvalidKey("secret key must be 32 bytes".into()))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let sig = signing_key.sign(message);
    Ok(sig.to_bytes().to_vec())
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, SomaError> {
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SomaError::InvalidKey("public key must be 32 bytes".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| SomaError::InvalidKey(e.to_string()))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| SomaError::InvalidSignature("signature must be 64 bytes".into()))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    Ok(verifying_key.verify(message, &sig).is_ok())
}

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let public_key = signing_key.verifying_key();
    (signing_key.to_bytes().to_vec(), public_key.to_bytes().to_vec())
}

pub fn encode_base64(data: &[u8]) -> String {
    BASE64.encode(data)
}

pub fn decode_base64(s: &str) -> Result<Vec<u8>, SomaError> {
    BASE64.decode(s).map_err(|e| SomaError::InvalidEncoding(e.to_string()))
}

use crate::SomaError;
