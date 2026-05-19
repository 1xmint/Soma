use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::{decode_base64, encode_base64, generate_keypair, sha256_hex, sign};
use crate::did::public_key_to_did;
use crate::heartbeat::HeartbeatChain;
use crate::SomaError;

/// Genome — identity commitment for an agent heart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Genome {
    pub model_provider: String,
    pub model_id: String,
    pub runtime_id: String,
    pub created_at: u64,
    pub version: u32,
}

/// A signed genome commitment — binds an identity to a keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenomeCommitment {
    pub genome: Genome,
    pub hash: String,
    pub signature: String,
    pub public_key: String,
    pub did: String,
}

/// A Soma heart identity — keypair + genome + heartbeat chain.
pub struct HeartIdentity {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub did: String,
    pub genome: GenomeCommitment,
    pub heartbeat_chain: HeartbeatChain,
}

impl HeartIdentity {
    /// Create a new heart identity for an agent.
    pub fn new(model_provider: &str, model_id: &str, runtime_id: &str) -> Result<Self, SomaError> {
        let (sk, pk) = generate_keypair();
        let did = public_key_to_did(&pk);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let genome = Genome {
            model_provider: model_provider.to_string(),
            model_id: model_id.to_string(),
            runtime_id: runtime_id.to_string(),
            created_at: now,
            version: 1,
        };

        let canonical = serde_json::to_string(&genome)
            .map_err(|e| SomaError::Serialization(e.to_string()))?;
        let hash = sha256_hex(&canonical);
        let sig_input = format!("soma/genome/v1:{canonical}");
        let sig = sign(&sk, sig_input.as_bytes())?;

        let commitment = GenomeCommitment {
            genome,
            hash,
            signature: encode_base64(&sig),
            public_key: encode_base64(&pk),
            did: did.clone(),
        };

        Ok(Self {
            secret_key: sk,
            public_key: pk,
            did,
            genome: commitment,
            heartbeat_chain: HeartbeatChain::new(),
        })
    }

    /// Load an existing identity from stored keys.
    pub fn from_keys(
        secret_key: Vec<u8>,
        public_key: Vec<u8>,
        genome: GenomeCommitment,
    ) -> Self {
        let did = public_key_to_did(&public_key);
        Self {
            secret_key,
            public_key,
            did,
            genome,
            heartbeat_chain: HeartbeatChain::new(),
        }
    }

    /// Save the identity to a JSON file. The secret key is stored as base64.
    pub fn save(&self, path: &Path) -> Result<(), SomaError> {
        let state = PersistedIdentity {
            secret_key: encode_base64(&self.secret_key),
            public_key: encode_base64(&self.public_key),
            genome: self.genome.clone(),
        };
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| SomaError::Serialization(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SomaError::Serialization(format!("mkdir failed: {e}")))?;
        }
        std::fs::write(path, json)
            .map_err(|e| SomaError::Serialization(format!("write failed: {e}")))?;
        Ok(())
    }

    /// Load an identity from a JSON file persisted by `save()`.
    pub fn load(path: &Path) -> Result<Self, SomaError> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| SomaError::Serialization(format!("read failed: {e}")))?;
        let state: PersistedIdentity = serde_json::from_str(&json)
            .map_err(|e| SomaError::Serialization(format!("parse failed: {e}")))?;
        let sk = decode_base64(&state.secret_key)?;
        let pk = decode_base64(&state.public_key)?;
        Ok(Self::from_keys(sk, pk, state.genome))
    }

    /// Load from file if it exists, otherwise create new and save.
    pub fn load_or_create(
        path: &Path,
        model_provider: &str,
        model_id: &str,
        runtime_id: &str,
    ) -> Result<Self, SomaError> {
        if path.exists() {
            Self::load(path)
        } else {
            let identity = Self::new(model_provider, model_id, runtime_id)?;
            identity.save(path)?;
            Ok(identity)
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedIdentity {
    secret_key: String,
    public_key: String,
    genome: GenomeCommitment,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_heart_identity() {
        let heart = HeartIdentity::new("heyvera", "cortex-router", "cortex-v0.1").unwrap();
        assert!(heart.did.starts_with("did:key:z"));
        assert!(!heart.genome.hash.is_empty());
        assert!(!heart.genome.signature.is_empty());
    }
}
