//! Soma protocol primitives for Rust.
//!
//! Port of the core Soma heart primitives (Ed25519 identity, delegation,
//! heartbeats, spend tracking) from the canonical TypeScript implementation.
//! Used by Cortex and other HeyVera agents that need Soma integration
//! without running a Node.js sidecar.

pub mod base58;
pub mod crypto;
pub mod delegation;
pub mod did;
pub mod heartbeat;
pub mod identity;
pub mod lineage;
pub mod spend;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SomaError {
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("invalid DID: {0}")]
    InvalidDid(String),
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("delegation error: {0}")]
    Delegation(String),
    #[error("verification failed: {0}")]
    Verification(String),
}
