use serde::{Deserialize, Serialize};

use crate::crypto::sha256_hex;

/// Types of events recorded in the heartbeat chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatEventType {
    SessionStart,
    QueryReceived,
    SeedGenerated,
    ModelCallStart,
    ModelCallEnd,
    ToolCall,
    ToolResult,
    DataFetch,
    DataReceived,
    ResponseSent,
    BirthCertificate,
    ReasoningStep,
    Retry,
    RagLookup,
    ToolProgress,
    ForkCreated,
    SubtaskDispatch,
    SubtaskReturn,
    DelegationIssued,
    DelegationRevoked,
    // Cortex-specific events
    RouteSelected,
    RouteCompleted,
    RouteFailed,
    BanditUpdate,
    EvidenceCollected,
    AutonomyDecision,
}

/// A single heartbeat — one link in the hash chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub sequence: u64,
    pub previous_hash: String,
    pub event_type: HeartbeatEventType,
    pub event_hash: String,
    pub timestamp: u64,
    pub hash: String,
}

/// A tamper-evident hash chain recording every computational step.
#[derive(Serialize, Deserialize)]
pub struct HeartbeatChain {
    chain: Vec<Heartbeat>,
    current_hash: String,
    sequence: u64,
}

impl HeartbeatChain {
    pub fn new() -> Self {
        let genesis = sha256_hex("soma:genesis");
        Self {
            chain: Vec::new(),
            current_hash: genesis,
            sequence: 0,
        }
    }

    /// Record a new heartbeat event. Returns the heartbeat for transmission.
    pub fn record(&mut self, event_type: HeartbeatEventType, event_data: &str) -> Heartbeat {
        let event_hash = sha256_hex(event_data);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let hash_input = format!(
            "{}:{}:{:?}:{}:{}",
            self.sequence, self.current_hash, event_type, event_hash, timestamp
        );
        let hash = sha256_hex(&hash_input);

        let heartbeat = Heartbeat {
            sequence: self.sequence,
            previous_hash: self.current_hash.clone(),
            event_type,
            event_hash,
            timestamp,
            hash: hash.clone(),
        };

        self.current_hash = hash;
        self.sequence += 1;
        self.chain.push(heartbeat.clone());
        heartbeat
    }

    pub fn from_persisted(chain: Vec<Heartbeat>) -> Self {
        let (current_hash, sequence) = if let Some(last) = chain.last() {
            (last.hash.clone(), last.sequence + 1)
        } else {
            (sha256_hex("soma:genesis"), 0)
        };
        Self {
            chain,
            current_hash,
            sequence,
        }
    }

    pub fn head_hash(&self) -> &str {
        &self.current_hash
    }

    pub fn len(&self) -> usize {
        self.chain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    pub fn chain(&self) -> &[Heartbeat] {
        &self.chain
    }

    /// Verify the integrity of the entire chain.
    pub fn verify(&self) -> bool {
        let genesis = sha256_hex("soma:genesis");
        let mut expected_prev = genesis;

        for (i, hb) in self.chain.iter().enumerate() {
            if hb.sequence != i as u64 {
                return false;
            }
            if hb.previous_hash != expected_prev {
                return false;
            }
            let hash_input = format!(
                "{}:{}:{:?}:{}:{}",
                hb.sequence, hb.previous_hash, hb.event_type, hb.event_hash, hb.timestamp
            );
            let expected_hash = sha256_hex(&hash_input);
            if hb.hash != expected_hash {
                return false;
            }
            expected_prev = hb.hash.clone();
        }
        true
    }
}

impl Default for HeartbeatChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_integrity() {
        let mut chain = HeartbeatChain::new();
        chain.record(HeartbeatEventType::SessionStart, "test session");
        chain.record(HeartbeatEventType::RouteSelected, r#"{"provider":"claude"}"#);
        chain.record(HeartbeatEventType::RouteCompleted, r#"{"success":true}"#);

        assert_eq!(chain.len(), 3);
        assert!(chain.verify());
    }

    #[test]
    fn tampered_chain_detected() {
        let mut chain = HeartbeatChain::new();
        chain.record(HeartbeatEventType::SessionStart, "test");
        chain.record(HeartbeatEventType::RouteSelected, "route");

        // Tamper with a heartbeat
        chain.chain[0].event_hash = "tampered".into();
        assert!(!chain.verify());
    }
}
