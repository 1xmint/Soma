use serde::{Deserialize, Serialize};

use crate::crypto::{decode_base64, encode_base64, sha256_hex, sign, verify};
use crate::SomaError;

/// A caveat constraining a delegation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind")]
pub enum Caveat {
    #[serde(rename = "expires-at")]
    ExpiresAt { timestamp: u64 },
    #[serde(rename = "not-before")]
    NotBefore { timestamp: u64 },
    #[serde(rename = "audience")]
    Audience { did: String },
    #[serde(rename = "budget")]
    Budget { credits: f64 },
    #[serde(rename = "max-invocations")]
    MaxInvocations { count: u64 },
    #[serde(rename = "capabilities")]
    Capabilities { allow: Vec<String> },
    #[serde(rename = "host-allowlist")]
    HostAllowlist { hosts: Vec<String> },
    #[serde(rename = "custom")]
    Custom { key: String, value: String },
}

/// A signed delegation token — macaroons-style capability token with caveats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub capabilities: Vec<String>,
    pub caveats: Vec<Caveat>,
    pub issued_at: u64,
    pub nonce: String,
    pub parent_id: Option<String>,
    pub signature: String,
    pub issuer_public_key: String,
}

/// Context for verifying a delegation at invocation time.
#[derive(Debug, Clone, Default)]
pub struct InvocationContext {
    pub invoker_did: String,
    pub audience_did: Option<String>,
    pub capability: String,
    pub credits_spent: Option<f64>,
    pub cumulative_credits_spent: Option<f64>,
    pub invocation_count: Option<u64>,
    pub now: Option<u64>,
    pub host: Option<String>,
}

#[derive(Debug)]
pub enum DelegationVerification {
    Valid,
    Invalid { reason: String },
}

impl DelegationVerification {
    pub fn is_valid(&self) -> bool {
        matches!(self, DelegationVerification::Valid)
    }
}

fn canonical_delegation(d: &Delegation) -> String {
    serde_json::json!({
        "id": d.id,
        "issuerDid": d.issuer_did,
        "subjectDid": d.subject_did,
        "capabilities": d.capabilities,
        "caveats": d.caveats,
        "issuedAt": d.issued_at,
        "nonce": d.nonce,
        "parentId": d.parent_id,
    })
    .to_string()
}

fn signing_input(domain: &str, payload: &str) -> Vec<u8> {
    format!("{domain}:{payload}").into_bytes()
}

const DELEGATION_DOMAIN: &str = "soma/delegation/v1";

/// Create a new delegation token signed by the issuer.
pub fn create_delegation(
    issuer_secret_key: &[u8],
    issuer_public_key: &[u8],
    issuer_did: &str,
    subject_did: &str,
    capabilities: Vec<String>,
    caveats: Vec<Caveat>,
    parent_id: Option<String>,
) -> Result<Delegation, SomaError> {
    let nonce = hex::encode(crate::crypto::random_bytes(16));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let id = format!(
        "dlg_{}",
        &sha256_hex(&format!("{issuer_did}:{subject_did}:{nonce}:{now}"))[..16]
    );

    let mut delegation = Delegation {
        id,
        issuer_did: issuer_did.to_string(),
        subject_did: subject_did.to_string(),
        capabilities,
        caveats,
        issued_at: now,
        nonce,
        parent_id,
        signature: String::new(),
        issuer_public_key: encode_base64(issuer_public_key),
    };

    let canonical = canonical_delegation(&delegation);
    let input = signing_input(DELEGATION_DOMAIN, &canonical);
    let sig = sign(issuer_secret_key, &input)?;
    delegation.signature = encode_base64(&sig);

    Ok(delegation)
}

/// Verify a delegation's signature.
pub fn verify_delegation_signature(d: &Delegation) -> Result<bool, SomaError> {
    let pk = decode_base64(&d.issuer_public_key)?;
    let canonical = canonical_delegation(d);
    let input = signing_input(DELEGATION_DOMAIN, &canonical);
    let sig = decode_base64(&d.signature)?;
    verify(&pk, &input, &sig)
}

/// Check all caveats against an invocation context.
pub fn check_caveats(caveats: &[Caveat], ctx: &InvocationContext) -> DelegationVerification {
    let now = ctx.now.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    });

    for caveat in caveats {
        match caveat {
            Caveat::ExpiresAt { timestamp } => {
                if now > *timestamp {
                    return DelegationVerification::Invalid {
                        reason: format!("delegation expired at {timestamp}"),
                    };
                }
            }
            Caveat::NotBefore { timestamp } => {
                if now < *timestamp {
                    return DelegationVerification::Invalid {
                        reason: format!("delegation not yet valid (not-before {timestamp})"),
                    };
                }
            }
            Caveat::Audience { did } => {
                if let Some(ref audience) = ctx.audience_did {
                    if audience != did {
                        return DelegationVerification::Invalid {
                            reason: format!("audience mismatch: expected {did}, got {audience}"),
                        };
                    }
                } else {
                    return DelegationVerification::Invalid {
                        reason: "audience caveat present but no audience_did in context".into(),
                    };
                }
            }
            Caveat::Budget { credits } => {
                if let Some(cumulative) = ctx.cumulative_credits_spent {
                    if cumulative > *credits {
                        return DelegationVerification::Invalid {
                            reason: format!(
                                "budget exceeded: spent {cumulative}, cap {credits}"
                            ),
                        };
                    }
                }
            }
            Caveat::MaxInvocations { count } => {
                if let Some(invocations) = ctx.invocation_count {
                    if invocations >= *count {
                        return DelegationVerification::Invalid {
                            reason: format!(
                                "max invocations exceeded: {invocations} >= {count}"
                            ),
                        };
                    }
                }
            }
            Caveat::Capabilities { allow } => {
                if !capability_matches(&ctx.capability, allow) {
                    return DelegationVerification::Invalid {
                        reason: format!(
                            "capability '{}' not in allowed set: {:?}",
                            ctx.capability, allow
                        ),
                    };
                }
            }
            Caveat::HostAllowlist { hosts } => {
                if let Some(ref host) = ctx.host {
                    if !hosts.contains(host) {
                        return DelegationVerification::Invalid {
                            reason: format!("host '{host}' not in allowlist"),
                        };
                    }
                } else {
                    return DelegationVerification::Invalid {
                        reason: "host-allowlist caveat present but no host in context".into(),
                    };
                }
            }
            Caveat::Custom { .. } => {
                // Custom caveats require application-specific evaluation
            }
        }
    }

    DelegationVerification::Valid
}

/// Check if a capability string matches any in the allowed list.
/// Supports wildcard matching: "route:*" matches "route:select", "route:execute", etc.
fn capability_matches(capability: &str, allowed: &[String]) -> bool {
    for pattern in allowed {
        if pattern == capability {
            return true;
        }
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix(":*") {
            if capability.starts_with(prefix) && capability[prefix.len()..].starts_with(':') {
                return true;
            }
            if capability == prefix {
                return true;
            }
        }
    }
    false
}

/// Full delegation verification: signature + caveats + subject binding.
pub fn verify_delegation(
    d: &Delegation,
    ctx: &InvocationContext,
) -> Result<DelegationVerification, SomaError> {
    // 1. Verify signature
    if !verify_delegation_signature(d)? {
        return Ok(DelegationVerification::Invalid {
            reason: "invalid signature".into(),
        });
    }

    // 2. Check issuer DID matches the public key
    let pk = decode_base64(&d.issuer_public_key)?;
    let expected_did = crate::did::public_key_to_did(&pk);
    if d.issuer_did != expected_did {
        return Ok(DelegationVerification::Invalid {
            reason: format!(
                "issuer DID mismatch: claimed {}, key resolves to {}",
                d.issuer_did, expected_did
            ),
        });
    }

    // 3. Check subject binding
    if ctx.invoker_did != d.subject_did {
        return Ok(DelegationVerification::Invalid {
            reason: format!(
                "invoker DID mismatch: {} is not the subject {}",
                ctx.invoker_did, d.subject_did
            ),
        });
    }

    // 4. Check caveats
    Ok(check_caveats(&d.caveats, ctx))
}

/// Verify a chain of delegations (each attenuates the previous).
pub fn verify_delegation_chain(
    chain: &[Delegation],
    ctx: &InvocationContext,
) -> Result<DelegationVerification, SomaError> {
    if chain.is_empty() {
        return Ok(DelegationVerification::Invalid {
            reason: "empty delegation chain".into(),
        });
    }

    // Verify each link
    for (i, d) in chain.iter().enumerate() {
        if !verify_delegation_signature(d)? {
            return Ok(DelegationVerification::Invalid {
                reason: format!("invalid signature at chain position {i}"),
            });
        }

        // Check parent linkage (except root)
        if i > 0 {
            let parent = &chain[i - 1];
            if d.parent_id.as_deref() != Some(&parent.id) {
                return Ok(DelegationVerification::Invalid {
                    reason: format!("broken chain at position {i}: parent_id mismatch"),
                });
            }
            if d.issuer_did != parent.subject_did {
                return Ok(DelegationVerification::Invalid {
                    reason: format!(
                        "broken chain at position {i}: issuer must be previous subject"
                    ),
                });
            }
        }
    }

    // Verify the leaf delegation against the invocation context
    let leaf = chain.last().unwrap();
    verify_delegation(leaf, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use crate::did::public_key_to_did;

    #[test]
    fn create_and_verify_delegation() {
        let (sk, pk) = generate_keypair();
        let (_, subject_pk) = generate_keypair();
        let issuer_did = public_key_to_did(&pk);
        let subject_did = public_key_to_did(&subject_pk);

        let d = create_delegation(
            &sk,
            &pk,
            &issuer_did,
            &subject_did,
            vec!["route:*".into()],
            vec![Caveat::Budget { credits: 100.0 }],
            None,
        )
        .unwrap();

        assert!(verify_delegation_signature(&d).unwrap());

        let ctx = InvocationContext {
            invoker_did: subject_did,
            capability: "route:select".into(),
            ..Default::default()
        };
        let result = verify_delegation(&d, &ctx).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn capability_wildcard_matching() {
        assert!(capability_matches("route:select", &["route:*".into()]));
        assert!(capability_matches("route:execute", &["route:*".into()]));
        assert!(!capability_matches("model:call", &["route:*".into()]));
        assert!(capability_matches("anything", &["*".into()]));
    }

    #[test]
    fn expired_delegation_rejected() {
        let (sk, pk) = generate_keypair();
        let (_, subject_pk) = generate_keypair();
        let issuer_did = public_key_to_did(&pk);
        let subject_did = public_key_to_did(&subject_pk);

        let d = create_delegation(
            &sk,
            &pk,
            &issuer_did,
            &subject_did,
            vec!["route:*".into()],
            vec![Caveat::ExpiresAt { timestamp: 1000 }],
            None,
        )
        .unwrap();

        let ctx = InvocationContext {
            invoker_did: subject_did,
            capability: "route:select".into(),
            now: Some(2000),
            ..Default::default()
        };
        let result = verify_delegation(&d, &ctx).unwrap();
        assert!(!result.is_valid());
    }
}
