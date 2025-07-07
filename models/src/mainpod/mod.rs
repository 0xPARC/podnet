//! MainPod operations for PodNet
//!
//! This module provides consolidated prove and verify functions for all MainPod types
//! used in PodNet, eliminating code duplication and providing consistent interfaces.

pub mod publish;
pub mod upvote;
pub mod upvote_count;

use pod_utils::ValueExt;
use pod2::frontend::{MainPod, SignedPod};
use pod2::middleware::{Hash, KEY_SIGNER, Value};
use std::error::Error;

/// Common error type for MainPod operations
#[derive(Debug)]
pub enum MainPodError {
    MissingField {
        pod_type: &'static str,
        field: &'static str,
    },
    InvalidValue {
        field: &'static str,
        expected: String,
    },
    ProofGeneration(String),
    Verification(String),
    InvalidSet {
        field: &'static str,
    },
}

impl std::fmt::Display for MainPodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MainPodError::MissingField { pod_type, field } => {
                write!(f, "{} pod missing required field: {}", pod_type, field)
            }
            MainPodError::InvalidValue { field, expected } => {
                write!(
                    f,
                    "Invalid value for field {}: expected {}",
                    field, expected
                )
            }
            MainPodError::ProofGeneration(msg) => {
                write!(f, "Proof generation failed: {}", msg)
            }
            MainPodError::Verification(msg) => {
                write!(f, "Verification failed: {}", msg)
            }
            MainPodError::InvalidSet { field } => {
                write!(f, "Invalid set for field: {}", field)
            }
        }
    }
}

impl Error for MainPodError {}

/// Result type for MainPod operations
pub type MainPodResult<T> = Result<T, MainPodError>;

/// Extract username from identity pod
pub fn extract_username(identity_pod: &SignedPod) -> MainPodResult<&str> {
    identity_pod
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or(MainPodError::MissingField {
            pod_type: "Identity",
            field: "username",
        })
}

/// Extract user public key from identity pod
pub fn extract_user_public_key(identity_pod: &SignedPod) -> MainPodResult<Value> {
    identity_pod
        .get("user_public_key")
        .cloned()
        .ok_or(MainPodError::MissingField {
            pod_type: "Identity",
            field: "user_public_key",
        })
}

/// Extract identity server public key from identity pod
pub fn extract_identity_server_public_key(identity_pod: &SignedPod) -> MainPodResult<Value> {
    identity_pod
        .get(KEY_SIGNER)
        .cloned()
        .ok_or(MainPodError::MissingField {
            pod_type: "Identity",
            field: KEY_SIGNER,
        })
}

/// Extract content hash from document or upvote pod
pub fn extract_content_hash(pod: &SignedPod, pod_type: &'static str) -> MainPodResult<Hash> {
    pod.get("content_hash")
        .and_then(|v| v.as_hash())
        .ok_or(MainPodError::MissingField {
            pod_type,
            field: "content_hash",
        })
}

/// Extract post ID from document or upvote pod
pub fn extract_post_id(pod: &SignedPod, pod_type: &'static str) -> MainPodResult<Value> {
    pod.get("post_id")
        .cloned()
        .ok_or(MainPodError::MissingField {
            pod_type,
            field: "post_id",
        })
}

pub fn extract_tags(pod: &SignedPod, pod_type: &'static str) -> MainPodResult<Value> {
    pod.get("tags").cloned().ok_or(MainPodError::MissingField {
        pod_type,
        field: "tags",
    })
}

/// Verify basic MainPod structure and signature
pub fn verify_mainpod_basics(main_pod: &MainPod) -> MainPodResult<()> {
    main_pod.pod.verify().map_err(|e| {
        MainPodError::Verification(format!("MainPod signature verification failed: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Add unit tests for the utility functions here
}

