//! Publish verification MainPod operations

use super::{
    MainPodError, MainPodResult, extract_post_id, extract_tags, extract_user_public_key,
    extract_username, verify_mainpod_basics,
};
use crate::get_publish_verification_predicate;
use pod_utils::ValueExt;
use pod_utils::prover_setup::PodNetProverSetup;
use pod2::frontend::{MainPod, MainPodBuilder, SignedPod};
use pod2::lang::parse;
use pod2::middleware::{Hash, KEY_SIGNER, KEY_TYPE, PodType, Statement, Value, containers::Set};
use pod2::op;

use std::collections::HashSet;

/// Parameters for publish verification proof generation
pub struct PublishProofParams<'a> {
    pub identity_pod: &'a SignedPod,
    pub document_pod: &'a SignedPod,
    pub identity_server_public_key: Value,
    pub content_hash: &'a Hash,
    pub use_mock_proofs: bool,
}

/// Generate a publish verification MainPod
///
/// This creates a MainPod that cryptographically proves:
/// - Identity pod was signed by a registered identity server
/// - Document pod was signed by the user from the identity pod
/// - Cross-verification between identity and document signers
/// - Content hash verification
pub fn prove_publish_verification(params: PublishProofParams) -> MainPodResult<MainPod> {
    let pod_params = PodNetProverSetup::get_params();
    let (vd_set, prover) = PodNetProverSetup::create_prover_setup(params.use_mock_proofs)
        .map_err(MainPodError::ProofGeneration)?;

    // Extract required values from pods
    let username = extract_username(params.identity_pod)?;
    let user_public_key = extract_user_public_key(params.identity_pod)?;
    let post_id = extract_post_id(params.document_pod, "Document")?;
    let tags = extract_tags(params.document_pod, "Document")?;

    // Parse predicates
    let predicate_input = get_publish_verification_predicate();
    let batch = parse(&predicate_input, &pod_params, &[])
        .map_err(|e| MainPodError::ProofGeneration(format!("Predicate parsing failed: {e}")))?
        .custom_batch;

    let identity_verified_pred = batch
        .predicate_ref_by_name("identity_verified")
        .ok_or_else(|| {
            MainPodError::ProofGeneration("Missing identity_verified predicate".to_string())
        })?;
    let document_verified_pred = batch
        .predicate_ref_by_name("document_verified")
        .ok_or_else(|| {
            MainPodError::ProofGeneration("Missing document_verified predicate".to_string())
        })?;
    let publish_verification_pred = batch
        .predicate_ref_by_name("publish_verification")
        .ok_or_else(|| {
            MainPodError::ProofGeneration("Missing publish_verification predicate".to_string())
        })?;

    // Step 1: Build identity verification main pod
    let mut identity_builder = MainPodBuilder::new(&pod_params, vd_set);
    identity_builder.add_signed_pod(params.identity_pod);

    let identity_type_check = identity_builder
        .priv_op(op!(eq, (params.identity_pod, KEY_TYPE), PodType::Signed))
        .map_err(|e| MainPodError::ProofGeneration(format!("Identity type check failed: {e}")))?;
    let _identity_signer_check = identity_builder
        .priv_op(op!(
            eq,
            (params.identity_pod, KEY_SIGNER),
            params.identity_server_public_key.clone()
        ))
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Identity signer check failed: {e}"))
        })?;
    let identity_username_check = identity_builder
        .priv_op(op!(eq, (params.identity_pod, "username"), username))
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Identity username check failed: {e}"))
        })?;

    let identity_verification = identity_builder
        .pub_op(op!(
            custom,
            identity_verified_pred,
            identity_type_check,
            identity_username_check
        ))
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Identity verification statement failed: {e}"))
        })?;

    let identity_main_pod = identity_builder
        .prove(prover.as_ref(), &pod_params)
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Identity proof generation failed: {e}"))
        })?;

    identity_main_pod.pod.verify().map_err(|e| {
        MainPodError::ProofGeneration(format!("Identity proof verification failed: {e}"))
    })?;

    // Step 2: Build document verification main pod
    let mut document_builder = MainPodBuilder::new(&pod_params, vd_set);
    document_builder.add_signed_pod(params.document_pod);

    let document_type_check = document_builder
        .priv_op(op!(eq, (params.document_pod, KEY_TYPE), PodType::Signed))
        .map_err(|e| MainPodError::ProofGeneration(format!("Document type check failed: {e}")))?;
    let _document_signer_check = document_builder
        .priv_op(op!(eq, (params.document_pod, KEY_SIGNER), user_public_key))
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Document signer check failed: {e}"))
        })?;
    let document_content_check = document_builder
        .priv_op(op!(
            eq,
            (params.document_pod, "content_hash"),
            *params.content_hash
        ))
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Document content check failed: {e}"))
        })?;
    let document_tags_check = document_builder
        .priv_op(op!(eq, (params.document_pod, "tags"), tags))
        .map_err(|e| MainPodError::ProofGeneration(format!("Document tags check failed: {e}")))?;
    let document_post_id_check = document_builder
        .priv_op(op!(eq, (params.document_pod, "post_id"), post_id))
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Document post ID check failed: {e}"))
        })?;

    let document_verification = document_builder
        .pub_op(op!(
            custom,
            document_verified_pred,
            document_type_check,
            document_content_check,
            document_tags_check,
            document_post_id_check
        ))
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Document verification statement failed: {e}"))
        })?;

    let document_main_pod = document_builder
        .prove(prover.as_ref(), &pod_params)
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Document proof generation failed: {e}"))
        })?;

    document_main_pod.pod.verify().map_err(|e| {
        MainPodError::ProofGeneration(format!("Document proof verification failed: {e}"))
    })?;

    // Step 3: Build final publish verification main pod
    let mut final_builder = MainPodBuilder::new(&pod_params, vd_set);
    final_builder.add_recursive_pod(identity_main_pod);
    final_builder.add_recursive_pod(document_main_pod);
    final_builder.add_signed_pod(params.identity_pod);
    final_builder.add_signed_pod(params.document_pod);

    let identity_server_pk_check = final_builder
        .priv_op(op!(
            eq,
            (params.identity_pod, KEY_SIGNER),
            params.identity_server_public_key.clone()
        ))
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Final identity server check failed: {e}"))
        })?;

    let user_pk_check = final_builder
        .priv_op(op!(
            eq,
            (params.identity_pod, "user_public_key"),
            (params.document_pod, KEY_SIGNER)
        ))
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Final user key check failed: {e}"))
        })?;

    let _publish_verification = final_builder
        .pub_op(op!(
            custom,
            publish_verification_pred,
            identity_verification,
            document_verification,
            identity_server_pk_check,
            user_pk_check
        ))
        .map_err(|e| {
            MainPodError::ProofGeneration(format!(
                "Final publish verification statement failed: {e}"
            ))
        })?;

    let main_pod = final_builder
        .prove(prover.as_ref(), &pod_params)
        .map_err(|e| {
            MainPodError::ProofGeneration(format!("Final proof generation failed: {e}"))
        })?;

    main_pod.pod.verify().map_err(|e| {
        MainPodError::ProofGeneration(format!("Final proof verification failed: {e}"))
    })?;

    Ok(main_pod)
}

/// Verify a publish verification MainPod
///
/// This verifies that the MainPod contains the expected public statements
/// and that the content hash and username match the expected values.
pub fn verify_publish_verification(
    main_pod: &MainPod,
    expected_content_hash: &Hash,
    expected_username: &str,
    expected_post_id: i64,
    expected_tags: &HashSet<String>,
) -> MainPodResult<()> {
    // Verify basic MainPod structure
    verify_mainpod_basics(main_pod)?;

    let params = PodNetProverSetup::get_params();
    let predicate_input = get_publish_verification_predicate();
    let batch = parse(&predicate_input, &params, &[])
        .map_err(|e| MainPodError::Verification(format!("Predicate parsing failed: {e}")))?
        .custom_batch;

    let publish_verification_pred = batch
        .predicate_ref_by_name("publish_verification")
        .ok_or_else(|| {
            MainPodError::Verification("Missing publish_verification predicate".to_string())
        })?;

    // Find the publish verification statement in public statements
    let publish_verification_args = main_pod
        .public_statements
        .iter()
        .find_map(|stmt| match stmt {
            Statement::Custom(pred, args) if *pred == publish_verification_pred => Some(args),
            _ => None,
        })
        .ok_or_else(|| {
            MainPodError::Verification("MainPod missing publish_verification statement".to_string())
        })?;

    // Extract and verify public data
    let username = publish_verification_args[0].as_str().ok_or_else(|| {
        MainPodError::Verification("publish_verification missing username argument".to_string())
    })?;

    let content_hash = publish_verification_args[1].as_hash().ok_or_else(|| {
        MainPodError::Verification("publish_verification missing content_hash argument".to_string())
    })?;

    let _identity_server_pk = publish_verification_args[2]
        .as_public_key()
        .ok_or_else(|| {
            MainPodError::Verification(
                "publish_verification missing identity_server_pk argument".to_string(),
            )
        })?;

    let post_id = publish_verification_args[3].as_i64().ok_or_else(|| {
        MainPodError::Verification("publish_verification missing post_id argument".to_string())
    })?;

    let tags = publish_verification_args[4].as_set().ok_or_else(|| {
        MainPodError::Verification("publish_verification missing tags argument".to_string())
    })?;

    // Verify extracted data matches expected values
    if username != expected_username {
        return Err(MainPodError::InvalidValue {
            field: "username",
            expected: expected_username.to_string(),
        });
    }

    if content_hash != *expected_content_hash {
        return Err(MainPodError::InvalidValue {
            field: "content_hash",
            expected: "matching content hash".to_string(),
        });
    }

    let expected_tags_set = Set::new(
        5,
        expected_tags
            .iter()
            .map(|v| Value::from(v.clone()))
            .collect(),
    )
    .map_err(|e| MainPodError::InvalidSet { field: "tags" })?;
    if *tags != expected_tags_set {
        return Err(MainPodError::InvalidValue {
            field: "tags",
            expected: format!("{expected_tags:?}"),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Add unit tests for publish verification functions
}

