//! Upvote verification MainPod operations

use super::{MainPodError, MainPodResult, extract_username, extract_user_public_key, verify_mainpod_basics};
use crate::{get_upvote_verification_predicate};
use pod_utils::prover_setup::PodNetProverSetup;
use pod_utils::ValueExt;
use pod2::frontend::{MainPod, MainPodBuilder, SignedPod};
use pod2::lang::parse;
use pod2::middleware::{Hash, KEY_SIGNER, KEY_TYPE, PodType, Statement, Value};
use pod2::op;

/// Parameters for upvote verification proof generation
pub struct UpvoteProofParams<'a> {
    pub identity_pod: &'a SignedPod,
    pub upvote_pod: &'a SignedPod,
    pub identity_server_public_key: Value,
    pub content_hash: &'a Hash,
    pub use_mock_proofs: bool,
}

/// Generate an upvote verification MainPod
/// 
/// This creates a MainPod that cryptographically proves:
/// - Identity pod was signed by a registered identity server
/// - Upvote pod was signed by the user from the identity pod
/// - Cross-verification between identity and upvote signers
/// - Content hash verification for the upvoted document
pub fn prove_upvote_verification(params: UpvoteProofParams) -> MainPodResult<MainPod> {
    let pod_params = PodNetProverSetup::get_params();
    let (vd_set, prover) = PodNetProverSetup::create_prover_setup(params.use_mock_proofs)
        .map_err(MainPodError::ProofGeneration)?;

    // Extract required values from pods
    let username = extract_username(params.identity_pod)?;
    let user_public_key = extract_user_public_key(params.identity_pod)?;

    // Parse predicates
    let predicate_input = get_upvote_verification_predicate();
    let batch = parse(&predicate_input, &pod_params, &[])
        .map_err(|e| MainPodError::ProofGeneration(format!("Predicate parsing failed: {e}")))?
        .custom_batch;
    
    let identity_verified_pred = batch.predicate_ref_by_name("identity_verified")
        .ok_or_else(|| MainPodError::ProofGeneration("Missing identity_verified predicate".to_string()))?;
    let upvote_verified_pred = batch.predicate_ref_by_name("upvote_verified")
        .ok_or_else(|| MainPodError::ProofGeneration("Missing upvote_verified predicate".to_string()))?;
    let upvote_verification_pred = batch.predicate_ref_by_name("upvote_verification")
        .ok_or_else(|| MainPodError::ProofGeneration("Missing upvote_verification predicate".to_string()))?;

    // Step 1: Build identity verification main pod
    let mut identity_builder = MainPodBuilder::new(&pod_params, vd_set);
    identity_builder.add_signed_pod(params.identity_pod);

    let identity_type_check = identity_builder.priv_op(op!(eq, (params.identity_pod, KEY_TYPE), PodType::Signed))
        .map_err(|e| MainPodError::ProofGeneration(format!("Identity type check failed: {e}")))?;
    let _identity_signer_check = identity_builder.priv_op(op!(
        eq,
        (params.identity_pod, KEY_SIGNER),
        params.identity_server_public_key.clone()
    )).map_err(|e| MainPodError::ProofGeneration(format!("Identity signer check failed: {e}")))?;
    let identity_username_check = identity_builder.priv_op(op!(eq, (params.identity_pod, "username"), username))
        .map_err(|e| MainPodError::ProofGeneration(format!("Identity username check failed: {e}")))?;

    let identity_verification = identity_builder.pub_op(op!(
        custom,
        identity_verified_pred,
        identity_type_check,
        identity_username_check
    )).map_err(|e| MainPodError::ProofGeneration(format!("Identity verification statement failed: {e}")))?;

    let identity_main_pod = identity_builder.prove(prover.as_ref(), &pod_params)
        .map_err(|e| MainPodError::ProofGeneration(format!("Identity proof generation failed: {e}")))?;
    
    identity_main_pod.pod.verify()
        .map_err(|e| MainPodError::ProofGeneration(format!("Identity proof verification failed: {e}")))?;

    // Step 2: Build upvote verification main pod
    let mut upvote_builder = MainPodBuilder::new(&pod_params, vd_set);
    upvote_builder.add_signed_pod(params.upvote_pod);

    let upvote_type_check = upvote_builder.priv_op(op!(eq, (params.upvote_pod, KEY_TYPE), PodType::Signed))
        .map_err(|e| MainPodError::ProofGeneration(format!("Upvote type check failed: {e}")))?;
    let _upvote_signer_check = upvote_builder.priv_op(op!(eq, (params.upvote_pod, KEY_SIGNER), user_public_key))
        .map_err(|e| MainPodError::ProofGeneration(format!("Upvote signer check failed: {e}")))?;
    let upvote_content_check = upvote_builder.priv_op(op!(eq, (params.upvote_pod, "content_hash"), *params.content_hash))
        .map_err(|e| MainPodError::ProofGeneration(format!("Upvote content check failed: {e}")))?;
    let upvote_request_type_check = upvote_builder.priv_op(op!(eq, (params.upvote_pod, "request_type"), "upvote"))
        .map_err(|e| MainPodError::ProofGeneration(format!("Upvote request type check failed: {e}")))?;

    let upvote_verification = upvote_builder.pub_op(op!(
        custom,
        upvote_verified_pred,
        upvote_type_check,
        upvote_content_check,
        upvote_request_type_check
    )).map_err(|e| MainPodError::ProofGeneration(format!("Upvote verification statement failed: {e}")))?;

    let upvote_main_pod = upvote_builder.prove(prover.as_ref(), &pod_params)
        .map_err(|e| MainPodError::ProofGeneration(format!("Upvote proof generation failed: {e}")))?;
    
    upvote_main_pod.pod.verify()
        .map_err(|e| MainPodError::ProofGeneration(format!("Upvote proof verification failed: {e}")))?;

    // Step 3: Build final upvote verification main pod
    let mut final_builder = MainPodBuilder::new(&pod_params, vd_set);
    final_builder.add_recursive_pod(identity_main_pod);
    final_builder.add_recursive_pod(upvote_main_pod);
    final_builder.add_signed_pod(params.identity_pod);
    final_builder.add_signed_pod(params.upvote_pod);

    let identity_server_pk_check = final_builder.priv_op(op!(
        eq,
        (params.identity_pod, KEY_SIGNER),
        params.identity_server_public_key.clone()
    )).map_err(|e| MainPodError::ProofGeneration(format!("Final identity server check failed: {e}")))?;
    
    let user_pk_check = final_builder.priv_op(op!(
        eq,
        (params.identity_pod, "user_public_key"),
        (params.upvote_pod, KEY_SIGNER)
    )).map_err(|e| MainPodError::ProofGeneration(format!("Final user key check failed: {e}")))?;

    let _upvote_verification_final = final_builder.pub_op(op!(
        custom,
        upvote_verification_pred,
        identity_verification,
        upvote_verification,
        identity_server_pk_check,
        user_pk_check
    )).map_err(|e| MainPodError::ProofGeneration(format!("Final upvote verification statement failed: {e}")))?;

    let main_pod = final_builder.prove(prover.as_ref(), &pod_params)
        .map_err(|e| MainPodError::ProofGeneration(format!("Final proof generation failed: {e}")))?;

    main_pod.pod.verify()
        .map_err(|e| MainPodError::ProofGeneration(format!("Final proof verification failed: {e}")))?;

    Ok(main_pod)
}

/// Verify an upvote verification MainPod
/// 
/// This verifies that the MainPod contains the expected public statements
/// and that the content hash and username match the expected values.
pub fn verify_upvote_verification(
    main_pod: &MainPod,
    expected_content_hash: &Hash,
    expected_username: &str,
) -> MainPodResult<()> {
    // Verify basic MainPod structure
    verify_mainpod_basics(main_pod)?;

    let params = PodNetProverSetup::get_params();
    let predicate_input = get_upvote_verification_predicate();
    let batch = parse(&predicate_input, &params, &[])
        .map_err(|e| MainPodError::Verification(format!("Predicate parsing failed: {e}")))?
        .custom_batch;
    
    let upvote_verification_pred = batch.predicate_ref_by_name("upvote_verification")
        .ok_or_else(|| MainPodError::Verification("Missing upvote_verification predicate".to_string()))?;

    // Find the upvote verification statement in public statements
    let upvote_verification_args = main_pod
        .public_statements
        .iter()
        .find_map(|stmt| match stmt {
            Statement::Custom(pred, args) if *pred == upvote_verification_pred => Some(args),
            _ => None,
        })
        .ok_or_else(|| MainPodError::Verification("MainPod missing upvote_verification statement".to_string()))?;

    // Extract and verify public data (this will depend on the specific predicate structure)
    // Note: The exact argument structure may vary based on the upvote verification predicate implementation
    let username = upvote_verification_args[0]
        .as_str()
        .ok_or_else(|| MainPodError::Verification("upvote_verification missing username argument".to_string()))?;
    
    let content_hash = upvote_verification_args[1]
        .as_hash()
        .ok_or_else(|| MainPodError::Verification("upvote_verification missing content_hash argument".to_string()))?;
    
    let _identity_server_pk = upvote_verification_args[2]
        .as_public_key()
        .ok_or_else(|| MainPodError::Verification("upvote_verification missing identity_server_pk argument".to_string()))?;

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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Add unit tests for upvote verification functions
}