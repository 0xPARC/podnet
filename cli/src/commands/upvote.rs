use chrono::Utc;
use hex::FromHex;
use num_bigint::BigUint;
use pod_utils::ValueExt;
use pod2::backends::plonky2::primitives::ec::schnorr::SecretKey;
use pod2::backends::plonky2::{
    basetypes::DEFAULT_VD_SET, mainpod::Prover, mock::mainpod::MockProver, signedpod::Signer,
};
use pod2::frontend::{MainPod, MainPodBuilder, SignedPod, SignedPodBuilder};
use pod2::lang::parse;
use pod2::middleware::{Hash, KEY_SIGNER, KEY_TYPE, Params, PodProver, PodType};
use pod2::op;
use podnet_models::get_upvote_verification_predicate;
use reqwest::StatusCode;
use std::fs::File;

use crate::utils::handle_error_response;

pub async fn upvote_document(
    keypair_file: &str,
    document_id: &str,
    server_url: &str,
    identity_pod_file: &str,
    use_mock: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Upvoting document {document_id} on server {server_url} using main pod verification..."
    );

    // Parse document ID
    let doc_id: i64 = document_id.parse()?;

    // First, get the document to retrieve its content hash and post ID
    println!(
        "Retrieving document {doc_id} to get content hash and post ID..."
    );
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{server_url}/documents/{doc_id}"))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "retrieve document");
        return Ok(());
    }

    let document: serde_json::Value = response.json().await?;
    let content_hash = document
        .pointer("/metadata/content_id")
        .and_then(|v| v.as_str())
        .map(Hash::from_hex)
        .ok_or("Document missing metadata.content_id field")??;

    let post_id = document
        .pointer("/metadata/post_id")
        .and_then(|v| v.as_i64())
        .ok_or("Document missing metadata.post_id field")?;

    println!("Document content hash: {content_hash}");
    println!("Document post ID: {post_id}");

    // Load and verify identity pod
    println!("Loading identity pod from: {identity_pod_file}");
    let identity_pod_json = std::fs::read_to_string(identity_pod_file)?;
    let identity_pod: SignedPod = serde_json::from_str(&identity_pod_json)?;

    // Verify the identity pod
    identity_pod.verify()?;
    println!("✓ Identity pod verification successful");

    // Load keypair from file
    let file = File::open(keypair_file)?;
    let keypair_data: serde_json::Value = serde_json::from_reader(file)?;

    let sk_hex = keypair_data["secret_key"]
        .as_str()
        .ok_or("Invalid keypair file: missing secret_key")?;
    let sk_bytes = hex::decode(sk_hex)?;
    let sk_bigint = BigUint::from_bytes_le(&sk_bytes);
    let secret_key = SecretKey(sk_bigint);

    println!("Using keypair: {}", keypair_data["name"]);
    println!("Public key: {}", keypair_data["public_key"]);

    // Create upvote pod with content hash, post ID, and request type
    let params = Params::default();
    let mut upvote_builder = SignedPodBuilder::new(&params);

    upvote_builder.insert("request_type", "upvote");
    upvote_builder.insert("content_hash", content_hash);
    upvote_builder.insert("timestamp", Utc::now().timestamp());

    let upvote_pod = upvote_builder.sign(&mut Signer(secret_key))?;
    println!("UPVOTE POD: {upvote_pod}");
    println!("✓ Upvote pod signed successfully");

    // Verify the upvote pod
    upvote_pod.verify()?;
    println!("✓ Upvote pod verification successful");

    // Extract verification info manually
    let username = identity_pod
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or("Identity pod missing username")?
        .to_string();

    println!("Username: {username}");

    // Get identity server public key from identity pod
    let identity_server_pk = identity_pod
        .get(KEY_SIGNER)
        .ok_or("Identity pod missing signer")?
        .clone();

    // Create main pod that proves both identity and upvote verification
    let main_pod = create_upvote_verification_main_pod(
        &identity_pod,
        &upvote_pod,
        identity_server_pk,
        &content_hash,
        use_mock,
    )?;

    println!("✓ Upvote main pod created and verified");

    // Create the upvote request with main pod
    let payload = serde_json::json!({
        "upvote_main_pod": main_pod
    });

    println!("Submitting upvote to server...");
    let response = client
        .post(format!("{server_url}/documents/{doc_id}/upvote"))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        println!("✓ Successfully upvoted document using main pod verification!");

        if let Some(upvote_count) = result.get("upvote_count").and_then(|v| v.as_i64()) {
            println!("Document now has {upvote_count} upvotes");
        }

        println!(
            "Server response: {}",
            serde_json::to_string_pretty(&result)?
        );
    } else {
        let status = response.status();
        let error_text = response.text().await?;

        if status == StatusCode::CONFLICT {
            println!("You have already upvoted this document!");
        } else {
            handle_error_response(status, &error_text, "upvote document with main pod");
        }
    }

    Ok(())
}

fn create_upvote_verification_main_pod(
    identity_pod: &pod2::frontend::SignedPod,
    upvote_pod: &pod2::frontend::SignedPod,
    identity_server_public_key: pod2::middleware::Value,
    content_hash: &Hash,
    use_mock: bool,
) -> Result<MainPod, Box<dyn std::error::Error>> {
    let mut params = Params::default();
    params.max_custom_batch_size = 6;

    // Choose prover based on mock flag
    let mock_prover = MockProver {};
    let real_prover = Prover {};
    let (vd_set, prover): (_, &dyn PodProver) = if use_mock {
        println!("Using MockMainPod for upvote verification");
        (&pod2::middleware::VDSet::new(8, &[])?, &mock_prover)
    } else {
        println!("Using MainPod for upvote verification");
        (&*DEFAULT_VD_SET, &real_prover)
    };

    // Extract username and user public key from identity pod
    let username = identity_pod
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or("Identity pod missing username")?;

    let user_public_key = identity_pod
        .get("user_public_key")
        .ok_or("Identity pod missing user_public_key")?;

    // Get predicate definition from shared models
    let predicate_input = get_upvote_verification_predicate();
    println!("upvote predicate is: {predicate_input}");

    println!("Parsing custom predicates...");
    let batch = parse(&predicate_input, &params, &[])?.custom_batch;
    let identity_verified_pred = batch.predicate_ref_by_name("identity_verified").unwrap();
    let upvote_verified_pred = batch.predicate_ref_by_name("upvote_verified").unwrap();
    let upvote_verification_pred = batch.predicate_ref_by_name("upvote_verification").unwrap();

    // Step 1: Build identity verification main pod
    println!("Building identity verification main pod...");
    let mut identity_builder = MainPodBuilder::new(&params, vd_set);
    identity_builder.add_signed_pod(identity_pod);

    // Identity verification constraints (private operations)
    let identity_type_check =
        identity_builder.priv_op(op!(eq, (identity_pod, KEY_TYPE), PodType::Signed))?;
    let _identity_signer_check = identity_builder.priv_op(op!(
        eq,
        (identity_pod, KEY_SIGNER),
        identity_server_public_key.clone()
    ))?;
    let identity_username_check =
        identity_builder.priv_op(op!(eq, (identity_pod, "username"), username))?;

    // Create identity verification statement (public)
    let identity_verification = identity_builder.pub_op(op!(
        custom,
        identity_verified_pred,
        identity_type_check,
        identity_username_check
    ))?;

    println!("Generating identity verification main pod proof...");
    let identity_main_pod = identity_builder.prove(prover, &params)?;
    identity_main_pod.pod.verify()?;
    println!("✓ Identity verification main pod created and verified");

    // Step 2: Build upvote verification main pod
    println!("Building upvote verification main pod...");
    let mut upvote_builder = MainPodBuilder::new(&params, vd_set);
    upvote_builder.add_signed_pod(upvote_pod);

    // Upvote verification constraints (private operations)
    let upvote_type_check =
        upvote_builder.priv_op(op!(eq, (upvote_pod, KEY_TYPE), PodType::Signed))?;
    let _upvote_signer_check =
        upvote_builder.priv_op(op!(eq, (upvote_pod, KEY_SIGNER), user_public_key))?;
    let upvote_content_check =
        upvote_builder.priv_op(op!(eq, (upvote_pod, "content_hash"), *content_hash))?;
    let upvote_request_type_check =
        upvote_builder.priv_op(op!(eq, (upvote_pod, "request_type"), "upvote"))?;

    // Create upvote verification statement (public)
    let upvote_verification = upvote_builder.pub_op(op!(
        custom,
        upvote_verified_pred,
        upvote_type_check,
        upvote_content_check,
        upvote_request_type_check
    ))?;

    println!("Generating upvote verification main pod proof...");
    let upvote_main_pod = upvote_builder.prove(prover, &params)?;
    upvote_main_pod.pod.verify()?;
    println!("✓ Upvote verification main pod created and verified");

    // Step 3: Build final upvote verification main pod that combines the two
    println!("Building final upvote verification main pod...");
    let mut final_builder = MainPodBuilder::new(&params, vd_set);

    // Add the identity and upvote main pods as recursive inputs
    final_builder.add_recursive_pod(identity_main_pod);
    final_builder.add_recursive_pod(upvote_main_pod);

    // Add the original signed pods for cross-verification
    final_builder.add_signed_pod(identity_pod);
    final_builder.add_signed_pod(upvote_pod);

    // Cross-verification constraints (private operations)
    let identity_server_pk_check = final_builder.priv_op(op!(
        eq,
        (identity_pod, KEY_SIGNER),
        identity_server_public_key.clone()
    ))?;
    let user_pk_check = final_builder.priv_op(op!(
        eq,
        (identity_pod, "user_public_key"),
        (upvote_pod, KEY_SIGNER)
    ))?;

    // Create the unified upvote verification statement (public)
    // This references the previous main pod proofs and adds cross-verification
    let _upvote_verification = final_builder.pub_op(op!(
        custom,
        upvote_verification_pred,
        identity_verification,
        upvote_verification,
        identity_server_pk_check,
        user_pk_check
    ))?;

    // Generate the final main pod proof
    println!("Generating final upvote verification main pod proof (this may take a while)...");
    let main_pod = final_builder.prove(prover, &params)?;

    // Verify the main pod
    main_pod.pod.verify()?;
    println!("✓ Upvote main pod proof generated and verified");

    Ok(main_pod)
}
