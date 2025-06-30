use num_bigint::BigUint;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use pod_utils::{ValueExt, get_publish_verification_predicate};
use pod2::backends::plonky2::primitives::ec::schnorr::SecretKey;
use pod2::backends::plonky2::{
    basetypes::DEFAULT_VD_SET, mainpod::Prover, mock::mainpod::MockProver, signedpod::Signer,
};
use pod2::frontend::{MainPod, MainPodBuilder, SignedPod, SignedPodBuilder};
use pod2::lang::parse;
use pod2::middleware::{KEY_SIGNER, KEY_TYPE, Params, PodProver, PodType, Value};
use pod2::op;
use std::fs::File;
use std::io::Write;

use crate::conversion::{detect_format, convert_to_markdown, DocumentFormat};
use crate::utils::handle_error_response;

pub async fn publish_content(
    keypair_file: &str,
    content: &str,
    file_path: Option<&String>,
    format_override: Option<&String>,
    server_url: &str,
    post_id: Option<&String>,
    identity_pod_file: &str,
    use_mock: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Publishing content to server using main pod verification...");
    
    // Step 1: Determine document format
    let detected_format = if let Some(format_str) = format_override {
        DocumentFormat::from_str(format_str)
            .ok_or_else(|| format!("Invalid format: {}", format_str))?
    } else {
        detect_format(content, file_path.map(|s| s.as_str()))
    };
    
    println!("Detected format: {:?}", detected_format);
    
    // Step 2: Convert to Markdown only if necessary
    let markdown_content = if detected_format != DocumentFormat::Markdown {
        let converted = convert_to_markdown(content, &detected_format)?;
        println!("✓ Content converted from {:?} to Markdown", detected_format);
        println!("Converted content preview: {}", 
            if converted.len() > 200 {
                format!("{}...", &converted[0..200])
            } else {
                converted.clone()
            }
        );
        converted
    } else {
        println!("Content is already in Markdown format");
        content.to_string()
    };
    
    // Use the converted markdown content for the rest of the process
    let content = &markdown_content;

    // Load and verify identity pod
    println!("Loading identity pod from: {identity_pod_file}");
    let identity_pod_json = std::fs::read_to_string(identity_pod_file)?;
    let identity_pod: SignedPod = serde_json::from_str(&identity_pod_json)?;

    // Verify the identity pod
    identity_pod.verify()?;
    println!("✓ Identity pod verification successful");

    // Calculate content hash (same as server)
    let bytes = content.as_bytes();
    let mut inputs = Vec::new();

    // Process bytes in chunks of 8 (64-bit field elements)
    for chunk in bytes.chunks(8) {
        let mut padded = [0u8; 8];
        padded[..chunk.len()].copy_from_slice(chunk);
        let value = u64::from_le_bytes(padded);
        inputs.push(GoldilocksField::from_canonical_u64(value));
    }

    // Pad to multiple of 4 for Poseidon (if needed)
    while inputs.len() % 4 != 0 {
        inputs.push(GoldilocksField::ZERO);
    }

    let hash_result = PoseidonHash::hash_no_pad(&inputs);
    // Convert full hash result to bytes (all 4 elements)
    let mut hash_bytes = Vec::new();
    for element in hash_result.elements {
        hash_bytes.extend_from_slice(&element.to_canonical_u64().to_le_bytes());
    }
    let content_hash = hex::encode(hash_bytes);

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
    println!("Content hash: {content_hash}");

    // Create document pod with content hash, timestamp, and optional post_id
    let params = Params::default();
    let mut document_builder = SignedPodBuilder::new(&params);

    document_builder.insert("content_hash", content_hash.as_str());
    document_builder.insert("timestamp", chrono::Utc::now().timestamp());

    // Add post_id to the pod if provided (for adding revision to existing post)
    if let Some(id) = post_id {
        let post_id_num = id.parse::<i64>()?;
        document_builder.insert("post_id", post_id_num);
    } else {
        document_builder.insert("post_id", -1);
    }

    let document_pod = document_builder.sign(&mut Signer(secret_key))?;
    println!("✓ Document pod signed successfully");

    // Verify the document pod
    document_pod.verify()?;
    println!("✓ Document pod verification successful");

    // Extract verification info manually
    let username = identity_pod
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or("Identity pod missing username")?
        .to_string();

    let verified_content_hash = document_pod
        .get("content_hash")
        .and_then(|v| v.as_str())
        .ok_or("Document pod missing content_hash")?
        .to_string();

    println!("Username: {}", username);

    // Get identity server public key from identity pod
    let identity_server_pk = identity_pod
        .get(KEY_SIGNER)
        .ok_or("Identity pod missing signer")?
        .clone();

    // Create main pod that proves both identity and document verification
    let main_pod = create_publish_verification_main_pod(
        &identity_pod,
        &document_pod,
        identity_server_pk,
        &verified_content_hash,
        use_mock,
    )?;

    println!("✓ Main pod created and verified");

    println!("Serializing main pod");
    // Create the publish request with main pod
    let payload = serde_json::json!({
        "content": content,
        "main_pod": main_pod
    });
    println!("Main pod is: {}", &main_pod);

    println!("Sending mainpod");
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{server_url}/publish"))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;
    println!("Done! mainpod");

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        println!("✓ Successfully published to server using main pod verification!");
        println!(
            "Server response: {}",
            serde_json::to_string_pretty(&result)?
        );
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "publish with main pod");
    }

    Ok(())
}

fn create_publish_verification_main_pod(
    identity_pod: &pod2::frontend::SignedPod,
    document_pod: &pod2::frontend::SignedPod,
    identity_server_public_key: pod2::middleware::Value,
    content_hash: &str,
    use_mock: bool,
) -> Result<MainPod, Box<dyn std::error::Error>> {
    let params = Params::default();

    // Choose prover based on mock flag
    let mock_prover = MockProver {};
    let real_prover = Prover {};
    let (vd_set, prover): (_, &dyn PodProver) = if use_mock {
        println!("Using MockMainPod for publish verification");
        (&pod2::middleware::VDSet::new(8, &[])?, &mock_prover)
    } else {
        println!("Using MainPod for publish verification");
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

    let post_id = document_pod
        .get("post_id")
        .ok_or("Document pod missing post_id")?;

    // Get predicate definition from shared pod-utils
    let predicate_input = get_publish_verification_predicate();
    println!("predicate is: {}", predicate_input);

    println!("Parsing custom predicates...");
    let batch = parse(&predicate_input, &params, &[])?.custom_batch;
    let identity_verified_pred = batch.predicate_ref_by_name("identity_verified").unwrap();
    let document_verified_pred = batch.predicate_ref_by_name("document_verified").unwrap();
    let publish_verification_pred = batch.predicate_ref_by_name("publish_verification").unwrap();

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

    // Step 2: Build document verification main pod
    println!("Building document verification main pod...");
    let mut document_builder = MainPodBuilder::new(&params, vd_set);
    document_builder.add_signed_pod(document_pod);

    // Document verification constraints (private operations)
    let document_type_check =
        document_builder.priv_op(op!(eq, (document_pod, KEY_TYPE), PodType::Signed))?;
    let _document_signer_check =
        document_builder.priv_op(op!(eq, (document_pod, KEY_SIGNER), user_public_key))?;
    let document_content_check =
        document_builder.priv_op(op!(eq, (document_pod, "content_hash"), content_hash))?;

    // Create document verification statement (public)
    let document_verification = document_builder.pub_op(op!(
        custom,
        document_verified_pred,
        document_type_check,
        document_content_check
    ))?;

    println!("Generating document verification main pod proof...");
    let document_main_pod = document_builder.prove(prover, &params)?;
    document_main_pod.pod.verify()?;
    println!("✓ Document verification main pod created and verified");

    // Step 3: Build final publish verification main pod that combines the two
    println!("Building final publish verification main pod...");
    let mut final_builder = MainPodBuilder::new(&params, vd_set);

    // Add the identity and document main pods as recursive inputs
    final_builder.add_recursive_pod(identity_main_pod);
    final_builder.add_recursive_pod(document_main_pod);

    // Add the original signed pods for cross-verification
    final_builder.add_signed_pod(identity_pod);
    final_builder.add_signed_pod(document_pod);

    // Cross-verification constraints (private operations)
    let identity_server_pk_check = final_builder.priv_op(op!(
        eq,
        (identity_pod, KEY_SIGNER),
        identity_server_public_key.clone()
    ))?;
    let user_pk_check = final_builder.priv_op(op!(
        eq,
        (identity_pod, "user_public_key"),
        (document_pod, KEY_SIGNER)
    ))?;
    let post_id_check = final_builder.priv_op(op!(eq, (document_pod, "post_id"), post_id))?;

    // Create the unified publish verification statement (public)
    // This references the previous main pod proofs and adds cross-verification
    let _publish_verification = final_builder.pub_op(op!(
        custom,
        publish_verification_pred,
        identity_verification,
        document_verification,
        identity_server_pk_check,
        user_pk_check,
        post_id_check
    ))?;

    // Generate the final main pod proof
    println!("Generating final publish verification main pod proof (this may take a while)...");
    let main_pod = final_builder.prove(prover, &params)?;

    // Verify the main pod
    main_pod.pod.verify()?;
    println!("✓ Main pod proof generated and verified");

    Ok(main_pod)
}
