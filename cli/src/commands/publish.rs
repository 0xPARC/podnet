use num_bigint::BigUint;
use pod_utils::ValueExt;
use pod_utils::prover_setup::PodNetProverSetup;
use pod2::backends::plonky2::primitives::ec::schnorr::SecretKey;
use pod2::backends::plonky2::signedpod::Signer;
use pod2::frontend::{SignedPod, SignedPodBuilder};
use pod2::middleware::{Hash, KEY_SIGNER, KEY_TYPE, Value, containers::Set, hash_values};
use podnet_models::mainpod::publish::{PublishProofParams, prove_publish_verification};
use std::collections::HashSet;
use std::fs::File;

use crate::conversion::{DocumentFormat, convert_to_markdown, detect_format};
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
    tags: Option<&String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Publishing content to server using main pod verification...");

    // Step 1: Determine document format
    let detected_format = if let Some(format_str) = format_override {
        DocumentFormat::from_str(format_str)
            .ok_or_else(|| format!("Invalid format: {format_str}"))?
    } else {
        detect_format(content, file_path.map(|s| s.as_str()))
    };

    println!("Detected format: {detected_format:?}");

    // Step 2: Convert to Markdown only if necessary
    let markdown_content = if detected_format != DocumentFormat::Markdown {
        let converted = convert_to_markdown(content, &detected_format)?;
        println!("✓ Content converted from {detected_format:?} to Markdown");
        println!(
            "Converted content preview: {}",
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

    // Step 3: Process tags
    let document_tags: HashSet<String> = if let Some(tags_str) = tags {
        tags_str
            .split(',')
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect()
    } else {
        HashSet::new()
    };

    if !document_tags.is_empty() {
        println!(
            "Tags: {}",
            document_tags
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Use the converted markdown content for the rest of the process
    let content = &markdown_content;

    // Load and verify identity pod
    println!("Loading identity pod from: {identity_pod_file}");
    let identity_pod_json = std::fs::read_to_string(identity_pod_file)?;
    let identity_pod: SignedPod = serde_json::from_str(&identity_pod_json)?;

    // Verify the identity pod
    identity_pod.verify()?;
    println!("✓ Identity pod verification successful");

    let content_hash = hash_values(&[Value::from(content.clone())]);
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
    println!("Tags: {document_tags:?}");

    // Create document pod with content hash, timestamp, tags, and optional post_id
    let params = PodNetProverSetup::get_params();
    let mut document_builder = SignedPodBuilder::new(&params);

    document_builder.insert("request_type", "publish");
    document_builder.insert("content_hash", content_hash);
    document_builder.insert("timestamp", chrono::Utc::now().timestamp());
    let tag_set = Set::new(
        5, // TODO: put this configuration somewhere global
        document_tags
            .iter()
            .map(|v| Value::from(v.clone()))
            .collect(),
    )?;
    document_builder.insert("tags", tag_set);

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
        .and_then(|v| v.as_hash())
        .ok_or("Document pod missing content_hash")?;

    println!("Username: {username}");

    // Get identity server public key from identity pod
    let identity_server_pk = identity_pod
        .get(KEY_SIGNER)
        .ok_or("Identity pod missing signer")?
        .clone();

    // Create main pod that proves both identity and document verification
    let params = PublishProofParams {
        identity_pod: &identity_pod,
        document_pod: &document_pod,
        identity_server_public_key: identity_server_pk,
        content_hash: &verified_content_hash,
        use_mock_proofs: use_mock,
    };
    let main_pod = prove_publish_verification(params)
        .map_err(|e| format!("Failed to generate publish verification MainPod: {}", e))?;

    println!("✓ Main pod created and verified");

    println!("Serializing main pod");
    // Create the publish request with main pod
    let payload = serde_json::json!({
        "content": content,
        "tags": document_tags,
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
