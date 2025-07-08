use num_bigint::BigUint;
use pod_utils::ValueExt;
use pod_utils::prover_setup::PodNetProverSetup;
use pod2::backends::plonky2::primitives::ec::schnorr::SecretKey;
use pod2::backends::plonky2::signedpod::Signer;
use pod2::frontend::{SignedPod, SignedPodBuilder};
use pod2::middleware::{KEY_SIGNER, Value, containers::Set, hash_values};
use podnet_models::mainpod::publish::{PublishProofParams, prove_publish_verification};
use std::collections::HashSet;
use std::fs::File;

use crate::conversion::{DocumentFormat, convert_to_markdown};
use crate::utils::handle_error_response;
use podnet_models::{DocumentContent, DocumentFile};

pub async fn publish_content(
    keypair_file: &str,
    message: Option<&String>,
    file_path: Option<&String>,
    url: Option<&String>,
    format_override: Option<&String>,
    server_url: &str,
    post_id: Option<&String>,
    identity_pod_file: &str,
    use_mock: bool,
    tags: Option<&String>,
    authors: Option<&String>,
    reply_to: Option<&String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Publishing content to server using main pod verification...");

    // Step 1: Build DocumentContent from provided inputs
    let mut document_content = DocumentContent {
        message: None,
        file: None,
        url: None,
    };

    // Process message
    if let Some(msg) = message {
        // Handle format conversion if needed
        let processed_message = if let Some(format_str) = format_override {
            let detected_format = DocumentFormat::from_str(format_str)
                .ok_or_else(|| format!("Invalid format: {format_str}"))?;
            if detected_format != DocumentFormat::Markdown {
                let converted = convert_to_markdown(msg, &detected_format)?;
                println!("✓ Message converted from {detected_format:?} to Markdown");
                converted
            } else {
                msg.clone()
            }
        } else {
            msg.clone()
        };
        document_content.message = Some(processed_message);
        println!("Message added to document");
    }

    // Process file
    if let Some(file_path_str) = file_path {
        println!("Reading file: {file_path_str}");
        let file_content = std::fs::read(file_path_str)?;
        let file_name = std::path::Path::new(file_path_str)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        // Detect MIME type based on file extension
        let mime_type = match std::path::Path::new(file_path_str)
            .extension()
            .and_then(|ext| ext.to_str())
        {
            Some("txt") => "text/plain",
            Some("md") => "text/markdown",
            Some("jpg") | Some("jpeg") => "image/jpeg",
            Some("png") => "image/png",
            Some("pdf") => "application/pdf",
            Some("json") => "application/json",
            _ => "application/octet-stream",
        }.to_string();

        document_content.file = Some(DocumentFile {
            name: file_name,
            content: file_content,
            mime_type,
        });
        println!("File added to document");
    }

    // Process URL
    if let Some(url_str) = url {
        document_content.url = Some(url_str.clone());
        println!("URL added to document: {url_str}");
    }

    // Validate that at least one content type is provided
    document_content.validate()
        .map_err(|e| format!("Content validation failed: {e}"))?;

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

    // Load and verify identity pod
    println!("Loading identity pod from: {identity_pod_file}");
    let identity_pod_json = std::fs::read_to_string(identity_pod_file)?;
    let identity_pod: SignedPod = serde_json::from_str(&identity_pod_json)?;

    // Verify the identity pod
    identity_pod.verify()?;
    println!("✓ Identity pod verification successful");

    // Extract username from identity pod for authors default
    let username = identity_pod
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or("Identity pod missing username")?
        .to_string();

    println!("Username: {username}");

    // Compute content hash from the entire DocumentContent structure
    let content_json = serde_json::to_string(&document_content)?;
    let content_hash = hash_values(&[Value::from(content_json)]);
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

    // Process authors (default to uploader if not provided or empty)
    let document_authors: HashSet<String> = if let Some(authors_str) = authors {
        let parsed_authors: HashSet<String> = authors_str
            .split(',')
            .map(|author| author.trim().to_string())
            .filter(|author| !author.is_empty())
            .collect();

        if parsed_authors.is_empty() {
            // If authors string was provided but empty, default to uploader
            let mut default_authors = HashSet::new();
            default_authors.insert(username.clone());
            default_authors
        } else {
            parsed_authors
        }
    } else {
        // If no authors provided, default to uploader
        let mut default_authors = HashSet::new();
        default_authors.insert(username.clone());
        default_authors
    };

    println!(
        "Authors: {}",
        document_authors
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

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

    // Add authors to the document pod
    let authors_set = Set::new(
        5,
        document_authors
            .iter()
            .map(|author| Value::from(author.as_str()))
            .collect(),
    )?;
    document_builder.insert("authors", authors_set);

    // Add post_id to the pod if provided (for adding revision to existing post)
    if let Some(id) = post_id {
        let post_id_num = id.parse::<i64>()?;
        document_builder.insert("post_id", post_id_num);
    } else {
        document_builder.insert("post_id", -1);
    }

    // Add reply_to if provided
    if let Some(id) = reply_to {
        let reply_to_num = id.parse::<i64>()?;
        document_builder.insert("reply_to", reply_to_num);
    } else {
        document_builder.insert("reply_to", -1);
    }

    let document_pod = document_builder.sign(&mut Signer(secret_key))?;
    println!("✓ Document pod signed successfully");

    // Verify the document pod
    document_pod.verify()?;
    println!("✓ Document pod verification successful");

    // Extract verification info manually
    let verified_content_hash = document_pod
        .get("content_hash")
        .and_then(|v| v.as_hash())
        .ok_or("Document pod missing content_hash")?;

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
        .map_err(|e| format!("Failed to generate publish verification MainPod: {e}"))?;

    println!("✓ Main pod created and verified");

    // Process reply_to parameter
    let reply_to_id: Option<i64> = if let Some(reply_to_str) = reply_to {
        match reply_to_str.parse::<i64>() {
            Ok(id) => {
                println!("Replying to document ID: {id}");
                Some(id)
            }
            Err(_) => {
                return Err(format!("Invalid reply_to document ID: {reply_to_str}").into());
            }
        }
    } else {
        None
    };

    println!("Serializing main pod");
    // Create the publish request with main pod
    let payload = serde_json::json!({
        "content": document_content,
        "tags": document_tags,
        "authors": document_authors,
        "reply_to": reply_to_id,
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
