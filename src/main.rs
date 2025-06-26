use std::fs::File;
use std::io::prelude::*;

use clap::{Arg, Command};
use pod2::backends::plonky2::primitives::ec::schnorr::SecretKey;

// Helper functions for creating common arguments
fn server_arg() -> Arg {
    Arg::new("server")
        .help("Server URL")
        .short('s')
        .long("server")
        .default_value("http://localhost:3000")
}

fn keypair_arg() -> Arg {
    Arg::new("keypair")
        .help("Path to keypair file")
        .short('k')
        .long("keypair")
        .required(true)
}

fn post_id_arg() -> Arg {
    Arg::new("post_id")
        .help("Post ID")
        .short('p')
        .long("post-id")
        .required(true)
}

fn document_id_arg() -> Arg {
    Arg::new("document_id")
        .help("Document ID")
        .short('d')
        .long("document-id")
        .required(true)
}

fn optional_post_id_arg() -> Arg {
    Arg::new("post_id")
        .help("Post ID to add revision to (creates new post if not provided)")
        .short('p')
        .long("post-id")
}

fn content_args() -> Vec<Arg> {
    vec![
        Arg::new("content")
            .help("Content to publish")
            .short('c')
            .long("content")
            .conflicts_with("file"),
        Arg::new("file")
            .help("Markdown file to publish")
            .short('f')
            .long("file")
            .conflicts_with("content"),
    ]
}

// Helper functions for common response handling
fn extract_document_metadata(document: &serde_json::Value) -> (String, String, i64, i64) {
    let content_id = document
        .get("content_id")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A")
        .to_string();
    let created_at = document
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A")
        .to_string();
    let post_id = document
        .get("post_id")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let revision = document
        .get("revision")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    (content_id, created_at, post_id, revision)
}

fn print_document_metadata(content_id: &str, created_at: &str, post_id: i64, revision: i64) {
    println!("Document ID: {content_id}");
    println!("Post ID: {post_id}");
    println!("Revision: {revision}");
    println!("Created: {created_at}");
}

fn handle_error_response(status: reqwest::StatusCode, error_text: &str, operation: &str) {
    println!("Failed to {operation}. Status: {status}");
    println!("Error: {error_text}");
}

fn create_enhanced_html_document(
    id: &str,
    content_id: &str,
    timestamp: &str,
    html_content: &str,
    revision_links: &str,
) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ParcNet Content - Post {id}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
            background-color: #fff;
        }}
        .header {{
            border-bottom: 2px solid #eee;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .metadata {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 0.9em;
            color: #666;
        }}
        .metadata strong {{
            color: #333;
        }}
        .revisions {{
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #2196f3;
        }}
        .revisions h3 {{
            margin-top: 0;
            color: #1976d2;
        }}
        .revisions ul {{
            margin-bottom: 0;
        }}
        .revisions a {{
            color: #1976d2;
            text-decoration: none;
        }}
        .revisions a:hover {{
            text-decoration: underline;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            border-left: 4px solid #007bff;
        }}
        code {{
            background-color: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Consolas', monospace;
        }}
        pre code {{
            background-color: transparent;
            padding: 0;
        }}
        h1, h2, h3, h4, h5, h6 {{
            margin-top: 30px;
            margin-bottom: 15px;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
        }}
        ul, ol {{
            padding-left: 30px;
        }}
        li {{
            margin-bottom: 5px;
        }}
        a {{
            color: #007bff;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ParcNet Content</h1>
        <div class="metadata">
            <div><strong>Post ID:</strong> {id}</div>
            <div><strong>Content Hash:</strong> <code>{content_id}</code></div>
            <div><strong>Timestamp:</strong> {timestamp}</div>
        </div>
    </div>
    {revision_links}
    <div class="content">
        {html_content}
    </div>
</body>
</html>"#
    )
}

fn create_html_document(id: &str, content_id: &str, timestamp: &str, html_content: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ParcNet Content - ID {id}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
            background-color: #fff;
        }}
        .header {{
            border-bottom: 2px solid #eee;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .metadata {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 0.9em;
            color: #666;
        }}
        .metadata strong {{
            color: #333;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            border-left: 4px solid #007bff;
        }}
        code {{
            background-color: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Consolas', monospace;
        }}
        pre code {{
            background-color: transparent;
            padding: 0;
        }}
        h1, h2, h3, h4, h5, h6 {{
            margin-top: 30px;
            margin-bottom: 15px;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
        }}
        ul, ol {{
            padding-left: 30px;
        }}
        li {{
            margin-bottom: 5px;
        }}
        a {{
            color: #007bff;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ParcNet Content</h1>
        <div class="metadata">
            <div><strong>ID:</strong> {id}</div>
            <div><strong>Content Hash:</strong> <code>{content_id}</code></div>
            <div><strong>Timestamp:</strong> {timestamp}</div>
        </div>
    </div>
    <div class="content">
        {html_content}
    </div>
</body>
</html>"#
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("parcnet-cli")
        .version("1.0")
        .about("CLI tool for parcnet pod2 operations")
        .subcommand(
            Command::new("keygen")
                .about("Generate a Schnorr keypair for pod2 signing")
                .args([
                    Arg::new("output")
                        .help("Output file for the keypair")
                        .short('o')
                        .long("output")
                        .default_value("keypair.json"),
                    Arg::new("name")
                        .help("Name/identifier for this keypair")
                        .short('n')
                        .long("name")
                        .default_value("default"),
                ]),
        )
        .subcommand(
            Command::new("publish")
                .about("Sign content and submit to server (creates new post or adds revision)")
                .args([keypair_arg(), server_arg(), optional_post_id_arg()])
                .args(content_args()),
        )
        .subcommand(
            Command::new("get-post")
                .about("Retrieve post with all its documents")
                .args([post_id_arg(), server_arg()]),
        )
        .subcommand(
            Command::new("get-document")
                .about("Retrieve specific document by ID")
                .args([document_id_arg(), server_arg()]),
        )
        .subcommand(
            Command::new("render")
                .about("Retrieve and render document as HTML by ID")
                .args([document_id_arg(), server_arg()]),
        )
        .subcommand(
            Command::new("view")
                .about("Retrieve latest document from post, render as HTML, and open in browser")
                .args([post_id_arg(), server_arg()]),
        )
        .subcommand(
            Command::new("list-posts")
                .about("List all posts")
                .arg(server_arg()),
        )
        .subcommand(
            Command::new("list-documents")
                .about("List all documents metadata")
                .arg(server_arg()),
        )
        .subcommand(
            Command::new("register")
                .about("Register user with server using keypair")
                .args([
                    keypair_arg(),
                    server_arg(),
                    Arg::new("user_id")
                        .help("User ID to register")
                        .short('u')
                        .long("user-id")
                        .required(true),
                ]),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("keygen", sub_matches)) => {
            let output_file = sub_matches.get_one::<String>("output").unwrap();
            let name = sub_matches.get_one::<String>("name").unwrap();
            generate_keypair(name, output_file)?;
        }
        Some(("publish", sub_matches)) => {
            let keypair_file = sub_matches.get_one::<String>("keypair").unwrap();
            let content = get_content_from_args(sub_matches)?;
            let server = sub_matches.get_one::<String>("server").unwrap();
            let post_id = sub_matches.get_one::<String>("post_id");
            publish_content(keypair_file, &content, server, post_id).await?;
        }
        Some(("get-post", sub_matches)) => {
            let post_id = sub_matches.get_one::<String>("post_id").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            get_post_by_id(post_id, server).await?;
        }
        Some(("get-document", sub_matches)) => {
            let document_id = sub_matches.get_one::<String>("document_id").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            get_document_by_id(document_id, server).await?;
        }
        Some(("render", sub_matches)) => {
            let document_id = sub_matches.get_one::<String>("document_id").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            render_document_by_id(document_id, server).await?;
        }
        Some(("view", sub_matches)) => {
            let post_id = sub_matches.get_one::<String>("post_id").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            view_post_in_browser(post_id, server).await?;
        }
        Some(("list-posts", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            list_posts(server).await?;
        }
        Some(("list-documents", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            list_documents(server).await?;
        }
        Some(("register", sub_matches)) => {
            let keypair_file = sub_matches.get_one::<String>("keypair").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            let user_id = sub_matches.get_one::<String>("user_id").unwrap();
            register_user(keypair_file, server, user_id).await?;
        }
        _ => {
            println!("No valid subcommand provided. Use --help for usage information.");
        }
    }

    Ok(())
}

fn generate_keypair(name: &str, output_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new Schnorr keypair
    let secret_key = SecretKey::new_rand();
    let public_key = secret_key.public_key();

    // Create a JSON structure with both keys and metadata
    let keypair_data = serde_json::json!({
        "name": name,
        "secret_key": hex::encode(secret_key.0.to_bytes_le()),
        "public_key": public_key,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "key_type": "schnorr"
    });

    // Write to file
    let mut file = File::create(output_file)?;
    file.write_all(serde_json::to_string_pretty(&keypair_data)?.as_bytes())?;

    println!("Generated keypair:");
    println!("Name: {name}");
    println!("Public Key: {public_key}");
    println!("Saved to: {output_file}");

    Ok(())
}

async fn publish_content(
    keypair_file: &str,
    content: &str,
    server_url: &str,
    post_id: Option<&String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use num_bigint::BigUint;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;
    use pod2::backends::plonky2::signedpod::Signer;
    use pod2::frontend::SignedPodBuilder;
    use pod2::middleware::Params;

    println!("Publishing content to server...");
    println!("Content: {content}");

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

    // TODO(EVAN): no padding could lead to issues ...
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

    // Create signed pod with the content hash
    let params = Params::default();
    let mut builder = SignedPodBuilder::new(&params);
    builder.insert("content_hash", content_hash.as_str());

    let signed_pod = builder.sign(&mut Signer(secret_key))?;

    println!("Content hash signed successfully!");

    // Submit content and pod to server using the /publish route
    let mut payload = serde_json::json!({
        "content": content,
        "signed_pod": signed_pod,
        "public_key": keypair_data["public_key"].as_str().unwrap_or("")
    });

    // Add post_id if provided (for adding revision to existing post)
    if let Some(id) = post_id {
        if let Ok(post_id_num) = id.parse::<i64>() {
            payload["post_id"] = serde_json::Value::Number(serde_json::Number::from(post_id_num));
        }
    }

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{server_url}/publish"))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        println!("Successfully published to server!");
        println!(
            "Server response: {}",
            serde_json::to_string_pretty(&result)?
        );
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        println!("Failed to publish. Status: {status}");
        println!("Error: {error_text}");
    }

    Ok(())
}

fn get_content_from_args(matches: &clap::ArgMatches) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(content) = matches.get_one::<String>("content") {
        Ok(content.clone())
    } else if let Some(file_path) = matches.get_one::<String>("file") {
        let content = std::fs::read_to_string(file_path)?;
        Ok(content)
    } else {
        Err("Either --content or --file must be provided".into())
    }
}

async fn get_post_by_id(post_id: &str, server_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{server_url}/posts/{post_id}"))
        .send()
        .await?;

    if response.status().is_success() {
        let post: serde_json::Value = response.json().await?;

        println!("Post ID: {post_id}");
        println!(
            "Created: {}",
            post.get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A")
        );
        println!(
            "Last Edited: {}",
            post.get("last_edited_at")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A")
        );

        if let Some(documents) = post.get("documents").and_then(|d| d.as_array()) {
            println!("\nDocuments ({} revisions):", documents.len());
            for document in documents {
                let (content_id, created_at, _, revision) = extract_document_metadata(document);
                println!("  Revision {revision}: {content_id} ({created_at})");

                if let Some(content) = document.get("content").and_then(|v| v.as_str()) {
                    println!(
                        "    Content: {}",
                        if content.len() > 100 {
                            format!("{}...", &content[0..100])
                        } else {
                            content.to_string()
                        }
                    );
                }
            }
        } else {
            println!("No documents found for this post.");
        }
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "retrieve post");
    }

    Ok(())
}

async fn get_document_by_id(
    document_id: &str,
    server_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{server_url}/documents/{document_id}"))
        .send()
        .await?;

    if response.status().is_success() {
        let document: serde_json::Value = response.json().await?;

        if let Some(content) = document.get("content").and_then(|v| v.as_str()) {
            let (content_id, created_at, post_id, revision) = extract_document_metadata(&document);
            print_document_metadata(&content_id, &created_at, post_id, revision);
            println!("Content:\n{content}");
        } else {
            println!("No content found for document ID: {document_id}");
        }
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "retrieve document");
    }

    Ok(())
}

async fn render_document_by_id(
    document_id: &str,
    server_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{server_url}/documents/{document_id}/render"))
        .send()
        .await?;

    if response.status().is_success() {
        let document: serde_json::Value = response.json().await?;

        if let Some(content) = document.get("content").and_then(|v| v.as_str()) {
            let (content_id, created_at, post_id, revision) = extract_document_metadata(&document);
            print_document_metadata(&content_id, &created_at, post_id, revision);
            println!("Rendered HTML:\n{content}");
        } else {
            println!("No content found for document ID: {document_id}");
        }
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "retrieve document");
    }

    Ok(())
}

async fn view_post_in_browser(
    post_id: &str,
    server_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    // Get server public key for signature verification
    let server_public_key = get_server_public_key(server_url).await?;
    println!("Server public key: {server_public_key}");

    // First get the post with all its documents
    let response = client
        .get(format!("{server_url}/posts/{post_id}"))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "retrieve post");
        return Ok(());
    }

    let post: serde_json::Value = response.json().await?;

    // Find the latest document (documents are ordered by revision DESC)
    if let Some(documents) = post.get("documents").and_then(|d| d.as_array()) {
        if documents.is_empty() {
            println!("No documents found for post ID: {post_id}");
            return Ok(());
        }

        // Get the first document (latest revision)
        let latest_document = &documents[0];
        let document_id = latest_document
            .get("id")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        // Now get the rendered version of this document
        let render_response = client
            .get(format!("{server_url}/documents/{document_id}/render"))
            .send()
            .await?;

        if !render_response.status().is_success() {
            let status = render_response.status();
            let error_text = render_response.text().await?;
            handle_error_response(status, &error_text, "retrieve rendered document");
            return Ok(());
        }

        let rendered_document: serde_json::Value = render_response.json().await?;

        if let Some(html_content) = rendered_document.get("content").and_then(|v| v.as_str()) {
            let (content_id, created_at, _, revision) =
                extract_document_metadata(&rendered_document);

            // Verify signatures
            println!("Verifying signatures...");

            // Verify document pod signature
            if let Some(pod) = rendered_document.get("pod") {
                if let Err(e) = verify_document_pod_signature(pod, None) {
                    println!("⚠ Document signature verification failed: {e}");
                }
            }

            // Verify timestamp pod signature if present
            if let Some(timestamp_pod) = rendered_document.get("timestamp_pod") {
                if let Err(e) = verify_timestamp_pod_signature(timestamp_pod, &server_public_key) {
                    println!("⚠ Timestamp signature verification failed: {e}");
                }
            }

            // Create revision navigation
            let mut revision_links = String::new();
            if documents.len() > 1 {
                revision_links
                    .push_str("<div class=\"revisions\">\n<h3>Other Revisions:</h3>\n<ul>\n");
                for doc in documents.iter() {
                    let doc_id = doc.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                    let doc_revision = doc.get("revision").and_then(|v| v.as_i64()).unwrap_or(0);
                    let doc_created = doc
                        .get("created_at")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");

                    if doc_revision != revision {
                        revision_links.push_str(&format!(
                            "<li><a href=\"#{doc_id}\">Revision {doc_revision} ({doc_created})</a></li>\n"
                        ));
                    } else {
                        revision_links.push_str(&format!(
                            "<li><strong>Revision {doc_revision} ({doc_created})</strong> ← Current</li>\n"
                        ));
                    }
                }
                revision_links.push_str("</ul></div>\n");
            }

            let full_html = create_enhanced_html_document(
                post_id,
                &content_id,
                &created_at,
                html_content,
                &revision_links,
            );

            // Write to a temporary file
            let temp_file = format!("/tmp/parcnet-post-{post_id}.html");
            std::fs::write(&temp_file, full_html)?;

            println!(
                "Opening latest document from post {post_id} in browser..."
            );
            println!("Document ID: {content_id}");
            println!("Revision: {revision}");
            println!("Created: {created_at}");

            // Open in default browser
            if let Err(e) = webbrowser::open(&temp_file) {
                println!("Failed to open browser: {e}");
                println!("HTML file saved to: {temp_file}");
            } else {
                println!("Opened in browser: {temp_file}");
            }
        } else {
            println!(
                "No content found in latest document for post ID: {post_id}"
            );
        }
    } else {
        println!("No documents found for post ID: {post_id}");
    }

    Ok(())
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[0..max_len - 3])
    } else {
        s.to_string()
    }
}

fn print_post_row(post: &serde_json::Value) {
    let id = post.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let created_at = post
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");
    let last_edited_at = post
        .get("last_edited_at")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    // Find the latest document ID from the documents array
    let latest_doc_id = post
        .get("documents")
        .and_then(|docs| docs.as_array())
        .and_then(|docs| docs.first())
        .and_then(|doc| doc.get("id"))
        .and_then(|id| id.as_i64())
        .map(|id| id.to_string())
        .unwrap_or_else(|| "N/A".to_string());

    println!(
        "{id:<5} {created_at:<20} {last_edited_at:<20} {latest_doc_id:<10}"
    );
}

fn print_document_row(document: &serde_json::Value) {
    let id = document.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let content_id = document
        .get("content_id")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");
    let post_id = document
        .get("post_id")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let revision = document
        .get("revision")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let created_at = document
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");
    let signer = document
        .pointer("/pod/data/kvs/kvs/_signer/PublicKey")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    let content_id_short = truncate_string(content_id, 12);
    let signer_short = truncate_string(signer, 40);

    println!(
        "{id:<5} {post_id:<7} {revision:<3} {content_id_short:<12} {created_at:<20} {signer_short:<40}"
    );
}

async fn list_posts(server_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.get(format!("{server_url}/posts")).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "retrieve posts list");
        return Ok(());
    }

    let posts: serde_json::Value = response.json().await?;
    let Some(posts_array) = posts.as_array() else {
        println!("Invalid response format from server.");
        return Ok(());
    };

    if posts_array.is_empty() {
        println!("No posts found.");
        return Ok(());
    }

    // Print header
    println!("Posts:");
    println!(
        "{:<5} {:<20} {:<20} {:<10}",
        "ID", "Created", "Last Edited", "Latest Doc"
    );
    println!("{}", "-".repeat(60));

    // Print posts
    for post in posts_array {
        print_post_row(post);
    }

    println!("\nUse 'get-post --post-id <ID>' to retrieve post details.");
    Ok(())
}

async fn list_documents(server_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{server_url}/documents"))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "retrieve documents list");
        return Ok(());
    }

    let documents: serde_json::Value = response.json().await?;
    let Some(documents_array) = documents.as_array() else {
        println!("Invalid response format from server.");
        return Ok(());
    };

    if documents_array.is_empty() {
        println!("No documents found.");
        return Ok(());
    }

    // Print header
    println!("Documents:");
    println!(
        "{:<5} {:<7} {:<3} {:<12} {:<20} {:<40}",
        "ID", "Post", "Rev", "Content ID", "Created", "Signer"
    );
    println!("{}", "-".repeat(90));

    // Print documents
    for document in documents_array {
        print_document_row(document);
    }

    println!(
        "\nUse 'get-document --document-id <ID>' to retrieve document or 'view --post-id <POST_ID>' to open latest document in browser."
    );
    Ok(())
}

async fn register_user(
    keypair_file: &str,
    server_url: &str,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Registering user {user_id} with server...");

    // Load keypair from file
    let file = File::open(keypair_file)?;
    let keypair_data: serde_json::Value = serde_json::from_reader(file)?;

    let public_key = keypair_data["public_key"]
        .as_str()
        .ok_or("Invalid keypair file: missing public_key")?;

    let payload = serde_json::json!({
        "user_id": user_id,
        "public_key": public_key
    });

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{server_url}/register"))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        println!("Successfully registered user: {user_id}");
        println!("Public Key: {public_key}");

        if let Some(server_pk) = result.get("public_key").and_then(|v| v.as_str()) {
            println!("Server Public Key: {server_pk}");
        }
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "register user");
    }

    Ok(())
}

fn verify_timestamp_pod_signature(
    timestamp_pod: &serde_json::Value,
    server_public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use pod2::frontend::SignedPod;

    // Deserialize timestamp pod
    let signed_pod: SignedPod = serde_json::from_value(timestamp_pod.clone())?;

    // Verify signature
    signed_pod.verify()?;

    // Check that the signer matches the server public key
    let pod_signer = signed_pod
        .get("_signer")
        .ok_or("Timestamp pod missing signer")?;

    let pod_signer_str = format!("{pod_signer}");
    let server_public_key = format!("pk:{server_public_key}");
    if pod_signer_str != server_public_key {
        return Err(format!(
            "Timestamp pod signer {pod_signer_str} does not match server public key {server_public_key}"
        )
        .into());
    }

    println!("✓ Timestamp pod signature verified");
    Ok(())
}

fn verify_document_pod_signature(
    document_pod: &serde_json::Value,
    expected_signer: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use pod2::frontend::SignedPod;

    // Deserialize document pod
    let signed_pod: SignedPod = serde_json::from_value(document_pod.clone())?;

    // Verify signature
    signed_pod.verify()?;

    // If expected signer provided, check it matches
    if let Some(expected) = expected_signer {
        let pod_signer = signed_pod
            .get("_signer")
            .ok_or("Document pod missing signer")?;

        let pod_signer_str = format!("{pod_signer}");
        if pod_signer_str != expected {
            return Err(format!(
                "Document pod signer {pod_signer_str} does not match expected {expected}"
            )
            .into());
        }
    }

    println!("✓ Document pod signature verified");
    Ok(())
}

async fn get_server_public_key(server_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.get(server_url).send().await?;

    if response.status().is_success() {
        let server_info: serde_json::Value = response.json().await?;
        let public_key = server_info
            .get("public_key")
            .and_then(|v| v.as_str())
            .ok_or("Server response missing public_key")?;
        Ok(public_key.to_string())
    } else {
        Err("Failed to get server info".into())
    }
}
