mod commands;
mod utils;
mod verification;

use clap::{Arg, Command};
use commands::{keygen, registry, identity};
use pod2::backends::plonky2::primitives::ec::schnorr::SecretKey;
use std::fs::File;
use utils::*;
use verification::*;

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

fn create_enhanced_html_document_with_author(
    id: &str,
    content_id: &str,
    timestamp: &str,
    author: &str,
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
            margin: 0;
            padding: 0;
            color: #333;
            background-color: #fff;
            display: flex;
            min-height: 100vh;
        }}
        .sidebar {{
            width: 250px;
            background-color: #f8f9fa;
            border-right: 2px solid #eee;
            padding: 20px;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            box-sizing: border-box;
        }}
        .main-content {{
            flex: 1;
            margin-left: 250px;
            padding: 20px;
            max-width: 800px;
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
        .sidebar h3 {{
            margin-top: 0;
            color: #1976d2;
            border-bottom: 2px solid #2196f3;
            padding-bottom: 10px;
        }}
        .revision-item {{
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        .revision-item:hover {{
            background-color: #e3f2fd;
        }}
        .revision-item.current {{
            background-color: #e8f5e8;
            border-left: 4px solid #28a745;
        }}
        .revision-link {{
            color: #1976d2;
            text-decoration: none;
            display: block;
            font-weight: 500;
        }}
        .revision-link:hover {{
            text-decoration: underline;
        }}
        .revision-date {{
            font-size: 0.8em;
            color: #666;
            margin-top: 5px;
        }}
        .loading {{
            text-align: center;
            padding: 20px;
            color: #666;
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
    <script>
        function showRevision(docId) {{
            // Hide all document content divs
            document.querySelectorAll('.document-content').forEach(div => {{
                div.style.display = 'none';
            }});
            
            // Show the selected document
            const selectedDoc = document.getElementById(`document-${{docId}}`);
            if (selectedDoc) {{
                selectedDoc.style.display = 'block';
                
                // Update metadata with the selected document's info
                const metadata = document.querySelector('.metadata');
                const contentId = selectedDoc.getAttribute('data-content-id') || 'N/A';
                const timestamp = selectedDoc.getAttribute('data-created') || 'N/A';
                const author = selectedDoc.getAttribute('data-author') || 'Unknown';
                const revision = selectedDoc.getAttribute('data-revision') || 'N/A';
                
                metadata.innerHTML = `
                    <div><strong>Post ID:</strong> {id}</div>
                    <div><strong>Author:</strong> ${{author}}</div>
                    <div><strong>Content Hash:</strong> <code>${{contentId}}</code></div>
                    <div><strong>Timestamp:</strong> ${{timestamp}}</div>
                    <div><strong>Revision:</strong> ${{revision}}</div>
                `;
                
                // Update current revision highlight in sidebar
                document.querySelectorAll('.revision-item').forEach(item => {{
                    item.classList.remove('current');
                }});
                document.querySelector(`[data-doc-id="${{docId}}"]`).classList.add('current');
            }}
        }}
    </script>
</head>
<body>
    <div class="sidebar">
        <h3>Revisions</h3>
        {revision_links}
    </div>
    <div class="main-content">
        <div class="header">
            <h1>ParcNet Content</h1>
            <div class="metadata">
                <div><strong>Post ID:</strong> {id}</div>
                <div><strong>Author:</strong> {author}</div>
                <div><strong>Content Hash:</strong> <code>{content_id}</code></div>
                <div><strong>Timestamp:</strong> {timestamp}</div>
            </div>
        </div>
        <div id="main-content" class="content">
            {html_content}
        </div>
    </div>
</body>
</html>"#,
        id = id,
        author = author,
        content_id = content_id,
        timestamp = timestamp,
        revision_links = revision_links,
        html_content = html_content
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
                .args([
                    keypair_arg(), 
                    server_arg(), 
                    optional_post_id_arg(),
                    Arg::new("identity_pod")
                        .help("Path to identity pod file")
                        .short('i')
                        .long("identity-pod")
                        .required(true),
                ])
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
            Command::new("get-identity")
                .about("Get identity pod from identity server")
                .args([
                    keypair_arg(),
                    Arg::new("identity_server")
                        .help("Identity server URL")
                        .short('i')
                        .long("identity-server")
                        .default_value("http://localhost:3001"),
                    Arg::new("username")
                        .help("Username to register")
                        .short('u')
                        .long("username")
                        .required(true),
                    Arg::new("output")
                        .help("Output file for identity pod")
                        .short('o')
                        .long("output")
                        .default_value("identity.pod"),
                ]),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("keygen", sub_matches)) => {
            let output_file = sub_matches.get_one::<String>("output").unwrap();
            let name = sub_matches.get_one::<String>("name").unwrap();
            keygen::generate_keypair(name, output_file)?;
        }
        Some(("publish", sub_matches)) => {
            let keypair_file = sub_matches.get_one::<String>("keypair").unwrap();
            let content = get_content_from_args(sub_matches)?;
            let server = sub_matches.get_one::<String>("server").unwrap();
            let post_id = sub_matches.get_one::<String>("post_id");
            let identity_pod_file = sub_matches.get_one::<String>("identity_pod").unwrap();
            publish_content(keypair_file, &content, server, post_id, identity_pod_file).await?;
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
        Some(("get-identity", sub_matches)) => {
            let keypair_file = sub_matches.get_one::<String>("keypair").unwrap();
            let identity_server = sub_matches.get_one::<String>("identity_server").unwrap();
            let username = sub_matches.get_one::<String>("username").unwrap();
            let output_file = sub_matches.get_one::<String>("output").unwrap();
            identity::get_identity(keypair_file, identity_server, username, output_file).await?;
        }
        _ => {
            println!("No valid subcommand provided. Use --help for usage information.");
        }
    }

    Ok(())
}

async fn publish_content(
    keypair_file: &str,
    content: &str,
    server_url: &str,
    post_id: Option<&String>,
    identity_pod_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use num_bigint::BigUint;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;
    use pod2::backends::plonky2::signedpod::Signer;
    use pod2::frontend::{SignedPod, SignedPodBuilder};
    use pod2::middleware::Params;

    println!("Publishing content to server...");
    println!("Content: {content}");

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
    let mut builder = SignedPodBuilder::new(&params);
    
    builder.insert("content_hash", content_hash.as_str());
    builder.insert("timestamp", chrono::Utc::now().timestamp());
    
    // Add post_id to the pod if provided (for adding revision to existing post)
    if let Some(id) = post_id {
        if let Ok(post_id_num) = id.parse::<i64>() {
            builder.insert("post_id", post_id_num);
        }
    }

    let signed_pod = builder.sign(&mut Signer(secret_key))?;
    println!("✓ Document pod signed successfully");

    // Verify the document pod
    signed_pod.verify()?;
    println!("✓ Document pod verification successful");

    // Create the publish request with both document pod and identity pod
    let payload = serde_json::json!({
        "content": content,
        "signed_pod": signed_pod,
        "identity_pod": identity_pod
    });

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{server_url}/publish"))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        println!("✓ Successfully published to server!");
        println!(
            "Server response: {}",
            serde_json::to_string_pretty(&result)?
        );
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "publish content");
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

    // Find all documents (documents are ordered by revision DESC)
    let documents = post
        .get("documents")
        .and_then(|d| d.as_array())
        .ok_or("Post missing documents field")?;

    if documents.is_empty() {
        println!("No documents found for post ID: {post_id}");
        return Ok(());
    }

    // Fetch rendered content for ALL documents
    println!("Fetching all document revisions...");
    let mut document_data = Vec::new();

    for doc in documents.iter() {
        let doc_id = doc.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let doc_revision = doc.get("revision").and_then(|v| v.as_i64()).unwrap_or(0);

        println!("Fetching revision {doc_revision}...");

        // Get rendered version of this document
        let render_response = client
            .get(format!("{server_url}/documents/{doc_id}/render"))
            .send()
            .await?;

        if !render_response.status().is_success() {
            let status = render_response.status();
            let error_text = render_response.text().await?;
            handle_error_response(
                status,
                &error_text,
                &format!("retrieve rendered document {doc_id}"),
            );
            continue; // Skip this document but continue with others
        }

        let rendered_document: serde_json::Value = render_response.json().await?;

        let html_content = rendered_document
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or("Rendered document missing content field")?;
        let (content_id, created_at, _, revision) = extract_document_metadata(&rendered_document);

        // Verify signatures (required)
        println!("Verifying signatures for revision {revision}...");

        // Verify document pod signature (required)
        let pod = rendered_document
            .get("pod")
            .ok_or("Document missing required pod field")?;
        verify_document_pod_signature(pod, None)?;

        // Verify timestamp pod signature (required)
        let timestamp_pod = rendered_document
            .get("timestamp_pod")
            .ok_or("Document missing required timestamp_pod field")?;
        verify_timestamp_pod_signature(timestamp_pod, &server_public_key)?;

        // Get username
        let username = rendered_document
            .get("user_id")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        document_data.push((
            doc_id,
            revision,
            content_id,
            created_at,
            username.to_string(),
            html_content.to_string(),
        ));
    }

    if document_data.is_empty() {
        return Err("No valid documents could be fetched".into());
    }

    // Sort by revision DESC to get latest first
    document_data.sort_by(|a, b| b.1.cmp(&a.1));
    let latest_doc = &document_data[0];

    // Create revision navigation for sidebar and embedded document data
    let mut revision_links = String::new();
    let mut embedded_documents = String::new();

    if document_data.len() > 1 {
        for (i, (doc_id, doc_revision, content_id, doc_created, username, html_content)) in
            document_data.iter().enumerate()
        {
            let is_current = i == 0; // First item is the latest
            let current_class = if is_current { " current" } else { "" };
            let display_style = if is_current { "block" } else { "none" };

            revision_links.push_str(&format!(
                r#"<div class="revision-item{current_class}" data-doc-id="{doc_id}" onclick="showRevision({doc_id})">
                    <div class="revision-link">Revision {doc_revision}</div>
                    <div class="revision-date">{doc_created}</div>
                    {current_indicator}
                </div>"#,
                current_class = current_class,
                doc_id = doc_id,
                doc_revision = doc_revision,
                doc_created = doc_created,
                current_indicator = if is_current { "<div style=\"font-size: 0.8em; color: #28a745; font-weight: bold;\">← Current</div>" } else { "" }
            ));

            // Add hidden div with document content
            embedded_documents.push_str(&format!(
                r#"<div id="document-{doc_id}" class="document-content" style="display: {display_style};" data-content-id="{content_id}" data-created="{doc_created}" data-author="{username}" data-revision="{doc_revision}">
                    {html_content}
                </div>"#,
                doc_id = doc_id,
                display_style = display_style,
                content_id = content_id,
                doc_created = doc_created,
                username = username,
                doc_revision = doc_revision,
                html_content = html_content
            ));
        }
    } else {
        let (doc_id, doc_revision, content_id, doc_created, username, html_content) =
            &document_data[0];
        revision_links.push_str("<div style=\"padding: 10px; color: #666; font-style: italic;\">This post has only one revision.</div>");

        embedded_documents.push_str(&format!(
            r#"<div id="document-{doc_id}" class="document-content" style="display: block;" data-content-id="{content_id}" data-created="{doc_created}" data-author="{username}" data-revision="{doc_revision}">
                {html_content}
            </div>"#,
            doc_id = doc_id,
            content_id = content_id,
            doc_created = doc_created,
            username = username,
            doc_revision = doc_revision,
            html_content = html_content
        ));
    }

    let full_html = create_enhanced_html_document_with_author(
        post_id,
        &latest_doc.2,       // content_id
        &latest_doc.3,       // created_at
        &latest_doc.4,       // username
        &embedded_documents, // all documents embedded
        &revision_links,
    );

    // Write to a temporary file
    let temp_file = format!("/tmp/parcnet-post-{post_id}.html");
    std::fs::write(&temp_file, full_html)?;

    println!(
        "Opening post {post_id} with {} revisions in browser...",
        document_data.len()
    );
    println!("Latest author: {}", latest_doc.4);
    println!("Latest document ID: {}", latest_doc.2);
    println!("Latest revision: {}", latest_doc.1);
    println!("Latest created: {}", latest_doc.3);

    // Open in default browser
    if let Err(e) = webbrowser::open(&temp_file) {
        println!("Failed to open browser: {e}");
        println!("HTML file saved to: {temp_file}");
    } else {
        println!("Opened in browser: {temp_file}");
    }

    Ok(())
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

    println!("{id:<5} {created_at:<20} {last_edited_at:<20} {latest_doc_id:<10}");
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
    let response = client.get(format!("{server_url}/documents")).send().await?;

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
