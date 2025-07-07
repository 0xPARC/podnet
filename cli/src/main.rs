mod cli;
mod commands;
mod conversion;
mod utils;
mod verification;

use clap::{Arg, Command};
use hex::ToHex;
use podnet_models::{mainpod::publish::verify_publish_verification, mainpod::upvote_count::verify_upvote_count};

use cli::*;
use commands::{keygen, identity, documents, posts, publish, upvote};
use utils::*;
use verification::*;


fn render_to_html(
    id: &str,
    content_id: &str,
    timestamp: &str,
    uploader: &str,
    tags: &std::collections::HashSet<String>,
    authors: &std::collections::HashSet<String>,
    html_content: &str,
    revision_links: &str,
) -> String {
    // Format tags for display
    let tags_display = if tags.is_empty() {
        "None".to_string()
    } else {
        let tag_list: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
        tag_list.join(", ")
    };

    let authors_display = if authors.is_empty() {
        "None".to_string()
    } else {
        let authors_list: Vec<&str> = authors.iter().map(|s| s.as_str()).collect();
        authors_list.join(", ")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PodNet Content - Post {id}</title>
    <script>
MathJax = {{
  tex: {{
    inlineMath: [['$', '$'], ['\\(', '\\)']],
    displayMath: [['$$', '$$'], ['\\[', '\\]']],
    processEscapes: true,
    processEnvironments: true,
    packages: {{'[+]': ['textcomp', 'textmacros']}},
    macros: {{
      textbf: ['\\mathbf{{#1}}', 1],
      texttt: ['\\mathtt{{#1}}', 1]
    }}
  }},
  options: {{
    ignoreHtmlClass: 'tex2jax_ignore',
    processHtmlClass: 'tex2jax_process'
  }}
}};
</script>
<script type="text/javascript" id="MathJax-script" async
  src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js">
</script>
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
                const uploader = selectedDoc.getAttribute('data-uploader') || 'Unknown';
                const revision = selectedDoc.getAttribute('data-revision') || 'N/A';
                
                metadata.innerHTML = `
                    <div><strong>Post ID:</strong> {id}</div>
                    <div><strong>Uploader:</strong> ${{uploader}}</div>
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
            <h1>PodNet Content</h1>
            <div class="metadata">
                <div><strong>Post ID:</strong> {id}</div>
                <div><strong>Uploader:</strong> {uploader}</div>
                <div><strong>Authors:</strong> {authors_display}</div>
                <div><strong>Content Hash:</strong> <code>{content_id}</code></div>
                <div><strong>Timestamp:</strong> {timestamp}</div>
                <div><strong>Tags:</strong> {tags_display}</div>
            </div>
        </div>
        <div id="main-content" class="content">
            {html_content}
        </div>
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
                ]),
        )
        .subcommand(
            Command::new("publish")
                .about("Sign content and submit to server using main pod verification (creates new post or adds revision)")
                .args([
                    keypair_arg(), 
                    server_arg(), 
                    optional_post_id_arg(),
                    Arg::new("identity_pod")
                        .help("Path to identity pod file")
                        .short('i')
                        .long("identity-pod")
                        .required(true),
                    Arg::new("mock")
                        .help("Use mock prover for faster development")
                        .long("mock")
                        .action(clap::ArgAction::SetTrue),
                    Arg::new("tags")
                        .help("Comma-separated list of tags for document organization")
                        .short('t')
                        .long("tags")
                        .value_name("TAG1,TAG2,TAG3"),
                    Arg::new("authors")
                        .help("Optional comma-separated list of authors for document attribution (defaults to uploader)")
                        .short('a')
                        .long("authors")
                        .value_name("AUTHOR1,AUTHOR2,AUTHOR3"),
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
        .subcommand(
            Command::new("upvote")
                .about("Upvote a document with cryptographic verification using main pod")
                .args([
                    keypair_arg(),
                    server_arg(),
                    document_id_arg(),
                    identity_pod_arg(),
                    mock_arg(),
                ]),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("keygen", sub_matches)) => {
            let output_file = sub_matches.get_one::<String>("output").unwrap();
            keygen::generate_keypair(output_file)?;
        }
        Some(("publish", sub_matches)) => {
            let keypair_file = sub_matches.get_one::<String>("keypair").unwrap();
            let content = get_content_from_args(sub_matches)?;
            let file_path = sub_matches.get_one::<String>("file");
            let format_override = sub_matches.get_one::<String>("format");
            let server = sub_matches.get_one::<String>("server").unwrap();
            let post_id = sub_matches.get_one::<String>("post_id");
            let identity_pod_file = sub_matches.get_one::<String>("identity_pod").unwrap();
            let use_mock = sub_matches.get_flag("mock");
            let tags = sub_matches.get_one::<String>("tags");
            let authors = sub_matches.get_one::<String>("authors");
            publish::publish_content(keypair_file, &content, file_path, format_override, server, post_id, identity_pod_file, use_mock, tags, authors).await?;
        }
        Some(("get-post", sub_matches)) => {
            let post_id = sub_matches.get_one::<String>("post_id").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            posts::get_post_by_id(post_id, server).await?;
        }
        Some(("view", sub_matches)) => {
            let post_id = sub_matches.get_one::<String>("post_id").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            view_post_in_browser(post_id, server).await?;
        }
        Some(("list-posts", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            posts::list_posts(server).await?;
        }
        Some(("list-documents", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            documents::list_documents(server).await?;
        }
        Some(("get-identity", sub_matches)) => {
            let keypair_file = sub_matches.get_one::<String>("keypair").unwrap();
            let identity_server = sub_matches.get_one::<String>("identity_server").unwrap();
            let username = sub_matches.get_one::<String>("username").unwrap();
            let output_file = sub_matches.get_one::<String>("output").unwrap();
            identity::get_identity(keypair_file, identity_server, username, output_file).await?;
        }
        Some(("upvote", sub_matches)) => {
            let keypair_file = sub_matches.get_one::<String>("keypair").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            let document_id = sub_matches.get_one::<String>("document_id").unwrap();
            let identity_pod = sub_matches.get_one::<String>("identity_pod").unwrap();
            let use_mock = sub_matches.get_flag("mock");
            upvote::upvote_document(keypair_file, document_id, server, identity_pod, use_mock).await?;
        }
        _ => {
            println!("No valid subcommand provided. Use --help for usage information.");
        }
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

        // Parse the document directly using the shared types
        let document: podnet_models::Document = serde_json::from_value(rendered_document.clone())
            .map_err(|e| format!("Failed to parse document: {e}"))?;

        let html_content = &document.content;
        
        let content_id = document.metadata.content_id;
        let created_at = document.metadata.created_at.as_deref().unwrap_or("Unknown").to_string();
        let revision = document.metadata.revision;
        let uploader_username = document.metadata.uploader_id.clone();
        let upvote_count = document.metadata.upvote_count;
        let tags = document.metadata.tags.clone();
        let authors = document.metadata.authors.clone();

        // Verify signatures (required)
        println!("Verifying signatures for revision {revision}...");
        verify_publish_verification(&document.metadata.pod, &content_id, &uploader_username, post_id.parse()?, &tags)
            .map_err(|e| format!("MainPod verification failed: {e}"))?;
        println!("Main pod: {}", document.metadata.pod);
        println!("✓ Main pod verification completed");

        // Verify timestamp pod signature (required)
        println!("Verifying timestamp pod signature...");
        println!("Timestamp pod: {}", document.metadata.timestamp_pod);
        
        // Convert SignedPod to JSON value for verification function
        let timestamp_pod_json = serde_json::to_value(&document.metadata.timestamp_pod)
            .map_err(|e| format!("Failed to serialize timestamp pod: {e}"))?;
        verify_timestamp_pod_signature(&timestamp_pod_json, &server_public_key)?;

        // Verify upvote count pod if present (optional)
        if let Some(upvote_count_pod) = &document.metadata.upvote_count_pod {
            println!("Verifying upvote count pod...");
            verify_upvote_count(upvote_count_pod, upvote_count, &content_id)
                .map_err(|e| format!("Upvote count MainPod verification failed: {e}"))?;
            println!("✓ Upvote count MainPod verification completed (count: {upvote_count})");
        } else if upvote_count > 0 {
            println!("⚠️  Warning: Document claims {upvote_count} upvotes but no upvote count proof provided");
        }

        document_data.push((
            doc_id,
            revision,
            content_id,
            created_at,
            uploader_username.to_string(),
            html_content.to_string(),
            upvote_count,
            tags,
            authors
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
        for (i, (doc_id, doc_revision, content_id, doc_created, username, html_content, upvote_count, _, _)) in
            document_data.iter().enumerate()
        {
            let is_current = i == 0; // First item is the latest
            let current_class = if is_current { " current" } else { "" };
            let display_style = if is_current { "block" } else { "none" };

            revision_links.push_str(&format!(
                r#"<div class="revision-item{current_class}" data-doc-id="{doc_id}" onclick="showRevision({doc_id})">
                    <div class="revision-link">Revision {doc_revision}</div>
                    <div class="revision-date">{doc_created}</div>
                    <div class="upvote-count">👍 {upvote_count}</div>
                    {current_indicator}
                </div>"#,
                current_class = current_class,
                doc_id = doc_id,
                doc_revision = doc_revision,
                doc_created = doc_created,
                upvote_count = upvote_count,
                current_indicator = if is_current { "<div style=\"font-size: 0.8em; color: #28a745; font-weight: bold;\">← Current</div>" } else { "" }
            ));

            // Add hidden div with document content
            embedded_documents.push_str(&format!(
                r#"<div id="document-{doc_id}" class="document-content" style="display: {display_style};" data-content-id="{content_id}" data-created="{doc_created}" data-uploader="{username}" data-revision="{doc_revision}" data-upvotes="{upvote_count}">
                    {html_content}
                </div>"#
            ));
        }
    } else {
        let (doc_id, doc_revision, content_id, doc_created, username, html_content, upvote_count, _tags, _authors) =
            &document_data[0];
        revision_links.push_str(&format!(
            r#"<div style="padding: 10px; color: #666; font-style: italic;">
                This post has only one revision.
                <div class="upvote-count" style="margin-top: 5px; color: #333;">👍 {upvote_count}</div>
            </div>"#
        ));

        embedded_documents.push_str(&format!(
            r#"<div id="document-{doc_id}" class="document-content" style="display: block;" data-content-id="{content_id}" data-created="{doc_created}" data-uploader="{username}" data-revision="{doc_revision}" data-upvotes="{upvote_count}">
                {html_content}
            </div>"#
        ));
    }

    let content_id_hex: String = latest_doc.2.encode_hex();
    let full_html = render_to_html(
        post_id,
        &content_id_hex,       // content_id
        &latest_doc.3,       // created_at
        &latest_doc.4,       // uploader_username
        &latest_doc.7,       // tags
        &latest_doc.8,       // authors
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
    println!("Latest uploader: {}", latest_doc.4);
    println!("Latest document ID: {}", latest_doc.2);
    println!("Latest revision: {}", latest_doc.1);
    println!("Latest created: {}", latest_doc.3);
    println!("Latest upvotes: {}", latest_doc.6);

    // Open in default browser
    if let Err(e) = webbrowser::open(&temp_file) {
        println!("Failed to open browser: {e}");
        println!("HTML file saved to: {temp_file}");
    } else {
        println!("Opened in browser: {temp_file}");
    }

    Ok(())
}

