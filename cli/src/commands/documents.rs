use crate::utils::{
    extract_document_metadata, handle_error_response, truncate_pod_json,
};

pub async fn get_document_by_id(
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
            let upvote_count = document.pointer("/metadata/upvote_count").and_then(|v| v.as_i64()).unwrap_or(0);
            print_document_metadata(&content_id, &created_at, post_id, revision, upvote_count);
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

pub async fn render_document_by_id(
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
            let upvote_count = document.pointer("/metadata/upvote_count").and_then(|v| v.as_i64()).unwrap_or(0);
            print_document_metadata(&content_id, &created_at, post_id, revision, upvote_count);
            println!("Rendered HTML:\n{content}");
        } else {
            println!("No content found for document ID: {document_id}");
        }
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "render document");
    }

    Ok(())
}

pub async fn list_documents(server_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.get(format!("{server_url}/documents")).send().await?;

    if response.status().is_success() {
        let documents: serde_json::Value = response.json().await?;

        if let Some(documents_array) = documents.as_array() {
            if documents_array.is_empty() {
                println!("No documents found.");
                return Ok(());
            }

            println!("Available documents:");
            println!(
                "{:<6} {:<12} {:<8} {:<8} {:<20} {:<66} {:<52} {:<52}",
                "ID", "Post", "Rev", "Upvotes", "Created", "Content Hash", "Main Pod", "Timestamp Pod"
            );
            println!("{}", "-".repeat(258));

            for document in documents_array {
                print_document_row(document);
            }
        } else {
            println!("Invalid response format from server.");
        }
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        handle_error_response(status, &error_text, "list documents");
    }

    println!(
        "\nUse 'get-document --document-id <ID>' to retrieve document or 'view --post-id <POST_ID>' to open latest document in browser."
    );

    Ok(())
}

fn print_document_metadata(content_id: &str, created_at: &str, post_id: i64, revision: i64, upvote_count: i64) {
    println!("Document Metadata:");
    println!("  Content ID: {content_id}");
    println!("  Post ID: {post_id}");
    println!("  Revision: {revision}");
    println!("  Created: {created_at}");
    println!("  Upvotes: {upvote_count}");
    println!();
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
    let upvote_count = document
        .get("upvote_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let created_at = document
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    // Truncate content_id for display
    let display_content_id = if content_id.len() > 64 {
        format!("{}...", &content_id[0..61])
    } else {
        content_id.to_string()
    };

    // Get main pod and timestamp pod (server sends as JSON objects)
    let main_pod = document
        .get("pod")
        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "Invalid JSON".to_string()))
        .unwrap_or("N/A".to_string());
    let timestamp_pod = document
        .get("timestamp_pod")
        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "Invalid JSON".to_string()))
        .unwrap_or("N/A".to_string());

    println!(
        "{:<6} {:<12} {:<8} {:<8} {:<20} {:<66} {:<52} {:<52}",
        id,
        post_id,
        revision,
        upvote_count,
        created_at,
        display_content_id,
        truncate_pod_json(&main_pod),
        truncate_pod_json(&timestamp_pod)
    );
}

