use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use pulldown_cmark::{Options, Parser, html};
use std::sync::Arc;

use crate::models::{PodEntryMetadata, PodEntryWithContent, PublishRequest};

fn validate_signed_pod(pod: &serde_json::Value) -> Result<(), StatusCode> {
    // Check if podType exists and is an array
    let pod_type = pod.get("podType")
        .and_then(|v| v.as_array())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Verify podType has exactly 2 elements
    if pod_type.len() != 2 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check first element is the number 4
    let type_number = pod_type[0].as_i64().ok_or(StatusCode::BAD_REQUEST)?;
    if type_number != 4 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check second element is the string "Signed"
    let type_string = pod_type[1].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    if type_string != "Signed" {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify pod has required structure (data field with signature)
    pod.get("data")
        .and_then(|d| d.get("signature"))
        .ok_or(StatusCode::BAD_REQUEST)?;

    Ok(())
}

fn verify_public_key(pod: &serde_json::Value, provided_public_key: &str) -> Result<(), StatusCode> {
    // Extract the public key from the pod's signer field
    let pod_public_key = pod
        .pointer("/data/kvs/kvs/_signer/PublicKey")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Verify the provided public key matches the one in the pod
    if pod_public_key != provided_public_key {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

pub async fn root() -> &'static str {
    "Axum server with SQLite and Markdown rendering"
}

pub async fn get_posts(
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<Vec<PodEntryMetadata>>, StatusCode> {
    match state.db.get_all_pod_entries() {
        Ok(entries) => {
            let mut entries_metadata = Vec::new();
            for entry in entries {
                let pod_value: serde_json::Value = serde_json::from_str(&entry.pod)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                entries_metadata.push(PodEntryMetadata {
                    id: entry.id,
                    content_id: entry.content_id,
                    timestamp: entry.timestamp,
                    pod: pod_value,
                });
            }
            Ok(Json(entries_metadata))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_post_from_db(
    id: i64,
    state: Arc<crate::AppState>,
) -> Result<PodEntryWithContent, StatusCode> {
    match state.db.get_pod_entry(id) {
        Ok(Some(entry)) => {
            let content = state.storage.retrieve(&entry.content_id).ok().flatten();

            let pod_value: serde_json::Value =
                serde_json::from_str(&entry.pod).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            Ok(PodEntryWithContent {
                id: entry.id,
                content_id: entry.content_id,
                timestamp: entry.timestamp,
                pod: pod_value,
                content,
            })
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_post_by_id(
    Path(id): Path<i64>,
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<PodEntryWithContent>, StatusCode> {
    let post = get_post_from_db(id, state).await?;
    Ok(Json(post))
}

pub async fn get_rendered_post_by_id(
    Path(id): Path<i64>,
    State(state): State<Arc<crate::AppState>>,
) -> Result<Json<PodEntryWithContent>, StatusCode> {
    let mut post = get_post_from_db(id, state).await?;

    if post.content.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);

    let content = &post.content.unwrap();
    let parser = Parser::new_ext(content, options);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    post.content = Some(html_output.clone());

    Ok(Json(post))
}

pub async fn publish_post(
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<PublishRequest>,
) -> Result<Json<PodEntryWithContent>, StatusCode> {
    // Validate pod type and structure
    validate_signed_pod(&payload.signed_pod)?;
    
    // Verify the public key matches the signer in the pod
    verify_public_key(&payload.signed_pod, &payload.public_key)?;

    // Store the content and get its hash
    let content_hash = match state.storage.store(&payload.content) {
        Ok(hash) => hash,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Convert signed pod to JSON string
    let pod_json =
        serde_json::to_string(&payload.signed_pod).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Store pod entry in database
    match state.db.create_pod_entry(&content_hash, &pod_json) {
        Ok(id) => match state.db.get_pod_entry(id) {
            Ok(Some(entry)) => Ok(Json(PodEntryWithContent {
                id: entry.id,
                content_id: entry.content_id,
                timestamp: entry.timestamp,
                pod: payload.signed_pod,
                content: Some(payload.content),
            })),
            _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
        },
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
