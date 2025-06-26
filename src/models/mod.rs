use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Post {
    pub id: Option<i64>,
    pub title: String,
    pub content_hash: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PostWithContent {
    pub id: Option<i64>,
    pub title: String,
    pub content: String,
    pub content_hash: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MarkdownResponse {
    pub html: String,
}

// New pod-based models
#[derive(Debug, Serialize, Deserialize)]
pub struct PodEntry {
    pub id: Option<i64>,
    pub content_id: String,
    pub timestamp: Option<String>,
    pub pod: String, // JSON string of the signed pod
}

// TODO: move metadata into metadata struct,
// and content is separate?
#[derive(Debug, Serialize)]
pub struct PodEntryWithContent {
    pub id: Option<i64>,
    pub content_id: String,
    pub timestamp: Option<String>,
    pub pod: serde_json::Value,
    pub content: Option<String>, // Retrieved from storage if available
}

#[derive(Debug, Serialize)]
pub struct PodEntryMetadata {
    pub id: Option<i64>,
    pub content_id: String,
    pub timestamp: Option<String>,
    pub pod: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct PublishRequest {
    pub content: String,
    pub signed_pod: serde_json::Value,
    pub public_key: String,
}

