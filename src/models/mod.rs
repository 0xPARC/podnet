use serde::{Deserialize, Serialize};

use pod2::backends::plonky2::primitives::ec::curve::Point as PublicKey;

#[derive(Debug, Serialize, Deserialize)]
pub struct Post {
    pub id: Option<i64>,
    pub created_at: Option<String>,
    pub last_edited_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Document {
    pub id: Option<i64>,
    pub content_id: String,
    pub post_id: i64,
    pub revision: i64,
    pub created_at: Option<String>,
    pub pod: String,                   // JSON string of the signed pod
    pub timestamp_pod: Option<String>, // JSON string of the server timestamp pod
    pub user_id: String,               // Username of the author
}

#[derive(Debug, Serialize)]
pub struct PostWithDocuments {
    pub id: Option<i64>,
    pub created_at: Option<String>,
    pub last_edited_at: Option<String>,
    pub documents: Vec<DocumentWithContent>,
}

#[derive(Debug, Serialize)]
pub struct DocumentWithContent {
    pub id: Option<i64>,
    pub content_id: String,
    pub post_id: i64,
    pub revision: i64,
    pub created_at: Option<String>,
    pub pod: serde_json::Value,
    pub content: Option<String>, // Retrieved from storage if available
    pub timestamp_pod: Option<serde_json::Value>, // Server-signed timestamp pod
    pub user_id: String,         // Username of the author
}

#[derive(Debug, Serialize)]
pub struct DocumentMetadata {
    pub id: Option<i64>,
    pub content_id: String,
    pub post_id: i64,
    pub revision: i64,
    pub created_at: Option<String>,
    pub pod: serde_json::Value,
    pub timestamp_pod: Option<serde_json::Value>,
    pub user_id: String, // Username of the author
}

#[derive(Debug, Deserialize)]
pub struct PublishRequest {
    pub content: String,
    pub signed_pod: serde_json::Value,
    pub post_id: Option<i64>, // If provided, add as new revision to existing post
}

#[derive(Debug, Serialize)]
pub struct MarkdownResponse {
    pub html: String,
}

#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub public_key: PublicKey,
}

#[derive(Debug, Deserialize)]
pub struct UserRegistration {
    pub user_id: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Option<i64>,
    pub user_id: String,
    pub public_key: String,
    pub created_at: Option<String>,
}
