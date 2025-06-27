use serde::{Deserialize, Serialize};

use pod2::backends::plonky2::primitives::ec::curve::Point as PublicKey;
use pod2::frontend::SignedPod;

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
    /// Document pod containing:
    /// - content_hash: String (Poseidon hash of content)
    /// - timestamp: i64 (Unix timestamp when document was created)
    /// - post_id: Option<i64> (if provided, add as new revision to existing post)
    /// - _signer: Point (author's public key, automatically added by SignedPod)
    pub signed_pod: SignedPod,
    /// Identity pod from identity server containing:
    /// - username: String (user's chosen username)
    /// - user_public_key: Point (user's public key, should match document pod signer)
    /// - identity_server_id: String (ID of the identity server that issued this)
    /// - _signer: Point (identity server's public key, automatically added by SignedPod)
    pub identity_pod: SignedPod,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityServer {
    pub id: Option<i64>,
    pub server_id: String,
    pub public_key: String,        // Stored as string in DB
    pub registration_pod: String,  // Complete signed pod as JSON string
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityServerRegistration {
    /// SignedPod containing:
    /// - challenge: String (challenge sent by podnet-server)
    /// - server_id: String (unique identifier for this identity server)
    /// - public_key: Point (identity server's public key)
    /// - _signer: Point (same as public_key, automatically added by SignedPod)
    pub challenge_response: SignedPod,
}
