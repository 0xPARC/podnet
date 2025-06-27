use serde::{Deserialize, Serialize};

use pod2::backends::plonky2::primitives::ec::curve::Point as PublicKey;
use pod2::frontend::{MainPod, SignedPod};

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
    /// Main pod that proves:
    /// - Identity verification: identity pod was signed by registered identity server
    /// - Document verification: document pod was signed by user from identity pod  
    /// - Cross verification: document signer matches identity user_public_key
    /// - Content hash verification: document pod contains correct content hash
    ///
    /// Public data exposed by main pod:
    /// - username: String (verified username from identity pod)
    /// - content_hash: String (verified Poseidon hash of content)
    /// - user_public_key: Point (verified user public key)
    /// - identity_server_pk: Point (verified identity server public key)
    pub main_pod: MainPod,
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
    pub public_key: String,       // Stored as string in DB
    pub registration_pod: String, // Complete signed pod as JSON string
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
