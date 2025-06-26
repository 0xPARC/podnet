mod db;
mod handlers;
mod models;
mod storage;

use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub struct AppState {
    pub db: Arc<db::Database>,
    pub storage: Arc<storage::ContentAddressedStorage>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db = Arc::new(db::Database::new("app.db").await?);
    let storage = Arc::new(storage::ContentAddressedStorage::new("content")?);

    let state = Arc::new(AppState { db, storage });

    let app = Router::new()
        .route("/", get(handlers::root))
        // Publish route (combined content + pod storage)
        .route("/:id", get(handlers::get_post_by_id))
        .route("/render/:id", get(handlers::get_rendered_post_by_id))
        .route("/list", get(handlers::get_posts))
        .route("/publish", post(handlers::publish_post))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Server running on http://localhost:3000");

    axum::serve(listener, app).await?;
    Ok(())
}
