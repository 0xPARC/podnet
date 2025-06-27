use crate::models::{Document, IdentityServer, Post, User};
use rusqlite::{Connection, OptionalExtension, Result};
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub async fn new(db_path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(db_path)?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        // Create posts table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_edited_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Create documents table (revisions of posts)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_id TEXT NOT NULL,
                post_id INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                pod TEXT NOT NULL,
                timestamp_pod TEXT,
                user_id TEXT NOT NULL,
                FOREIGN KEY (post_id) REFERENCES posts (id),
                UNIQUE (post_id, revision)
            )",
            [],
        )?;

        // Create users table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Create identity_servers table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS identity_servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                registration_pod TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        Ok(())
    }

    // Post methods
    pub fn create_post(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute("INSERT INTO posts DEFAULT VALUES", [])?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_post(&self, id: i64) -> Result<Option<Post>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id, created_at, last_edited_at FROM posts WHERE id = ?1")?;

        let post = stmt
            .query_row([id], |row| {
                Ok(Post {
                    id: Some(row.get(0)?),
                    created_at: Some(row.get(1)?),
                    last_edited_at: Some(row.get(2)?),
                })
            })
            .optional()?;

        Ok(post)
    }

    pub fn get_all_posts(&self) -> Result<Vec<Post>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, created_at, last_edited_at FROM posts ORDER BY last_edited_at DESC",
        )?;

        let posts = stmt
            .query_map([], |row| {
                Ok(Post {
                    id: Some(row.get(0)?),
                    created_at: Some(row.get(1)?),
                    last_edited_at: Some(row.get(2)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(posts)
    }

    pub fn update_post_last_edited(&self, post_id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE posts SET last_edited_at = CURRENT_TIMESTAMP WHERE id = ?1",
            [post_id],
        )?;
        Ok(())
    }

    // Document methods
    pub fn create_document(
        &self,
        content_id: &str,
        post_id: i64,
        pod_json: &str,
        user_id: &str,
        timestamp_pod_json: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();

        // Get the next revision number for this post
        let next_revision: i64 = conn.query_row(
            "SELECT COALESCE(MAX(revision), 0) + 1 FROM documents WHERE post_id = ?1",
            [post_id],
            |row| row.get(0),
        )?;

        conn.execute(
            "INSERT INTO documents (content_id, post_id, revision, pod, timestamp_pod, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                content_id,
                post_id,
                next_revision,
                pod_json,
                timestamp_pod_json,
                user_id,
            ],
        )?;

        // Update the post's last_edited_at timestamp (within same connection lock)
        conn.execute(
            "UPDATE posts SET last_edited_at = CURRENT_TIMESTAMP WHERE id = ?1",
            [post_id],
        )?;

        Ok(conn.last_insert_rowid())
    }

    pub fn update_document_timestamp_pod(
        &self,
        document_id: i64,
        timestamp_pod_json: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE documents SET timestamp_pod = ?1 WHERE id = ?2",
            [timestamp_pod_json, &document_id.to_string()],
        )?;
        Ok(())
    }

    pub fn get_document(&self, id: i64) -> Result<Option<Document>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, content_id, post_id, revision, created_at, pod, timestamp_pod, user_id FROM documents WHERE id = ?1"
        )?;

        let document = stmt
            .query_row([id], |row| {
                Ok(Document {
                    id: Some(row.get(0)?),
                    content_id: row.get(1)?,
                    post_id: row.get(2)?,
                    revision: row.get(3)?,
                    created_at: Some(row.get(4)?),
                    pod: row.get(5)?,
                    timestamp_pod: row.get(6)?,
                    user_id: row.get(7)?,
                })
            })
            .optional()?;

        Ok(document)
    }

    pub fn get_documents_by_post_id(&self, post_id: i64) -> Result<Vec<Document>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, content_id, post_id, revision, created_at, pod, timestamp_pod, user_id 
             FROM documents WHERE post_id = ?1 ORDER BY revision DESC",
        )?;

        let documents = stmt
            .query_map([post_id], |row| {
                Ok(Document {
                    id: Some(row.get(0)?),
                    content_id: row.get(1)?,
                    post_id: row.get(2)?,
                    revision: row.get(3)?,
                    created_at: Some(row.get(4)?),
                    pod: row.get(5)?,
                    timestamp_pod: row.get(6)?,
                    user_id: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(documents)
    }

    pub fn get_latest_document_by_post_id(&self, post_id: i64) -> Result<Option<Document>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, content_id, post_id, revision, created_at, pod, timestamp_pod, user_id 
             FROM documents WHERE post_id = ?1 ORDER BY revision DESC LIMIT 1",
        )?;

        let document = stmt
            .query_row([post_id], |row| {
                Ok(Document {
                    id: Some(row.get(0)?),
                    content_id: row.get(1)?,
                    post_id: row.get(2)?,
                    revision: row.get(3)?,
                    created_at: Some(row.get(4)?),
                    pod: row.get(5)?,
                    timestamp_pod: row.get(6)?,
                    user_id: row.get(7)?,
                })
            })
            .optional()?;

        Ok(document)
    }

    pub fn get_all_documents(&self) -> Result<Vec<Document>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, content_id, post_id, revision, created_at, pod, timestamp_pod, user_id 
             FROM documents ORDER BY created_at DESC",
        )?;

        let documents = stmt
            .query_map([], |row| {
                Ok(Document {
                    id: Some(row.get(0)?),
                    content_id: row.get(1)?,
                    post_id: row.get(2)?,
                    revision: row.get(3)?,
                    created_at: Some(row.get(4)?),
                    pod: row.get(5)?,
                    timestamp_pod: row.get(6)?,
                    user_id: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(documents)
    }

    // User methods
    pub fn create_user(&self, user_id: &str, public_key: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (user_id, public_key) VALUES (?1, ?2)",
            [user_id, public_key],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, user_id, public_key, created_at FROM users WHERE user_id = ?1")?;

        let user = stmt
            .query_row([user_id], |row| {
                Ok(User {
                    id: Some(row.get(0)?),
                    user_id: row.get(1)?,
                    public_key: row.get(2)?,
                    created_at: Some(row.get(3)?),
                })
            })
            .optional()?;

        Ok(user)
    }

    pub fn get_user_by_public_key(&self, public_key: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user_id, public_key, created_at FROM users WHERE public_key = ?1",
        )?;

        let user = stmt
            .query_row([public_key], |row| {
                Ok(User {
                    id: Some(row.get(0)?),
                    user_id: row.get(1)?,
                    public_key: row.get(2)?,
                    created_at: Some(row.get(3)?),
                })
            })
            .optional()?;

        Ok(user)
    }

    // Identity server methods
    pub fn create_identity_server(
        &self,
        server_id: &str,
        public_key: &str,
        registration_pod: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO identity_servers (server_id, public_key, registration_pod) VALUES (?1, ?2, ?3)",
            [server_id, public_key, registration_pod],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_identity_server_by_id(&self, server_id: &str) -> Result<Option<IdentityServer>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, server_id, public_key, registration_pod, created_at FROM identity_servers WHERE server_id = ?1",
        )?;

        let identity_server = stmt
            .query_row([server_id], |row| {
                Ok(IdentityServer {
                    id: Some(row.get(0)?),
                    server_id: row.get(1)?,
                    public_key: row.get(2)?,
                    registration_pod: row.get(3)?,
                    created_at: Some(row.get(4)?),
                })
            })
            .optional()?;

        Ok(identity_server)
    }

    pub fn get_identity_server_by_public_key(&self, public_key: &str) -> Result<Option<IdentityServer>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, server_id, public_key, registration_pod, created_at FROM identity_servers WHERE public_key = ?1",
        )?;

        let identity_server = stmt
            .query_row([public_key], |row| {
                Ok(IdentityServer {
                    id: Some(row.get(0)?),
                    server_id: row.get(1)?,
                    public_key: row.get(2)?,
                    registration_pod: row.get(3)?,
                    created_at: Some(row.get(4)?),
                })
            })
            .optional()?;

        Ok(identity_server)
    }

    pub fn get_all_identity_servers(&self) -> Result<Vec<IdentityServer>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, server_id, public_key, registration_pod, created_at FROM identity_servers ORDER BY created_at DESC",
        )?;

        let identity_servers = stmt
            .query_map([], |row| {
                Ok(IdentityServer {
                    id: Some(row.get(0)?),
                    server_id: row.get(1)?,
                    public_key: row.get(2)?,
                    registration_pod: row.get(3)?,
                    created_at: Some(row.get(4)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(identity_servers)
    }
}
