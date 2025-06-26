use rusqlite::{Connection, Result, OptionalExtension};
use std::sync::Mutex;
use crate::models::{Post, PodEntry};

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub async fn new(db_path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(db_path)?;
        let db = Database { conn: Mutex::new(conn) };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pod_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                pod TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    pub fn create_pod_entry(&self, content_id: &str, pod_json: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO pod_entries (content_id, pod) VALUES (?1, ?2)",
            [content_id, pod_json],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_pod_entry(&self, id: i64) -> Result<Option<PodEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, content_id, timestamp, pod FROM pod_entries WHERE id = ?1"
        )?;
        
        let entry = stmt.query_row([id], |row| {
            Ok(PodEntry {
                id: Some(row.get(0)?),
                content_id: row.get(1)?,
                timestamp: Some(row.get(2)?),
                pod: row.get(3)?,
            })
        }).optional()?;
        
        Ok(entry)
    }

    pub fn get_all_pod_entries(&self) -> Result<Vec<PodEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, content_id, timestamp, pod FROM pod_entries ORDER BY timestamp DESC"
        )?;
        
        let entries = stmt.query_map([], |row| {
            Ok(PodEntry {
                id: Some(row.get(0)?),
                content_id: row.get(1)?,
                timestamp: Some(row.get(2)?),
                pod: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        
        Ok(entries)
    }

    pub fn get_pod_entries_by_content_id(&self, content_id: &str) -> Result<Vec<PodEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, content_id, timestamp, pod FROM pod_entries WHERE content_id = ?1 ORDER BY timestamp DESC"
        )?;
        
        let entries = stmt.query_map([content_id], |row| {
            Ok(PodEntry {
                id: Some(row.get(0)?),
                content_id: row.get(1)?,
                timestamp: Some(row.get(2)?),
                pod: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        
        Ok(entries)
    }

    // Legacy methods for compatibility
    pub fn create_post(&self, title: &str, content_hash: &str) -> Result<i64> {
        // For now, create a dummy pod entry for legacy support
        let pod_json = serde_json::json!({
            "legacy": true,
            "title": title
        }).to_string();
        self.create_pod_entry(content_hash, &pod_json)
    }

    pub fn get_post(&self, id: i64) -> Result<Option<Post>> {
        match self.get_pod_entry(id)? {
            Some(entry) => {
                // Convert pod entry back to legacy post format
                if let Ok(pod) = serde_json::from_str::<serde_json::Value>(&entry.pod) {
                    let title = pod.get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Untitled")
                        .to_string();
                    
                    Ok(Some(Post {
                        id: entry.id,
                        title,
                        content_hash: entry.content_id,
                        created_at: entry.timestamp,
                    }))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    pub fn get_all_posts(&self) -> Result<Vec<Post>> {
        let entries = self.get_all_pod_entries()?;
        let mut posts = Vec::new();
        
        for entry in entries {
            if let Ok(pod) = serde_json::from_str::<serde_json::Value>(&entry.pod) {
                if pod.get("legacy").and_then(|v| v.as_bool()).unwrap_or(false) {
                    let title = pod.get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Untitled")
                        .to_string();
                    
                    posts.push(Post {
                        id: entry.id,
                        title,
                        content_hash: entry.content_id,
                        created_at: entry.timestamp,
                    });
                }
            }
        }
        
        Ok(posts)
    }
}