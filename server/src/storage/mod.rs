use std::fs;
use std::path::PathBuf;
use anyhow::Result;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::config::Hasher;

pub struct ContentAddressedStorage {
    base_path: PathBuf,
}

impl ContentAddressedStorage {
    pub fn new(base_path: &str) -> Result<Self> {
        let path = PathBuf::from(base_path);
        fs::create_dir_all(&path)?;
        Ok(Self { base_path: path })
    }

    pub fn hash_content(content: &str) -> String {
        // Convert content bytes to Goldilocks field elements for Poseidon
        let bytes = content.as_bytes();
        let mut inputs = Vec::new();
        
        // Process bytes in chunks of 8 (64-bit field elements)
        for chunk in bytes.chunks(8) {
            let mut padded = [0u8; 8];
            padded[..chunk.len()].copy_from_slice(chunk);
            let value = u64::from_le_bytes(padded);
            inputs.push(GoldilocksField::from_canonical_u64(value));
        }
        
        // Pad to multiple of 4 for Poseidon (if needed)
        while inputs.len() % 4 != 0 {
            inputs.push(GoldilocksField::ZERO);
        }
        
        let hash_result = PoseidonHash::hash_no_pad(&inputs);
        // Convert full hash result to bytes (all 4 elements)
        let mut hash_bytes = Vec::new();
        for element in hash_result.elements {
            hash_bytes.extend_from_slice(&element.to_canonical_u64().to_le_bytes());
        }
        hex::encode(hash_bytes)
    }

    pub fn get_file_path(&self, hash: &str) -> PathBuf {
        let prefix = &hash[0..2];
        let suffix = &hash[2..];
        self.base_path.join(prefix).join(suffix)
    }

    pub fn store(&self, content: &str) -> Result<String> {
        let hash = Self::hash_content(content);
        let file_path = self.get_file_path(&hash);
        
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        if !file_path.exists() {
            fs::write(&file_path, content)?;
        }
        
        Ok(hash)
    }

    pub fn retrieve(&self, hash: &str) -> Result<Option<String>> {
        let file_path = self.get_file_path(hash);
        
        if file_path.exists() {
            let content = fs::read_to_string(file_path)?;
            Ok(Some(content))
        } else {
            Ok(None)
        }
    }

    pub fn exists(&self, hash: &str) -> bool {
        self.get_file_path(hash).exists()
    }
}