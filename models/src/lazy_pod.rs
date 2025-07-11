use std::sync::OnceLock;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::marker::PhantomData;

/// A generic lazy deserialization wrapper that deserializes JSON only when accessed
#[derive(Debug, Clone)]
pub struct LazyDeser<T> {
    json: String,
    value: OnceLock<T>,
    _phantom: PhantomData<T>,
}

// Manual implementation of Serialize to serialize transparently as the JSON value
impl<T> Serialize for LazyDeser<T>
where
    T: DeserializeOwned + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;
        
        // Parse the JSON string and serialize the actual value
        let value: serde_json::Value = serde_json::from_str(&self.json)
            .map_err(S::Error::custom)?;
        value.serialize(serializer)
    }
}

// Manual implementation of Deserialize to deserialize transparently from the JSON value
impl<'de, T> Deserialize<'de> for LazyDeser<T>
where
    T: DeserializeOwned + Serialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        
        // Deserialize as a JSON value, then convert to string
        let value = serde_json::Value::deserialize(deserializer)?;
        let json = serde_json::to_string(&value).map_err(D::Error::custom)?;
        Ok(Self::new(json))
    }
}

impl<T> LazyDeser<T>
where
    T: DeserializeOwned + Serialize,
{
    pub fn new(json: String) -> Self {
        Self {
            json,
            value: OnceLock::new(),
            _phantom: PhantomData,
        }
    }

    pub fn from_value(value: T) -> Result<Self, serde_json::Error> {
        let json = serde_json::to_string(&value)?;
        let lazy_deser = Self::new(json);
        // Pre-populate the cache
        let _ = lazy_deser.value.set(value);
        Ok(lazy_deser)
    }

    pub fn get(&self) -> Result<&T, serde_json::Error> {
        Ok(self.value.get_or_init(|| {
            serde_json::from_str(&self.json).unwrap_or_else(|e| {
                // If deserialization fails, we need to handle it gracefully
                // For now, panic - in production you might want different error handling
                panic!("Failed to deserialize JSON in LazyDeser. JSON content: '{}', Error: {}", self.json, e)
            })
        }))
    }

    pub fn try_get(&self) -> Result<&T, serde_json::Error> {
        match self.value.get() {
            Some(value) => Ok(value),
            None => {
                let value = serde_json::from_str(&self.json)?;
                // Try to set the value, but don't worry if it fails (race condition)
                let _ = self.value.set(value);
                // Get the value again (either our value or one from a concurrent thread)
                Ok(self.value.get().unwrap())
            }
        }
    }

    pub fn json(&self) -> &str {
        &self.json
    }
}