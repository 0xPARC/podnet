use pod2::backends::plonky2::primitives::ec::curve::Point as PublicKey;
use pod2::middleware::{
    containers::Array, containers::Dictionary, containers::Set, PodId, PodType, RawValue,
    TypedValue, Value, KEY_SIGNER, KEY_TYPE,
};

/// Utility trait for extracting typed values from pod2::middleware::Value
pub trait ValueExt {
    fn as_i64(&self) -> Option<i64>;
    fn as_str(&self) -> Option<&str>;
    fn as_bool(&self) -> Option<bool>;
    fn as_public_key(&self) -> Option<&PublicKey>;
    fn as_set(&self) -> Option<&Set>;
    fn as_dictionary(&self) -> Option<&Dictionary>;
    fn as_array(&self) -> Option<&Array>;
    fn as_raw(&self) -> Option<&RawValue>;
    fn as_pod_id(&self) -> Option<&PodId>;
}

impl ValueExt for Value {
    fn as_i64(&self) -> Option<i64> {
        match self.typed() {
            TypedValue::Int(i) => Some(*i),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self.typed() {
            TypedValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self.typed() {
            TypedValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    fn as_public_key(&self) -> Option<&PublicKey> {
        match self.typed() {
            TypedValue::PublicKey(pk) => Some(pk),
            _ => None,
        }
    }

    fn as_set(&self) -> Option<&Set> {
        match self.typed() {
            TypedValue::Set(set) => Some(set),
            _ => None,
        }
    }

    fn as_dictionary(&self) -> Option<&Dictionary> {
        match self.typed() {
            TypedValue::Dictionary(dict) => Some(dict),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&Array> {
        match self.typed() {
            TypedValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    fn as_raw(&self) -> Option<&RawValue> {
        match self.typed() {
            TypedValue::Raw(raw) => Some(raw),
            _ => None,
        }
    }

    fn as_pod_id(&self) -> Option<&PodId> {
        match self.typed() {
            TypedValue::PodId(id) => Some(id),
            _ => None,
        }
    }
}

/// Shared predicate definitions for publish verification
pub fn get_publish_verification_predicate() -> String {
    format!(
        r#"
        identity_verified(username, private: identity_pod) = AND(
            Equal(?identity_pod["{key_type}"], {signed_pod_type})
            Equal(?identity_pod["username"], ?username)
        )

        document_verified(content_hash, private: document_pod) = AND(
            Equal(?document_pod["{key_type}"], {signed_pod_type})
            Equal(?document_pod["content_hash"], ?content_hash)
        )

        publish_verification(username, content_hash, identity_server_pk, post_id, private: identity_pod, document_pod) = AND(
            identity_verified(?username)
            document_verified(?content_hash)
            Equal(?identity_pod["{key_signer}"], ?identity_server_pk)
            Equal(?identity_pod["user_public_key"], ?document_pod["{key_signer}"]) 
            Equal(?document_pod["post_id"], ?post_id)
        )
        "#,
        key_type = KEY_TYPE,
        key_signer = KEY_SIGNER,
        signed_pod_type = PodType::Signed as usize,
    )
}

/// Main pod verification utilities
pub mod mainpod {
    use super::ValueExt;
    use pod2::frontend::MainPod;

    /// Verify main pod signature and public statements for publish verification
    pub fn verify_publish_verification_main_pod(
        main_pod: &MainPod,
        expected_content_hash: &str,
        expected_username: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use pod2::backends::plonky2::{
            basetypes::DEFAULT_VD_SET, mainpod::Prover, mock::mainpod::MockProver,
        };
        use pod2::lang::parse;
        use pod2::middleware::{Params, PodProver, Statement};

        // Verify main pod proof
        main_pod.pod.verify()?;

        // Verify the main pod contains the expected public statements
        let params = Params::default();

        // Choose prover based on mock flag (use same as server)
        let mock_prover = MockProver {};
        let real_prover = Prover {};
        let use_mock = true;
        let (_vd_set, _prover): (_, &dyn PodProver) = if use_mock {
            (&pod2::middleware::VDSet::new(8, &[])?, &mock_prover)
        } else {
            (&*DEFAULT_VD_SET, &real_prover)
        };

        // Get predicate definition from shared pod-utils
        let predicate_input = super::get_publish_verification_predicate();

        let batch = parse(&predicate_input, &params, &[])?.custom_batch;
        let publish_verification_pred = batch
            .predicate_ref_by_name("publish_verification")
            .ok_or("Failed to find publish_verification predicate")?;

        let publish_verification_args = main_pod
            .public_statements
            .iter()
            .find_map(|v| match v {
                Statement::Custom(pred, args) if *pred == publish_verification_pred => Some(args),
                _ => None,
            })
            .ok_or("Main pod public statements missing publish_verification predicate")?;

        // Extract and verify public data
        let username = publish_verification_args[0]
            .as_str()
            .ok_or("publish_verification predicate missing username argument")?;
        let content_hash = publish_verification_args[1]
            .as_str()
            .ok_or("publish_verification predicate missing content_hash argument")?;
        let _identity_server_pk = publish_verification_args[2]
            .as_public_key()
            .ok_or("publish_verification predicate missing identity_server_pk argument")?;

        // Verify extracted data matches expected values
        if username != expected_username {
            return Err(format!(
                "Username mismatch: expected {}, got {}",
                expected_username, username
            )
            .into());
        }

        if content_hash != expected_content_hash {
            return Err(format!(
                "Content hash mismatch: expected {}, got {}",
                expected_content_hash, content_hash
            )
            .into());
        }

        Ok(())
    }
}
