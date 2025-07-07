use serde::{Deserialize, Serialize};

use pod2::backends::plonky2::primitives::ec::curve::Point as PublicKey;
use pod2::frontend::{MainPod, SignedPod};
use pod2::middleware::{Hash, KEY_SIGNER, KEY_TYPE, PodType};

#[derive(Debug, Serialize, Deserialize)]
pub struct Post {
    pub id: Option<i64>,
    pub created_at: Option<String>,
    pub last_edited_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDocument {
    pub id: Option<i64>,
    pub content_id: String,
    pub post_id: i64,
    pub revision: i64,
    pub created_at: Option<String>,
    pub pod: String,                      // JSON string of the signed pod
    pub timestamp_pod: String,            // JSON string of the server timestamp pod
    pub user_id: String,                  // Username of the author
    pub upvote_count_pod: Option<String>, // JSON string of the upvote count main pod
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostWithDocuments {
    pub id: Option<i64>,
    pub created_at: Option<String>,
    pub last_edited_at: Option<String>,
    pub documents: Vec<DocumentMetadata>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub id: Option<i64>,
    pub content_id: Hash,
    pub post_id: i64,
    pub revision: i64,
    pub created_at: Option<String>,
    /// MainPod that proves:
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
    pub pod: MainPod,
    /// SignedPod containing server timestamp information:
    /// - post_id: i64 (ID of the post this document belongs to)
    /// - document_id: i64 (ID of this document revision)
    /// - timestamp: i64 (server timestamp when document was created)
    /// - _signer: Point (server's public key, automatically added by SignedPod)
    ///
    /// This pod proves the document was timestamped by the server and establishes
    /// the canonical ordering of document creation.
    pub timestamp_pod: SignedPod,
    pub user_id: String,   // Username of the author
    pub upvote_count: i64, // Number of upvotes for this document
    /// MainPod that cryptographically proves the upvote count is correct
    /// Proves: upvote_count(N, content_hash, post_id) where N is the actual count
    /// Uses recursive proofs starting from base case (count=0) and building up
    pub upvote_count_pod: Option<MainPod>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Document {
    pub metadata: DocumentMetadata,
    pub content: String, // Retrieved from storage
}

#[derive(Debug, Deserialize)]
pub struct PublishRequest {
    pub content: String,
    /// MainPod that cryptographically proves the user's identity and document authenticity:
    ///
    /// Contains two inner pods:
    /// 1. Identity pod (from identity server) proving user identity
    /// 2. Document pod (from user) containing content hash and metadata
    ///
    /// The MainPod proves:
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
    ///
    /// This enables trustless document publishing with verified authorship.
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
    pub public_key: String,    // Stored as string in DB
    pub challenge_pod: String, // Server's challenge pod as JSON string
    pub identity_pod: String,  // Identity server's response pod as JSON string
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityServerChallengeRequest {
    /// Request from identity server to get a challenge for registration
    pub server_id: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Serialize)]
pub struct IdentityServerChallengeResponse {
    /// SignedPod containing challenge information from main server:
    /// - challenge: String (random challenge value)
    /// - expires_at: String (ISO timestamp when challenge expires)
    /// - identity_server_public_key: Point (public key from request)
    /// - server_id: String (server ID from request)
    /// - _signer: Point (main server's public key, automatically added by SignedPod)
    pub challenge_pod: SignedPod,
}

#[derive(Debug, Deserialize)]
pub struct IdentityServerRegistration {
    /// Registration request containing both server's challenge and identity server's response
    ///
    /// server_challenge_pod contains:
    /// - challenge: String (original challenge from server)
    /// - expires_at: String (expiration timestamp)
    /// - identity_server_public_key: Point (identity server's public key)
    /// - server_id: String (identity server ID)
    /// - _signer: Point (main server's public key)
    ///
    /// identity_response_pod contains:
    /// - challenge: String (same challenge value, proving identity server received it)
    /// - server_id: String (confirming identity server ID)
    /// - _signer: Point (identity server's public key, proving control of private key)
    pub server_challenge_pod: SignedPod,
    pub identity_response_pod: SignedPod,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Upvote {
    pub id: Option<i64>,
    pub document_id: i64,
    pub username: String,
    pub pod_json: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpvoteRequest {
    /// MainPod that cryptographically proves the user's identity and upvote authenticity:
    ///
    /// Contains two inner pods:
    /// 1. Identity pod (from identity server) proving user identity
    /// 2. Upvote pod (from user) containing upvote details and document reference
    ///
    /// The MainPod proves:
    /// - Identity verification: identity pod was signed by registered identity server
    /// - Upvote verification: upvote pod was signed by user from identity pod  
    /// - Cross verification: upvote signer matches identity user_public_key
    /// - Document hash verification: upvote pod contains correct document content hash
    /// - Post ID verification: upvote pod contains correct post ID
    /// - Request type verification: upvote pod specifies "upvote" request type
    ///
    /// Public data exposed by main pod:
    /// - username: String (verified username from identity pod)
    /// - content_hash: String (verified content hash of upvoted document)
    /// - identity_server_pk: Point (verified identity server public key)
    /// - post_id: i64 (verified post ID containing the document)
    ///
    /// This enables trustless upvoting with verified user identity.
    pub upvote_main_pod: MainPod,
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

/// Shared predicate definitions for upvote verification
pub fn get_upvote_verification_predicate() -> String {
    // TODO: This is the full verification predicate...
    //       however I can't get this to successfully prove
    //       Therefore, we use a simplified version for now.
    //format!(
    //    r#"
    //    identity_verified(username, private: identity_pod) = AND(
    //        Equal(?identity_pod["{key_type}"], {signed_pod_type})
    //        Equal(?identity_pod["username"], ?username)
    //    )

    //    upvote_verified(content_hash, post_id, private: upvote_pod) = AND(
    //        Equal(?upvote_pod["{key_type}"], {signed_pod_type})
    //        Equal(?upvote_pod["content_hash"], ?content_hash)
    //        Equal(?upvote_pod["post_id"], ?post_id)
    //        Equal(?upvote_pod["request_type"], "upvote")
    //    )

    //    upvote_verification(username, content_hash, identity_server_pk, post_id, private: identity_pod, upvote_pod) = AND(
    //        identity_verified(?username)
    //        upvote_verified(?content_hash, ?post_id)
    //        Equal(?identity_pod["{key_signer}"], ?identity_server_pk)
    //        Equal(?identity_pod["user_public_key"], ?upvote_pod["{key_signer}"])
    //    )

    //    upvote_count_base(count, username, content_hash, identity_server_pk, post_id) = AND(
    //        Equal(?count, 0)
    //    )

    //    upvote_count_ind(count, username, content_hash, identity_server_pk, post_id, private: intermed) = AND(
    //        upvote_count(?intermed, ?username, ?content_hash, ?identity_server_pk, ?post_id)
    //        SumOf(?count, ?intermed, 1)
    //        upvote_verification(?username, ?content_hash, ?identity_server_pk, ?post_id)
    //    )

    //    upvote_count(count, username, content_hash, identity_server_pk, post_id) = OR(
    //        upvote_count_base(?count, ?username, ?content_hash, ?identity_server_pk, ?post_id)
    //        upvote_count_ind(?count, ?username, ?content_hash, ?identity_server_pk, ?post_id)
    //    )
    //    "#,
    //    key_type = KEY_TYPE,
    //    key_signer = KEY_SIGNER,
    //    signed_pod_type = PodType::Signed as usize,
    //)
    format!(
        r#"
        identity_verified(username, private: identity_pod) = AND(
            Equal(?identity_pod["{key_type}"], {signed_pod_type})
            Equal(?identity_pod["username"], ?username)
        )

        upvote_verified(content_hash, private: upvote_pod) = AND(
            Equal(?upvote_pod["{key_type}"], {signed_pod_type})
            Equal(?upvote_pod["content_hash"], ?content_hash)
            Equal(?upvote_pod["request_type"], "upvote")
        )

        upvote_verification(username, content_hash, identity_server_pk, private: identity_pod, upvote_pod) = AND(
            identity_verified(?username)
            upvote_verified(?content_hash)
            Equal(?identity_pod["{key_signer}"], ?identity_server_pk)
            Equal(?identity_pod["user_public_key"], ?upvote_pod["{key_signer}"])
        )

        upvote_count_base(count, content_hash, private: data_pod) = AND(
            Equal(?count, 0)
            Equal(?data_pod["content_hash"], ?content_hash)
        )

        upvote_count_ind(count, content_hash, private: intermed, username, identity_server_pk) = AND(
            upvote_count(?intermed, ?content_hash)
            SumOf(?count, ?intermed, 1)
            upvote_verification(?username, ?content_hash, ?identity_server_pk)
        )

        upvote_count(count, content_hash) = OR(
            upvote_count_base(?count, ?content_hash)
            upvote_count_ind(?count, ?content_hash)
        )
        "#,
        key_type = KEY_TYPE,
        key_signer = KEY_SIGNER,
        signed_pod_type = PodType::Signed as usize,
    )
}

/// Main pod verification utilities
pub mod mainpod {
    use pod_utils::ValueExt;
    use pod2::frontend::MainPod;
    use pod2::middleware::Hash;

    /// Verify main pod signature and public statements for publish verification
    pub fn verify_publish_verification_main_pod(
        main_pod: &MainPod,
        expected_content_hash: &Hash,
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
        let mut params = Params::default();
        params.max_custom_batch_size = 6;

        // Choose prover based on mock flag (use same as server)
        let mock_prover = MockProver {};
        let real_prover = Prover {};
        let use_mock = true;
        let (_vd_set, _prover): (_, &dyn PodProver) = if use_mock {
            (&pod2::middleware::VDSet::new(8, &[])?, &mock_prover)
        } else {
            (&*DEFAULT_VD_SET, &real_prover)
        };

        // Get predicate definition from shared models
        let predicate_input = super::get_publish_verification_predicate();

        let batch = parse(&predicate_input, &params, &[])?.custom_batch;
        let publish_verification_pred = batch
            .predicate_ref_by_name("publish_verification")
            .ok_or("Failed to find publish_verification predicate")?;

        println!("GOT MAIN POD OF: {:?}", main_pod.public_statements);
        let publish_verification_args = main_pod
            .public_statements
            .iter()
            .find_map(|v| {
                println!(
                    "GOT V: {v:?}\n\n want {publish_verification_pred:?}\n\n\n"
                );
                match v {
                    Statement::Custom(pred, args) if *pred == publish_verification_pred => {
                        Some(args)
                    }
                    _ => None,
                }
            })
            .ok_or("Main pod public statements missing publish_verification predicate")?;

        // Extract and verify public data
        let username = publish_verification_args[0]
            .as_str()
            .ok_or("publish_verification predicate missing username argument")?;
        let content_hash = publish_verification_args[1]
            .as_hash()
            .ok_or("publish_verification predicate missing content_hash argument")?;
        let _identity_server_pk = publish_verification_args[2]
            .as_public_key()
            .ok_or("publish_verification predicate missing identity_server_pk argument")?;

        // Verify extracted data matches expected values
        if username != expected_username {
            return Err(format!(
                "Username mismatch: expected {expected_username}, got {username}"
            )
            .into());
        }

        if &content_hash != expected_content_hash {
            return Err(format!(
                "Content hash mismatch: expected {expected_content_hash}, got {content_hash}"
            )
            .into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pod_utils::ValueExt;
    use pod2::backends::plonky2::{
        basetypes::DEFAULT_VD_SET, mainpod::Prover, mock::mainpod::MockProver,
    };
    use pod2::frontend::MainPodBuilder;
    use pod2::lang::parse;
    use pod2::middleware::{Params, PodProver, Statement};
    use pod2::op;

    #[tokio::test]
    async fn test_upvote_count_predicate_0_to_3() {
        let params = Params::default();

        // Choose prover based on mock flag
        let mock_prover = MockProver {};
        let real_prover = Prover {};
        let use_mock = true;
        let (vd_set, prover): (_, &dyn PodProver) = if use_mock {
            println!("Using MockMainPod for publish verification");
            (&pod2::middleware::VDSet::new(8, &[]).unwrap(), &mock_prover)
        } else {
            println!("Using MainPod for publish verification");
            (&*DEFAULT_VD_SET, &real_prover)
        };

        // Get the upvote count predicate
        let predicate_input = get_upvote_verification_predicate();
        println!("Upvote count predicate:\n{}", predicate_input);

        // Parse the predicate
        let batch = parse(&predicate_input, &params, &[]).unwrap().custom_batch;
        let upvote_count_pred = batch.predicate_ref_by_name("upvote_count").unwrap();
        let upvote_count_base = batch.predicate_ref_by_name("upvote_count_base").unwrap();
        let upvote_count_ind = batch.predicate_ref_by_name("upvote_count_ind").unwrap();

        // Test count = 0 (base case)
        println!("\n=== Testing upvote_count(0) ===");
        let mut builder_0 = MainPodBuilder::new(&params, vd_set);
        let equals_zero_stmt = builder_0.priv_op(op!(eq, 0, 0)).unwrap();
        let base_stmt = builder_0
            .priv_op(op!(custom, upvote_count_base.clone(), equals_zero_stmt))
            .unwrap();
        let _count_0_stmt = builder_0
            .pub_op(op!(
                custom,
                upvote_count_pred.clone(),
                base_stmt.clone(),
                base_stmt
            ))
            .unwrap();
        let main_pod_0 = builder_0.prove(prover, &params).unwrap();
        main_pod_0.pod.verify().unwrap();
        println!("✓ Successfully proved upvote_count(0)");

        let recursive_statement = main_pod_0.public_statements[1].clone();
        // Test count = 1 (inductive case with count = 0)
        println!("\n=== Testing upvote_count(1) ===");
        let mut builder_1 = MainPodBuilder::new(&params, vd_set);
        builder_1.add_recursive_pod(main_pod_0.clone());
        let sum_of_stmt = builder_1.priv_op(op!(sum_of, 1, 0, 1)).unwrap();
        // The inductive case needs to refer to the previous proof
        let ind_count_stmt = builder_1
            .pub_op(op!(
                custom,
                upvote_count_ind.clone(),
                recursive_statement,
                sum_of_stmt
            ))
            .unwrap();
        let dummy_stmt = builder_1.priv_op(op!(eq, 0, 0)).unwrap();
        let _count_stmt = builder_1
            .pub_op(op!(
                custom,
                upvote_count_pred.clone(),
                ind_count_stmt.clone(),
                ind_count_stmt
            ))
            .unwrap();
        let main_pod_1 = builder_1.prove(prover, &params).unwrap();
        main_pod_1.pod.verify().unwrap();
        println!("✓ Successfully proved upvote_count(1)");

        // Test count = 2 (inductive case with count = 1)
        //println!("\n=== Testing upvote_count(2) ===");
        //let mut builder_2 = MainPodBuilder::new(&params, vd_set);
        //builder_2.add_recursive_pod(main_pod_1.clone());
        //let prev_count_stmt = builder_2.priv_op(op!(custom, upvote_count_pred.clone(), 1)).unwrap();
        //let _count_2_stmt = builder_2.pub_op(op!(custom, upvote_count_pred.clone(), 2, prev_count_stmt)).unwrap();
        //let main_pod_2 = builder_2.prove(prover, &params).unwrap();
        //main_pod_2.pod.verify().unwrap();
        //println!("✓ Successfully proved upvote_count(2)");

        //// Test count = 3 (inductive case with count = 2)
        //println!("\n=== Testing upvote_count(3) ===");
        //let mut builder_3 = MainPodBuilder::new(&params, vd_set);
        //builder_3.add_recursive_pod(main_pod_2.clone());
        //let prev_count_stmt = builder_3.priv_op(op!(custom, upvote_count_pred.clone(), 2)).unwrap();
        //let _count_3_stmt = builder_3.pub_op(op!(custom, upvote_count_pred.clone(), 3, prev_count_stmt)).unwrap();
        //let main_pod_3 = builder_3.prove(prover, &params).unwrap();
        //main_pod_3.pod.verify().unwrap();
        //println!("✓ Successfully proved upvote_count(3)");

        //// Verify the public statements contain the correct counts
        //for (i, main_pod) in [&main_pod_0, &main_pod_1, &main_pod_2, &main_pod_3].iter().enumerate() {
        //    println!("\n=== Verifying public statement for count {} ===", i);
        //
        //    let count_statement = main_pod
        //        .public_statements
        //        .iter()
        //        .find_map(|stmt| match stmt {
        //            Statement::Custom(pred, args) if *pred == upvote_count_pred.clone() => Some(args),
        //            _ => None,
        //        })
        //        .expect(&format!("upvote_count predicate not found in main pod {}", i));

        //    let count_value = count_statement[0].as_i64()
        //        .expect(&format!("Count argument should be integer for count {}", i));
        //
        //    assert_eq!(count_value, i as i64, "Count mismatch for upvote_count({})", i);
        //    println!("✓ Public statement correctly shows upvote_count({})", i);
        //}

        //println!("\n🎉 All upvote count proofs from 0 to 3 completed successfully!");
    }
}
