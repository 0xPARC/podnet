use axum::http::StatusCode;
use pod2::{
    backends::plonky2::{
        basetypes::DEFAULT_VD_SET,
        mainpod::Prover,
        mock::mainpod::MockProver,
    },
    middleware::{Params, PodProver, VDSet},
};
use std::sync::OnceLock;

static MOCK_VD_SET: OnceLock<VDSet> = OnceLock::new();

/// Configuration for POD-related operations
pub struct PodConfig {
    use_mock: bool,
}

impl PodConfig {
    pub fn new(use_mock: bool) -> Self {
        Self { use_mock }
    }

    /// Get the appropriate prover setup (VDSet and Prover) based on configuration
    pub fn get_prover_setup(&self) -> Result<(&'static VDSet, Box<dyn PodProver>), StatusCode> {
        if self.use_mock {
            log::info!("Using MockMainPod for verification");
            let vd_set = MOCK_VD_SET.get_or_init(|| {
                VDSet::new(8, &[]).expect("Failed to create mock VDSet")
            });
            let prover = Box::new(MockProver {});
            Ok((vd_set, prover))
        } else {
            log::info!("Using MainPod for verification");
            let vd_set = &*DEFAULT_VD_SET;
            let prover = Box::new(Prover {});
            Ok((vd_set, prover))
        }
    }

    /// Get default parameters for POD operations
    pub fn get_params(&self) -> Params {
        let mut params = Params::default();
        params.max_custom_batch_size = 6;
        params
    }

    /// Get parameters with custom batch size
    pub fn get_params_with_batch_size(&self, batch_size: usize) -> Params {
        let mut params = Params::default();
        params.max_custom_batch_size = batch_size;
        params
    }

    /// Check if using mock proofs
    pub fn is_mock(&self) -> bool {
        self.use_mock
    }
}