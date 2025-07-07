use pod2::{
    backends::plonky2::{basetypes::DEFAULT_VD_SET, mainpod::Prover, mock::mainpod::MockProver},
    middleware::{Params, PodProver, VDSet},
};
use std::sync::OnceLock;

static MOCK_VD_SET: OnceLock<VDSet> = OnceLock::new();

/// Shared utility for creating prover setups across PodNet components
pub struct PodNetProverSetup;

impl PodNetProverSetup {
    /// Create prover setup based on mock flag
    /// Returns (VDSet, Prover) tuple for use in POD operations
    pub fn create_prover_setup(
        use_mock: bool,
    ) -> Result<(&'static VDSet, Box<dyn PodProver>), String> {
        if use_mock {
            log::info!("Using MockMainPod for verification");
            let vd_set = MOCK_VD_SET
                .get_or_init(|| VDSet::new(8, &[]).expect("Failed to create mock VDSet"));
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
    pub fn get_params() -> Params {
        let mut params = Params::default();
        params.max_custom_batch_size = 6;
        params.max_statement_args = 6;
        params
    }

    /// Get parameters with custom batch size
    pub fn get_params_with_batch_size(batch_size: usize) -> Params {
        let mut params = Params::default();
        params.max_custom_batch_size = batch_size;
        params
    }
}

