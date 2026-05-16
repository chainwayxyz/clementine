#[derive(Clone, Copy)]
pub(crate) enum TxDebugState {
    Confirmed,
    CreatingPackage,
    SubmittingPackage,
    WaitingForFeePayerUtxos,
    WaitingForUtxoConfirmation,
    PreparingRbf,
    RbfPsbtSignFailed,
    RbfBumpedSent,
    CreatingInitialRbfPsbt,
    RbfInitialSent,
    NoFundingSendSuccess,
    NoFundingSendFailed,
    RbfPsbtBumpFailed,
    SlipstreamSubmitRbfTxClientFailed,
    SlipstreamSubmitRbfTxFailed,
    SlipstreamSubmitRbfTxSent,
    SlipstreamSubmitRbfTxTxidMismatch,
    SlipstreamSubmitInitialRbfTxClientFailed,
    SlipstreamSubmitInitialRbfTxFailed,
    SlipstreamSubmitInitialRbfTxSent,
    SlipstreamSubmitInitialRbfTxTxidMismatch,
    SlipstreamSubmitPackageClientFailed,
    SlipstreamSubmitPackageFailed,
    SlipstreamSubmitPackageSuccess,
    SlipstreamSubmitPackageAlreadySubmitted,
    SlipstreamSubmitPackageAlreadySubmittedStatusFailed,
    SlipstreamSubmitPackageAlreadySubmittedParentNotFound,
}

impl TxDebugState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::CreatingPackage => "creating_package",
            Self::SubmittingPackage => "submitting_package",
            Self::WaitingForFeePayerUtxos => "waiting_for_fee_payer_utxos",
            Self::WaitingForUtxoConfirmation => "waiting_for_utxo_confirmation",
            Self::PreparingRbf => "preparing_rbf",
            Self::RbfPsbtSignFailed => "rbf_psbt_sign_failed",
            Self::RbfBumpedSent => "rbf_bumped_sent",
            Self::CreatingInitialRbfPsbt => "creating_initial_rbf_psbt",
            Self::RbfInitialSent => "rbf_initial_sent",
            Self::NoFundingSendSuccess => "no_funding_send_success",
            Self::NoFundingSendFailed => "no_funding_send_failed",
            Self::RbfPsbtBumpFailed => "rbf_psbt_bump_failed",
            Self::SlipstreamSubmitRbfTxClientFailed => "rbf_slipstream_client_failed",
            Self::SlipstreamSubmitRbfTxFailed => "rbf_slipstream_send_failed",
            Self::SlipstreamSubmitRbfTxSent => "rbf_slipstream_sent",
            Self::SlipstreamSubmitRbfTxTxidMismatch => "rbf_slipstream_txid_mismatch",
            Self::SlipstreamSubmitInitialRbfTxClientFailed => {
                "rbf_initial_slipstream_client_failed"
            }
            Self::SlipstreamSubmitInitialRbfTxFailed => "rbf_initial_slipstream_send_failed",
            Self::SlipstreamSubmitInitialRbfTxSent => "rbf_initial_slipstream_sent",
            Self::SlipstreamSubmitInitialRbfTxTxidMismatch => {
                "rbf_initial_slipstream_txid_mismatch"
            }
            Self::SlipstreamSubmitPackageClientFailed => "slipstream_submit_package_client_failed",
            Self::SlipstreamSubmitPackageFailed => "slipstream_submit_package_failed",
            Self::SlipstreamSubmitPackageSuccess => "slipstream_submit_package_success",
            Self::SlipstreamSubmitPackageAlreadySubmitted => {
                "slipstream_submit_package_already_submitted"
            }
            Self::SlipstreamSubmitPackageAlreadySubmittedStatusFailed => {
                "slipstream_submit_package_already_submitted_status_failed"
            }
            Self::SlipstreamSubmitPackageAlreadySubmittedParentNotFound => {
                "slipstream_submit_package_already_submitted_parent_not_found"
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum SlipstreamSubmitTxLabel {
    Rbf,
    InitialRbf,
}

impl SlipstreamSubmitTxLabel {
    pub(crate) fn client_failed_state(self) -> TxDebugState {
        match self {
            Self::Rbf => TxDebugState::SlipstreamSubmitRbfTxClientFailed,
            Self::InitialRbf => TxDebugState::SlipstreamSubmitInitialRbfTxClientFailed,
        }
    }

    pub(crate) fn failed_state(self) -> TxDebugState {
        match self {
            Self::Rbf => TxDebugState::SlipstreamSubmitRbfTxFailed,
            Self::InitialRbf => TxDebugState::SlipstreamSubmitInitialRbfTxFailed,
        }
    }

    pub(crate) fn sent_state(self) -> TxDebugState {
        match self {
            Self::Rbf => TxDebugState::SlipstreamSubmitRbfTxSent,
            Self::InitialRbf => TxDebugState::SlipstreamSubmitInitialRbfTxSent,
        }
    }

    pub(crate) fn txid_mismatch_state(self) -> TxDebugState {
        match self {
            Self::Rbf => TxDebugState::SlipstreamSubmitRbfTxTxidMismatch,
            Self::InitialRbf => TxDebugState::SlipstreamSubmitInitialRbfTxTxidMismatch,
        }
    }
}
