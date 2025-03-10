pub struct BCHostParameters {
    pub l1_block_height: u32,
    pub payment_block_height: u32,
    pub move_to_vault_txid: [u8; 32],
    pub payout_tx_index: u32,
    pub deposit_index: u32,
}
