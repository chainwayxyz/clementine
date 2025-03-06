use hex_literal::hex;

pub struct Parameters {
    pub l1_block_height: u32,
    pub payment_block_height: u32,
    pub move_tx_id: [u8; 32],
    pub payout_tx_index: u32,
    pub deposit_index: u32,
}

pub const PARAMETERS: Parameters = Parameters {
    l1_block_height: 72075,
    payment_block_height: 72041,
    move_tx_id: hex!("BB25103468A467382ED9F585129AD40331B54425155D6F0FAE8C799391EE2E7F"),
    payout_tx_index: 51,
    deposit_index: 37,
};
