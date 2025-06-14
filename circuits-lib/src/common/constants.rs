/// Constant bridge amount in sats
pub const BRIDGE_AMOUNT_SATS: u64 = 1_000_000_000;
pub const FIRST_FIVE_OUTPUTS: usize = 5;
pub const NUMBER_OF_ASSERT_TXS: usize = 33;
pub const MAX_NUMBER_OF_WATCHTOWERS: usize = 160;

pub const MAINNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    2828598111, 4098193592, 3494626909, 1325569329, 1552726101, 455678563, 48065395, 241300384,
];

pub const TESTNET4_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    1468244244, 1800076587, 4080612645, 254146503, 3388096845, 3113073391, 3260391615, 3896028932,
];

pub const SIGNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    1308144088, 3978434433, 3532346338, 1873546347, 2829516822, 1247482657, 77995441, 53017038,
];

pub const REGTEST_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    963286175, 2518840500, 1702030878, 1501962083, 2944827571, 2461833252, 968655091, 3443362857,
];
