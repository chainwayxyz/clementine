#[macro_export]
macro_rules! sha256_hash {
    ($($data:expr),+) => {{
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        $(
            hasher.update($data);
        )+
        let result: [u8; 32] = hasher.finalize().try_into().expect("SHA256 should produce a 32-byte output");
        result
    }};
}
