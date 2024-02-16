use std::sync::RwLock;

use circuit_helpers::env::Environment;

// Define a global static variable with RwLock for thread-safe interior mutability.
static GLOBAL_DATA: RwLock<Vec<u8>> = RwLock::new(Vec::new());

pub struct MockEnvironment;

impl MockEnvironment {
    // Helper function to write data to the global storage
    fn write_global(data: &[u8]) {
        let mut global_data = GLOBAL_DATA.write().unwrap();
        global_data.extend_from_slice(data);
    }

    // Helper function to read data from the global storage
    fn read_global(count: usize) -> Vec<u8> {
        let mut global_data = GLOBAL_DATA.write().unwrap();
        if count > global_data.len() {
            panic!("Not enough data in global storage to read");
        }
        global_data.drain(0..count).collect()
    }
}

impl Environment for MockEnvironment {
    fn read_32bytes() -> [u8; 32] {
        let bytes = Self::read_global(32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[..]);
        array
    }

    fn read_u32() -> u32 {
        let bytes = Self::read_global(4);
        u32::from_le_bytes(bytes.try_into().unwrap())
    }

    fn read_u64() -> u64 {
        let bytes = Self::read_global(8);
        u64::from_le_bytes(bytes.try_into().unwrap())
    }

    fn read_i32() -> i32 {
        let bytes = Self::read_global(4);
        i32::from_le_bytes(bytes.try_into().unwrap())
    }

    fn write_32bytes(data: [u8; 32]) {
        Self::write_global(&data);
    }

    fn write_u32(data: u32) {
        Self::write_global(&data.to_le_bytes());
    }

    fn write_u64(data: u64) {
        Self::write_global(&data.to_le_bytes());
    }

    fn write_i32(data: i32) {
        Self::write_global(&data.to_le_bytes());
    }
}
