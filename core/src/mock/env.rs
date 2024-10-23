use std::sync::RwLock;

use clementine_circuits::env::Environment;
use risc0_zkvm::ExecutorEnv;
// Define a global static variable with RwLock for thread-safe interior mutability.
static GLOBAL_DATA: RwLock<Vec<u8>> = RwLock::new(Vec::new());
static GLOBAL_DATA_TYPES: RwLock<Vec<u8>> = RwLock::new(Vec::new());
static READ_POSITION: RwLock<usize> = RwLock::new(0);

pub struct MockEnvironment;

impl MockEnvironment {
    // Helper function to write data to the global storage
    fn write_global(data: &[u8], data_type: u8) {
        let mut global_data = GLOBAL_DATA.write().unwrap();
        global_data.extend_from_slice(data);
        let mut global_data_types = GLOBAL_DATA_TYPES.write().unwrap(); // Use write lock for data types since we're updating it
        global_data_types.push(data_type);
    }

    // Helper function to read data from the global storage
    fn read_global(count: usize) -> Vec<u8> {
        let global_data = GLOBAL_DATA.read().unwrap(); // Use read lock for data
        let mut pos = READ_POSITION.write().unwrap(); // Use write lock for position since we're updating it

        if *pos + count > global_data.len() {
            panic!("Not enough data in global storage to read");
        }
        let result = global_data[*pos..*pos + count].to_vec();
        *pos += count; // Update the read position

        result
    }

    pub fn reset_mock_env() {
        let mut global_data = GLOBAL_DATA.write().unwrap();
        global_data.clear();
        let mut global_data_types = GLOBAL_DATA_TYPES.write().unwrap();
        global_data_types.clear();
        let mut read_position = READ_POSITION.write().unwrap();
        *read_position = 0;
    }

    pub fn output_env<'a>() -> risc0_zkvm::ExecutorEnvBuilder<'a> {
        let global_data = GLOBAL_DATA.read().unwrap(); // Use read lock for data
        let global_data_types = GLOBAL_DATA_TYPES.read().unwrap(); // Use read lock for data types
        let mut env = ExecutorEnv::builder();
        let mut i = 0;
        for data_type in global_data_types.iter() {
            // tracing::debug!("Data type: {}", data_type);
            match data_type {
                0 => {
                    let data: [u8; 32] = global_data[i..i + 32].try_into().unwrap();
                    env.write(&data).unwrap();
                    i += 32;
                }
                1 => {
                    env.write(&u32::from_le_bytes(
                        global_data[i..i + 4].try_into().unwrap(),
                    ))
                    .unwrap();
                    i += 4
                }
                2 => {
                    env.write(&u64::from_le_bytes(
                        global_data[i..i + 8].try_into().unwrap(),
                    ))
                    .unwrap();
                    i += 8
                }
                3 => {
                    env.write(&i32::from_le_bytes(
                        global_data[i..i + 4].try_into().unwrap(),
                    ))
                    .unwrap();
                    i += 4;
                }
                _ => panic!("Invalid data type"),
            }
        }
        env
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

    fn read_u32x8() -> [u32; 8] {
        let mut data = [0; 8];
        for i in 0..8 {
            let bytes = Self::read_global(4);
            data[i] = u32::from_le_bytes(bytes.try_into().unwrap())
        }
        data
    }

    fn write_u32x8(data: [u32; 8]) {
        for i in 0..8 {
            Self::write_global(&data[i].to_le_bytes(), 1);
        }
    }

    fn verify(_method_id: [u32; 8], _journal: &[u32]) {
        unimplemented!()
    }

    fn write_32bytes(data: [u8; 32]) {
        Self::write_global(&data, 0);
    }

    fn write_u32(data: u32) {
        Self::write_global(&data.to_le_bytes(), 1);
    }

    fn write_u64(data: u64) {
        Self::write_global(&data.to_le_bytes(), 2);
    }

    fn write_i32(data: i32) {
        Self::write_global(&data.to_le_bytes(), 3);
    }
}

pub struct RealEnvironment;

impl Environment for RealEnvironment {
    fn read_32bytes() -> [u8; 32] {
        unimplemented!()
    }

    fn read_u32() -> u32 {
        unimplemented!()
    }

    fn read_u64() -> u64 {
        unimplemented!()
    }

    fn read_i32() -> i32 {
        unimplemented!()
    }

    fn read_u32x8() -> [u32; 8] {
        unimplemented!()
    }

    fn write_u32x8(_data: [u32; 8]) {
        unimplemented!()
    }

    fn verify(_method_id: [u32; 8], _journal: &[u32]) {
        unimplemented!()
    }

    fn write_32bytes(_data: [u8; 32]) {}

    fn write_u32(_data: u32) {
        unimplemented!()
    }

    fn write_u64(_data: u64) {
        unimplemented!()
    }

    fn write_i32(_data: i32) {
        unimplemented!()
    }
}
