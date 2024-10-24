use clementine_circuits::env::Environment;
use risc0_zkvm::guest::env;

pub struct RealEnvironment;
impl Environment for RealEnvironment {
    fn read_32bytes() -> [u8; 32] {
        env::read()
    }
    fn read_u32() -> u32 {
        env::read()
    }
    fn read_u64() -> u64 {
        env::read()
    }
    fn read_i32() -> i32 {
        env::read()
    }

    fn read_u32x8() -> [u32; 8] {
        let mut data = [0; 8];
        for i in 0..8 {
            data[i] = env::read();
        }
        data
    }

    fn write_u32x8(data: [u32; 8]) {
        for i in 0..8 {
            env::write(&data[i]);
        }
    }

    fn verify(method_id: [u32; 8], journal: &[u32]) {
        env::verify(method_id, journal).unwrap();
    }


    fn write_32bytes(_data: [u8; 32]) {
        panic!("Not implemented");
    }
    fn write_u32(_data: u32) {
        panic!("Not implemented");
    }
    fn write_u64(_data: u64) {
        panic!("Not implemented");
    }
    fn write_i32(_data: i32) {
        panic!("Not implemented");
    }
}
