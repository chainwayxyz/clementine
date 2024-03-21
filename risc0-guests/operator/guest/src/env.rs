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
