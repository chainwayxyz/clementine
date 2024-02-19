pub trait Environment {
    fn read_32bytes() -> [u8; 32];
    fn read_u32() -> u32;
    fn read_u64() -> u64;
    fn read_i32() -> i32;

    fn write_32bytes(data: [u8; 32]);
    fn write_u32(data: u32);
    fn write_u64(data: u64);
    fn write_i32(data: i32);
}

