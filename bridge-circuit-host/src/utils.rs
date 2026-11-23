//! Protocol helpers.
use bitcoin::{opcodes, script::Instruction, Transaction};

pub fn total_work_from_wt_tx(wt_tx: &Transaction) -> [u8; 16] {
    let output = wt_tx.output[2].clone();
    let mut instructions = output.script_pubkey.instructions();
    if let Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) = instructions.next() {
        if let Some(Ok(Instruction::PushBytes(data))) = instructions.next() {
            let data_bytes = data.as_bytes();
            let total_work: [u8; 16] = data_bytes[64..]
                .try_into()
                .expect("Expected total work data to be exactly 16 bytes long after OP_RETURN");
            return total_work;
        }
        panic!("Expected OP_RETURN followed by data");
    }
    panic!("Expected OP_RETURN instruction in the transaction output script");
}
