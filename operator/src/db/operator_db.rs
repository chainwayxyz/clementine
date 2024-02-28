use bitcoin::OutPoint;

use crate::traits::db::OperatorDatabase;

#[derive(Debug, Clone)]
pub struct OperatorDB {
    pub deposit_utxos: Vec<OutPoint>,
    pub move_utxos: Vec<OutPoint>,
}

impl OperatorDB {
    pub fn new() -> Self {
        Self {
            deposit_utxos: Vec::new(),
            move_utxos: Vec::new(),
        }
    }
}

impl OperatorDatabase for OperatorDB {
    fn get_deposit_utxo(&self, index: usize) -> OutPoint {
        self.deposit_utxos[index]
    }
    fn add_deposit_utxo(&mut self, utxo: OutPoint) {
        self.deposit_utxos.push(utxo);
    }

    fn get_move_utxo(&self, index: usize) -> OutPoint {
        self.move_utxos[index]
    }

    fn add_move_utxo(&mut self, utxo: OutPoint) {
        self.move_utxos.push(utxo);
    }
}
