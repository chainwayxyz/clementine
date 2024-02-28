use bitcoin::OutPoint;

pub trait CommonDatabase {
    // fn get_connector_tree_hash(&self, period: usize, depth: usize, index: usize) -> HashType;

    // fn get_connector_tree_utxo(&self, period: usize, depth: usize, index: usize) -> OutPoint;
}

pub trait OperatorDatabase {
    // fn get_connector_tree_preimage(
    //     &self,
    //     period: usize,
    //     depth: usize,
    //     index: usize,
    // ) -> PreimageType;

    // fn get_inscription_txs(&self, period: usize) -> InscriptionTxs;

    fn get_deposit_utxo(&self, index: usize) -> OutPoint;

    fn add_deposit_utxo(&mut self, utxo: OutPoint);

    fn get_move_utxo(&self, index: usize) -> OutPoint;

    fn add_move_utxo(&mut self, utxo: OutPoint);

    // fn get_move_utxo(&self, index: usize) -> OutPoint;

    // fn get_deposit_take_sigs(&self, index: usize) -> OperatorClaimSigs;
}

pub trait VerifierDatabase {}

// #[macro_export]
// macro_rules! get_connector_tree {
//     ($db:expr, $period:expr, $depth:expr, $index:expr, $method:ident) => {
//         $db.$method($period, $depth, $index)
//     };
// }
