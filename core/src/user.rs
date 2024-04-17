use crate::actor::Actor;
use crate::constants::NUM_VERIFIERS;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::transaction_builder::TransactionBuilder;
use crate::utils::calculate_witness_merkle_path;
use crate::EVMAddress;
use bitcoin::consensus::serialize;
use bitcoin::merkle_tree;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use secp256k1::schnorr::Signature;
use secp256k1::SecretKey;

#[derive(Debug)]
pub struct User {
    pub rpc: ExtendedRpc,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub transaction_builder: TransactionBuilder,
}

impl User {
    pub fn new(rpc: ExtendedRpc, all_xonly_pks: Vec<XOnlyPublicKey>, sk: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let signer = Actor::new(sk);
        let transaction_builder = TransactionBuilder::new(all_xonly_pks.clone());
        User {
            rpc,
            secp,
            signer,
            transaction_builder,
        }
    }

    pub fn deposit_tx(
        &self,
        evm_address: EVMAddress,
    ) -> Result<(OutPoint, XOnlyPublicKey, EVMAddress), BridgeError> {
        let (deposit_address, _) = self
            .transaction_builder
            .generate_deposit_address(&self.signer.xonly_public_key, &evm_address)?;

        let deposit_utxo = self
            .rpc
            .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)?;

        Ok((deposit_utxo, self.signer.xonly_public_key, evm_address))
    }

    pub fn generate_deposit_proof(&self, move_txid: Txid) -> Result<(), BridgeError> {
        let raw_transaction_result = self.rpc.get_raw_transaction_info(&move_txid, None)?;

        let blockhash = match raw_transaction_result.blockhash {
            Some(hash) => hash,
            None => return Err(BridgeError::BlockNotFound),
        };
        let tx = self.rpc.get_raw_transaction(&move_txid, Some(&blockhash))?;
        let block = self.rpc.get_block(&blockhash)?;

        let (index, merkle_path_to_be_sent) = calculate_witness_merkle_path(move_txid, &block)?;

        tracing::info!("Merkle path to be sent: {:?}", merkle_path_to_be_sent);
        let flattened_merkle_path = merkle_path_to_be_sent
            .iter()
            .flat_map(|x| serialize(x)) // Convert each Hash to Vec<u8>
            .collect::<Vec<_>>();

        tracing::info!("Index: {:?}", index);
        tracing::info!("tx hex: {:?}", tx);
        tracing::info!("tx hex: {:?}", hex::encode(serialize(&tx)));
        tracing::info!("witness txid: {:?}", hex::encode(serialize(&tx.wtxid())));
        println!(
            "bytes4 version = hex{:?};",
            hex::encode(serialize(&tx.version))
        );
        println!("bytes vin = hex{:?};", hex::encode(serialize(&tx.input)));
        println!("bytes vout = hex{:?};", hex::encode(serialize(&tx.output)));
        println!(
            "bytes4 locktime = hex{:?};",
            hex::encode(serialize(&tx.lock_time))
        );

        println!(
            "bytes witness = hex{:?};",
            hex::encode(serialize(&tx.input[0].witness))
        );
        let witness = tx.input[0].witness.clone();
        let deposit_script = witness.nth(NUM_VERIFIERS + 1).unwrap();
        // delete last 21 bytes
        let deposit_script = &deposit_script[..deposit_script.len() - 21];
        println!(
            "bytes deposit_script = hex{:?};",
            hex::encode(deposit_script)
        );

        println!(
            "bytes intermediate_nodes = hex{:?};",
            hex::encode(flattened_merkle_path)
        );

        let witness_root = block.witness_root().unwrap();
        println!(
            "bytes witness_root = hex{:?};",
            hex::encode(serialize(&witness_root))
        );

        Ok(())
    }
}
