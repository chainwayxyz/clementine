use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::transaction_builder::TransactionBuilder;
use crate::EVMAddress;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Address;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::XOnlyPublicKey;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use secp256k1::SecretKey;

#[derive(Debug)]
pub struct User {
    pub rpc: ExtendedRpc,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub transaction_builder: TransactionBuilder,
}

impl User {
    pub fn new(
        rpc: ExtendedRpc,
        all_xonly_pks: Vec<XOnlyPublicKey>,
        sk: SecretKey,
        config: BridgeConfig,
    ) -> Self {
        let secp = Secp256k1::new();
        let signer = Actor::new(sk, config.network);
        let transaction_builder = TransactionBuilder::new(all_xonly_pks.clone(), config);
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
        let (deposit_address, _) = self.transaction_builder.generate_deposit_address(
            &self.signer.address.as_unchecked(),
            &evm_address,
            BRIDGE_AMOUNT_SATS,
        )?;

        let deposit_utxo = self
            .rpc
            .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)?;

        Ok((deposit_utxo, self.signer.xonly_public_key, evm_address))
    }

    pub fn get_deposit_address(&self, evm_address: EVMAddress) -> Result<Address, BridgeError> {
        let (deposit_address, _) = self.transaction_builder.generate_deposit_address(
            &self.signer.address.as_unchecked(),
            &evm_address,
            BRIDGE_AMOUNT_SATS,
        )?;
        Ok(deposit_address)
    }

    pub fn generate_deposit_proof(&self, _move_txid: Transaction) -> Result<(), BridgeError> {
        // let out = self.rpc.get_spent_tx_out(&deposit_utxo)?;
        // self.rpc.get_spent_tx_out(outpoint)
        // merkle_tree::PartialMerkleTree::from_txids(&[move_txid.wtxid()], &[move_txid.txid()]);
        Ok(())
    }
}
