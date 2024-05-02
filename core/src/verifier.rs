use crate::config::BridgeConfig;
#[cfg(feature = "mainnet")]
use crate::constants::CONNECTOR_TREE_DEPTH;
use crate::db::verifier::VerifierMockDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::traits::rpc::VerifierRpcServer;
// use crate::traits::verifier::VerifierConnector;
use crate::transaction_builder::TransactionBuilder;
use crate::utils::check_deposit_utxo;
use crate::EVMAddress;
use crate::{actor::Actor, operator::DepositPresigns};
use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::{secp256k1, secp256k1::Secp256k1, OutPoint};
use bitcoin::{Address, TxOut};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use jsonrpsee::core::async_trait;
use secp256k1::XOnlyPublicKey;
use secp256k1::{schnorr, SecretKey};

#[derive(Debug, Clone)]
pub struct Verifier {
    pub rpc: ExtendedRpc,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub transaction_builder: TransactionBuilder,
    pub verifiers: Vec<XOnlyPublicKey>,
    pub operator_pk: XOnlyPublicKey,
    pub verifier_db_connector: VerifierMockDB,
    config: BridgeConfig,
}

#[async_trait]
impl VerifierRpcServer for Verifier {
    async fn new_deposit_rpc(
        &self,
        start_utxo: OutPoint,
        return_address: XOnlyPublicKey,
        deposit_index: u32,
        evm_address: EVMAddress,
        operator_address: Address<NetworkUnchecked>,
    ) -> Result<DepositPresigns, BridgeError> {
        let operator_address = operator_address.require_network(self.config.network)?;
        self.new_deposit(
            start_utxo,
            &return_address,
            deposit_index,
            &evm_address,
            &operator_address,
        )
        .await
    }
    async fn new_withdrawal_direct_rpc(
        &self,
        bridge_utxo: OutPoint,
        bridge_txout: TxOut,
        withdrawal_address: Address<NetworkUnchecked>,
    ) -> Result<schnorr::Signature, BridgeError> {
        let withdrawal_address = withdrawal_address.require_network(self.config.network)?;
        self.new_withdrawal_direct(bridge_utxo, bridge_txout, &withdrawal_address)
            .await
    }
}

impl Verifier {
    /// this is a endpoint that only the operator can call
    /// 1. Check if the deposit utxo is valid and finalized (6 blocks confirmation)
    /// 2. Check if the utxo is not already spent
    /// 3. Give move signature and operator claim signatures
    async fn new_deposit(
        &self,
        start_utxo: OutPoint,
        return_address: &XOnlyPublicKey,
        _deposit_index: u32,
        evm_address: &EVMAddress,
        _operator_address: &Address,
    ) -> Result<DepositPresigns, BridgeError> {
        check_deposit_utxo(
            &self.rpc,
            &self.transaction_builder,
            &start_utxo,
            return_address,
            evm_address,
            BRIDGE_AMOUNT_SATS,
            self.config.confirmation_treshold,
        )?;

        let mut move_tx =
            self.transaction_builder
                .create_move_tx(start_utxo, evm_address, &return_address)?;
        let move_txid = move_tx.tx.txid();

        let _move_utxo = OutPoint {
            txid: move_txid,
            vout: 0,
        };

        tracing::debug!("Verifier with public key {:?} is signing {:?}.", self.signer.xonly_public_key.to_string(), move_txid);
        let move_sig = self
            .signer
            .sign_taproot_script_spend_tx_new(&mut move_tx, 0)?;

        let op_claim_sigs = Vec::new();

        #[cfg(feature = "mainnet")]
        {
            for i in 0..NUM_ROUNDS {
                let connector_utxo = self.verifier_db_connector.get_connector_tree_utxo(i)
                    [CONNECTOR_TREE_DEPTH][deposit_index as usize];
                let connector_hash = self.verifier_db_connector.get_connector_tree_hash(
                    i,
                    CONNECTOR_TREE_DEPTH,
                    deposit_index as usize,
                );

                let mut operator_claim_tx = self.transaction_builder.create_operator_claim_tx(
                    move_utxo,
                    connector_utxo,
                    &operator_address,
                    &self.operator_pk,
                    &connector_hash,
                )?;

                let op_claim_sig = self
                    .signer
                    .sign_taproot_script_spend_tx_new(&mut operator_claim_tx, 0)?;
                op_claim_sigs.push(op_claim_sig);
            }
        }
        Ok(DepositPresigns {
            move_sign: move_sig,
            operator_claim_sign: op_claim_sigs,
        })
    }

    async fn new_withdrawal_direct(
        &self,
        bridge_utxo: OutPoint,
        bridge_txout: TxOut,
        withdrawal_address: &Address<NetworkChecked>,
    ) -> Result<schnorr::Signature, BridgeError> {
        let mut withdrawal_tx = self.transaction_builder.create_withdraw_tx(
            bridge_utxo,
            bridge_txout,
            withdrawal_address,
        )?;
        let sig = self
            .signer
            .sign_taproot_script_spend_tx_new(&mut withdrawal_tx, 0)?;
        Ok(sig)
    }

    #[cfg(feature = "mainnet")]
    /// TODO: Add verification for the connector tree hashes
    fn connector_roots_created(
        &self,
        connector_tree_hashes: &Vec<HashTree>,
        first_source_utxo: &OutPoint,
        start_blockheight: u64,
        period_relative_block_heights: Vec<u32>,
    ) -> Result<(), BridgeError> {
        let (_claim_proof_merkle_roots, _, _utxo_trees, _claim_proof_merkle_trees) =
            self.transaction_builder.create_all_connector_trees(
                &connector_tree_hashes,
                &first_source_utxo,
                start_blockheight,
                &period_relative_block_heights,
            )?;

        // self.verifier_db_connector
        //     .set_connector_tree_utxos(utxo_trees);
        // self.verifier_db_connector
        //     .set_connector_tree_hashes(connector_tree_hashes.clone());
        // self.verifier_db_connector
        //     .set_claim_proof_merkle_trees(claim_proof_merkle_trees);
        // self.verifier_db_connector
        //     .set_start_block_height(start_blockheight);
        // self.verifier_db_connector
        //     .set_period_relative_block_heights(period_relative_block_heights);

        Ok(())
    }

    #[cfg(feature = "mainnet")]
    /// Challenges the operator for current period for now
    /// Will return the blockhash, total work, and period
    fn challenge_operator(&self, period: u8) -> Result<VerifierChallenge, BridgeError> {
        tracing::info!("Verifier starts challenges");
        let last_blockheight = self.rpc.get_block_count()?;
        let last_blockhash = self.rpc.get_block_hash(
            self.verifier_db_connector.get_start_block_height()
                + self
                    .verifier_db_connector
                    .get_period_relative_block_heights()[period as usize] as u64
                - 1,
        )?;
        tracing::debug!("Verifier last_blockhash: {:?}", last_blockhash);
        let total_work = self.rpc.calculate_total_work_between_blocks(
            self.verifier_db_connector.get_start_block_height(),
            last_blockheight,
        )?;
        Ok((last_blockhash, total_work, period))
    }
}

impl Verifier {
    pub fn new(
        rpc: ExtendedRpc,
        all_xonly_pks: Vec<XOnlyPublicKey>,
        sk: SecretKey,
        config: BridgeConfig,
    ) -> Result<Self, BridgeError> {
        let signer = Actor::new(sk, config.network);
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

        let pk: secp256k1::PublicKey = sk.public_key(&secp);
        let xonly_pk = XOnlyPublicKey::from(pk);
        // if pk is not in all_pks, we should raise an error
        if !all_xonly_pks.contains(&xonly_pk) {
            return Err(BridgeError::PublicKeyNotFound);
        }

        let verifier_db_connector = VerifierMockDB::new(config.db_file_path.clone());

        let transaction_builder = TransactionBuilder::new(all_xonly_pks.clone(), config.clone());
        let operator_pk = all_xonly_pks[all_xonly_pks.len() - 1];
        Ok(Verifier {
            rpc,
            secp,
            signer,
            transaction_builder,
            verifiers: all_xonly_pks,
            operator_pk,
            verifier_db_connector,
            config,
        })
    }
}

// #[derive(Debug, Clone)]
// pub struct VerifierClient {
//     pub verifier_client: HttpClient,
// }

// impl VerifierClient {
//     pub fn new(verifier_rpc_address: String) -> Self {
//         let headers = HeaderMap::new();
//         // Build client
//         let client = HttpClientBuilder::default()
//             .set_headers(headers)
//             .build(verifier_rpc_address)
//             .unwrap();

//         VerifierClient {
//             verifier_client: client,
//         }
//     }
// }
// #[async_trait]
// impl VerifierConnector for VerifierClient {
//     async fn new_deposit(
//         &self,
//         start_utxo: OutPoint,
//         return_address: &XOnlyPublicKey,
//         deposit_index: u32,
//         evm_address: &EVMAddress,
//         operator_address: &Address,
//     ) -> Result<DepositPresigns, BridgeError> {
//         // Create a JSON object with the expected parameters
//         let mut params = ObjectParams::new();
//         params
//             .insert("deposit_txid", start_utxo.txid.to_string())
//             .unwrap();
//         params.insert("deposit_vout", start_utxo.vout).unwrap();
//         params
//             .insert("user_return_xonly_pk", return_address.to_string())
//             .unwrap();
//         params.insert("deposit_index", deposit_index).unwrap();
//         params
//             .insert("user_evm_address", hex::encode(evm_address))
//             .unwrap();
//         params
//             .insert("operator_address", operator_address.to_string())
//             .unwrap();

//         // Make the request with the JSON object
//         let result: String = self.verifier_client.request("new_deposit", params).await?;

//         println!("result: {:?}", result);
//         let deposit_presigns: DepositPresigns = serde_json::from_str(&result).unwrap();
//         Ok(deposit_presigns)
//     }

//     #[cfg(feature = "mainnet")]
//     fn connector_roots_created(
//         &self,
//         _connector_tree_hashes: &Vec<HashTree>,
//         _first_source_utxo: &OutPoint,
//         _start_blockheight: u64,
//         _period_relative_block_heights: Vec<u32>,
//     ) -> Result<(), BridgeError> {
//         unimplemented!()
//     }

//     #[cfg(feature = "mainnet")]
//     fn challenge_operator(&self, _period: u8) -> Result<VerifierChallenge, BridgeError> {
//         unimplemented!()
//     }
// }
