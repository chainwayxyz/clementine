use async_stream::stream;
use bitcoin::TapSighash;
use bitcoin::{address::NetworkUnchecked, Address, Amount, OutPoint};

use crate::{actor::Actor, builder, database::Database, EVMAddress};

use futures_core::stream::Stream;

pub fn create_sighash_stream(
    _db: Database,
    deposit_outpoint: OutPoint,
    evm_address: EVMAddress,
    recovery_taproot_address: Address<NetworkUnchecked>,
    user_takes_after: u64,
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
) -> impl Stream<Item = TapSighash> {
    stream! {

        for i in 0..10 {
            let mut dummy_move_tx_handler = builder::transaction::create_move_tx_handler(
                deposit_outpoint,
                evm_address,
                &recovery_taproot_address,
                nofn_xonly_pk,
                bitcoin::Network::Regtest,
                user_takes_after as u32,
                Amount::from_sat(i as u64 + 1000000),
            );


            yield Actor::convert_tx_to_sighash_script_spend(&mut dummy_move_tx_handler, 0, 0)
                .unwrap();

        }

    }
}
