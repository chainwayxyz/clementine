use crate::{citrea::Bridge::Transaction as CitreaTransaction, errors::BridgeError};
use alloy::primitives::{Bytes, FixedBytes};
use bitcoin::{consensus::Encodable, Transaction};

pub fn get_transaction_details_for_citrea(
    transaction: &Transaction,
) -> Result<CitreaTransaction, BridgeError> {
    let version = (transaction.version.0 as u32).to_le_bytes();
    let flag: u16 = 1;

    let vin = [
        vec![transaction.input.len() as u8],
        transaction
            .input
            .iter()
            .map(|x| bitcoin::consensus::serialize(&x))
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>(),
    ]
    .concat();

    let vout = [
        vec![transaction.output.len() as u8],
        transaction
            .output
            .iter()
            .map(|x| bitcoin::consensus::serialize(&x))
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>(),
    ]
    .concat();

    let witness: Vec<u8> = transaction
        .input
        .iter()
        .map(|param| {
            let mut raw = Vec::new();
            param
                .witness
                .consensus_encode(&mut raw)
                .map_err(|e| eyre::eyre!("Can't encode param: {}", e))?;

            Ok::<Vec<u8>, BridgeError>(raw)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>();

    let locktime = bitcoin::consensus::serialize(&transaction.lock_time);
    let locktime: [u8; 4] = locktime.try_into().unwrap();
    Ok(CitreaTransaction {
        version: FixedBytes::from(version),
        flag: FixedBytes::from(flag),
        vin: Bytes::copy_from_slice(&vin),
        vout: Bytes::copy_from_slice(&vout),
        witness: Bytes::copy_from_slice(&witness),
        locktime: FixedBytes::from(locktime),
    })
}
