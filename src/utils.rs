use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::secp256k1::Scalar;
use bitcoin::{network::constants::Network, Address};

use secp256k1_zkp::schnorr::Signature as SchnorrSignature;
use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};

use dlc::*;

pub fn get_random_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut rng = secp256k1_zkp::rand::thread_rng();

    let privkey = SecretKey::new(&mut rng);
    let pubkey = PublicKey::from_secret_key(&secp, &privkey);

    (privkey, pubkey)
}

// there is only one spending path for now
// CLTV can be added to the script for unstaking
pub fn get_staking_contract_script(
    validator_pubkey: &PublicKey,
    protocol_pubkey: &PublicKey,
) -> ScriptBuf {
    make_funding_redeemscript(validator_pubkey, protocol_pubkey)
}

pub fn get_p2wpkh_script_pubkey(pubkey: PublicKey, network: Network) -> ScriptBuf {
    let pk = bitcoin::PublicKey {
        compressed: true,
        inner: pubkey,
    };
    Address::p2wpkh(&pk, network).unwrap().script_pubkey()
}

pub fn signatures_to_secret(signatures: &[Vec<SchnorrSignature>]) -> Result<SecretKey, Error> {
    let s_values = signatures
        .iter()
        .flatten()
        .map(|x| match secp_utils::schnorrsig_decompose(x) {
            Ok(v) => Ok(v.1),
            Err(err) => Err(err),
        })
        .collect::<Result<Vec<&[u8]>, Error>>()?;
    let secret = SecretKey::from_slice(s_values[0])?;

    let result = s_values.iter().skip(1).fold(secret, |accum, s| {
        let sec = SecretKey::from_slice(s).unwrap();
        accum.add_tweak(&Scalar::from(sec)).unwrap()
    });

    Ok(result)
}
