use std::str::FromStr;

use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::blockdata::transaction::OutPoint;
use bitcoin::secp256k1::Scalar;
use bitcoin::{network::constants::Network, Address, Txid};

use secp256k1_zkp::schnorr::Signature as SchnorrSignature;
use secp256k1_zkp::{
    rand::{Rng, RngCore},
    KeyPair, Message, PublicKey, Secp256k1, SecretKey, Signing, XOnlyPublicKey,
};

use dlc::*;

fn main() {
    // contract parties
    let (offer_party_params, offer_fund_sk) = get_party_params(1000000000, 100000000, None);
    let (accept_party_params, accept_fund_sk) = get_party_params(1000000000, 100000000, None);

    // build dlc transactions: funding, CETs and refunding
    let dlc_txs = create_dlc_transactions(
        &offer_party_params,
        &accept_party_params,
        &payouts(),
        100,
        4,
        10,
        10,
        0,
    )
    .unwrap();

    let cets = dlc_txs.cets;

    // outcomes and messages which are hashed outcomes
    let outcomes = [true, false];
    let messages: Vec<Message> = (0..outcomes.len())
        .map(|o| Message::from_hashed_data::<secp256k1_zkp::hashes::sha256::Hash>(&[o as u8]))
        .collect();

    // oracle related operations
    // single oracle for demo

    let secp = Secp256k1::new();
    let mut rng = secp256k1_zkp::rand::thread_rng();

    let oracle_kp = KeyPair::new(&secp, &mut rng);
    let oracle_pubkey = oracle_kp.x_only_public_key().0;

    let oracle_info: OracleInfo;
    let mut nonces: Vec<XOnlyPublicKey> = Vec::with_capacity(messages.len());
    let mut sk_nonces: Vec<[u8; 32]> = Vec::with_capacity(messages.len());
    let mut oracle_sigs: Vec<SchnorrSignature> = Vec::with_capacity(messages.len());

    for i in 0..messages.len() {
        let mut sk_nonce = [0u8; 32];
        rng.fill_bytes(&mut sk_nonce);

        let oracle_r_kp = KeyPair::from_seckey_slice(&secp, &sk_nonce).unwrap();
        let nonce = XOnlyPublicKey::from_keypair(&oracle_r_kp).0;

        let sig =
            secp_utils::schnorrsig_sign_with_nonce(&secp, &messages[i], &oracle_kp, &sk_nonce);

        oracle_sigs.push(sig);
        nonces.push(nonce);
        sk_nonces.push(sk_nonce);
    }

    oracle_info = OracleInfo {
        public_key: oracle_pubkey,
        nonces,
    };

    let funding_script_pubkey = make_funding_redeemscript(
        &offer_party_params.fund_pubkey,
        &accept_party_params.fund_pubkey,
    );
    let fund_output_value = dlc_txs.fund.output[0].value;

    // create adaptor signatures
    let adaptor_sigs = create_cet_adaptor_sigs_from_oracle_info(
        &secp,
        &cets,
        &[oracle_info.clone()],
        &offer_fund_sk,
        &funding_script_pubkey,
        fund_output_value,
        &[vec![messages.clone()], vec![messages.clone()]],
    )
    .unwrap();

    // sign CET
    let sign_res = sign_cet(
        &secp,
        &mut cets[0].clone(),
        &adaptor_sigs[0],
        &[vec![oracle_sigs[0]]],
        &offer_fund_sk,
        &offer_party_params.fund_pubkey,
        &funding_script_pubkey,
        fund_output_value,
    )
    .expect("Failed to sign CET");

    let adaptor_secret = signatures_to_secret(&[vec![oracle_sigs[0]]]).unwrap();
    let adapted_sig = adaptor_sigs[0].decrypt(&adaptor_secret).unwrap();

    // verify
    assert!(adaptor_sigs
        .iter()
        .enumerate()
        .all(|(i, x)| verify_cet_adaptor_sig_from_oracle_info(
            &secp,
            x,
            &cets[i],
            &[oracle_info.clone()],
            &offer_party_params.fund_pubkey,
            &funding_script_pubkey,
            fund_output_value,
            &[messages.clone()],
        )
        .is_ok()));
}

fn get_party_params(
    input_amount: u64,
    collateral: u64,
    serial_id: Option<u64>,
) -> (PartyParams, SecretKey) {
    let secp = Secp256k1::new();
    let mut rng = secp256k1_zkp::rand::thread_rng();
    let fund_privkey = SecretKey::new(&mut rng);
    let serial_id = serial_id.unwrap_or(1);
    (
        PartyParams {
            fund_pubkey: PublicKey::from_secret_key(&secp, &fund_privkey),
            change_script_pubkey: get_p2wpkh_script_pubkey(&secp, &mut rng),
            change_serial_id: serial_id,
            payout_script_pubkey: get_p2wpkh_script_pubkey(&secp, &mut rng),
            payout_serial_id: serial_id,
            input_amount,
            collateral,
            inputs: vec![TxInputInfo {
                max_witness_len: 108,
                redeem_script: ScriptBuf::new(),
                outpoint: OutPoint {
                    txid: Txid::from_str(
                        "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
                    )
                    .unwrap(),
                    vout: serial_id as u32,
                },
                serial_id,
            }],
        },
        fund_privkey,
    )
}

fn payouts() -> Vec<Payout> {
    vec![
        Payout {
            offer: 200000000,
            accept: 0,
        },
        Payout {
            offer: 0,
            accept: 200000000,
        },
    ]
}

fn get_p2wpkh_script_pubkey<C: Signing, R: Rng + ?Sized>(
    secp: &Secp256k1<C>,
    rng: &mut R,
) -> ScriptBuf {
    let sk = bitcoin::PrivateKey {
        inner: SecretKey::new(rng),
        network: Network::Testnet,
        compressed: true,
    };
    let pk = bitcoin::PublicKey::from_private_key(secp, &sk);
    Address::p2wpkh(&pk, Network::Testnet)
        .unwrap()
        .script_pubkey()
}

fn signatures_to_secret(signatures: &[Vec<SchnorrSignature>]) -> Result<SecretKey, Error> {
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
