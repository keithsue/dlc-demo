mod transactions;
mod types;
mod utils;

use std::collections::BTreeMap;

use bitcoin::blockdata::transaction::{OutPoint, TxOut};
use bitcoin::hashes::Hash;
use bitcoin::{network::constants::Network, Txid};

use secp256k1_zkp::{rand::RngCore, KeyPair, Message, Secp256k1, XOnlyPublicKey};

use dlc::*;

use transactions::build_dlc_transactions;
use types::EventName;
use types::OracleInfoWithEvents;
use utils::*;

fn main() {
    // parties involving in the staking contract
    let (validator_privkey, validator_pubkey) = get_random_keypair();
    let (protocol_privkey, protocol_pubkey) = get_random_keypair();

    // validator staking info
    let validator_script_pubkey = get_p2wpkh_script_pubkey(validator_pubkey, Network::Signet);
    let staking_amount = 100000000;

    // protocol info
    let protocol_script_pubkey = get_p2wpkh_script_pubkey(protocol_pubkey, Network::Signet);

    // multisig contract
    let contract_script_pubkey = get_staking_contract_script(&validator_pubkey, &protocol_pubkey);
    let contract_outpoint = OutPoint::new(Txid::all_zeros(), 0);
    let contract_output = TxOut {
        value: staking_amount,
        script_pubkey: contract_script_pubkey.clone(),
    };

    let (mut cet_slashed, _unstake_tx) = build_dlc_transactions(
        contract_outpoint,
        contract_output.clone(),
        validator_script_pubkey,
        protocol_script_pubkey,
    );

    // staking event outcome which is only a single value "true" meaning the slashed event occurs
    let outcome = "true";
    let message =
        Message::from_hashed_data::<secp256k1_zkp::hashes::sha256::Hash>(outcome.as_bytes());

    // staking events
    let chain_id = "Ethereum";
    let validator_address = "0x5FaA53FA3Bdb4a4f21681D9a0ad4198DFF336Ab8";
    let slashed_event_double_sign = "double_sign";
    let slashed_event_downtime = "downtime";

    let event_names = [
        EventName::new(chain_id, validator_address, slashed_event_double_sign).to_string(),
        EventName::new(chain_id, validator_address, slashed_event_downtime).to_string(),
    ];

    let mut events = BTreeMap::<String, XOnlyPublicKey>::new();

    // oracle related operations
    // single oracle for demo

    let secp = Secp256k1::new();
    let mut rng = secp256k1_zkp::rand::thread_rng();

    // key pair
    let oracle_kp = KeyPair::new(&secp, &mut rng);
    let oracle_pubkey = oracle_kp.x_only_public_key().0;

    // nonces
    let mut sk_nonces = Vec::new();
    let mut nonces = Vec::new();

    for i in 0..event_names.len() {
        let mut sk_nonce = [0u8; 32];
        rng.fill_bytes(&mut sk_nonce);

        let oracle_r_kp = KeyPair::from_seckey_slice(&secp, &sk_nonce).unwrap();
        let nonce = XOnlyPublicKey::from_keypair(&oracle_r_kp).0;

        sk_nonces.push(sk_nonce);
        nonces.push(nonce);

        events.insert(event_names[i].clone(), nonce);
    }

    // oracle info to be published
    let oracle_info_with_events = OracleInfoWithEvents {
        public_key: oracle_pubkey,
        events,
    };

    // create CET adaptor signature for the validator's possible double signing event
    let cet_slashed_adaptor_sig = create_cet_adaptor_sig_from_oracle_info(
        &secp,
        &cet_slashed,
        &[oracle_info_with_events
            .oracle_info(&event_names[0])
            .unwrap()],
        &validator_privkey,
        &contract_script_pubkey,
        contract_output.value,
        &[vec![message]],
    )
    .unwrap();

    // verify the adaptor signature
    verify_cet_adaptor_sig_from_oracle_info(
        &secp,
        &cet_slashed_adaptor_sig,
        &cet_slashed,
        &[oracle_info_with_events
            .oracle_info(&event_names[0])
            .unwrap()],
        &validator_pubkey,
        &contract_script_pubkey,
        contract_output.value,
        &[vec![message]],
    )
    .expect("Failed to verify the adaptor signature");

    // oracle publishes the signature of the event outcome
    // meaning that the validator is slashed due to double signing
    let oracle_signature =
        secp_utils::schnorrsig_sign_with_nonce(&secp, &message, &oracle_kp, &sk_nonces[0]);

    // sign CET with the protocol's self-signature and the validator's adaptor signature
    sign_cet(
        &secp,
        &mut cet_slashed,
        &cet_slashed_adaptor_sig,
        &[vec![oracle_signature]],
        &protocol_privkey,
        &validator_pubkey, // corresponding to adaptor signature
        &contract_script_pubkey,
        contract_output.value,
    )
    .expect("Failed to sign CET");

    // decrypt the adaptor signature
    let adaptor_secret = signatures_to_secret(&[vec![oracle_signature]]).unwrap();
    let adapted_sig = cet_slashed_adaptor_sig.decrypt(&adaptor_secret).unwrap();

    // verify if the adapted signature is valid against the CET
    verify_tx_input_sig(
        &secp,
        &adapted_sig,
        &cet_slashed,
        0,
        &contract_script_pubkey.as_script(),
        contract_output.value,
        &validator_pubkey,
    )
    .expect("Decrypted adapted signature is invalid");
}
