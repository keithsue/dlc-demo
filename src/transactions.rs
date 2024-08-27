use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
use bitcoin::Transaction;

// Build dlc transactions for staking
// Fee and change ignored for demo
// 1. CET for slashing execution
// 2. Unstaking tx for validator
pub fn build_dlc_transactions(
    contract_outpoint: OutPoint,
    contract_output: TxOut,
    validator_script_pubkey: ScriptBuf,
    protocol_script_pubkey: ScriptBuf,
) -> (Transaction, Transaction) {
    let cet_slashed = Transaction {
        version: 2,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: [TxIn {
            previous_output: contract_outpoint,
            ..Default::default()
        }]
        .to_vec(),
        output: [TxOut {
            value: contract_output.value,
            script_pubkey: protocol_script_pubkey,
        }]
        .to_vec(),
    };

    let unstake_tx = Transaction {
        version: 2,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: [TxIn {
            previous_output: contract_outpoint,
            ..Default::default()
        }]
        .to_vec(),
        output: [TxOut {
            value: contract_output.value,
            script_pubkey: validator_script_pubkey,
        }]
        .to_vec(),
    };

    (cet_slashed, unstake_tx)
}
