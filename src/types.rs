use std::collections::BTreeMap;

use crate::secp256k1_zkp::XOnlyPublicKey;
use dlc::OracleInfo;

#[derive(Clone)]
pub struct EventName(String);

impl EventName {
    pub fn new(chain_id: &str, validator_address: &str, event_type: &str) -> Self {
        EventName(format!("{}-{}-{}", chain_id, validator_address, event_type))
    }

    pub fn to_string(&self) -> String {
        self.0.clone()
    }
}

#[derive(Clone)]
pub struct OracleInfoWithEvents {
    pub public_key: XOnlyPublicKey,
    pub events: BTreeMap<String, XOnlyPublicKey>,
}

impl OracleInfoWithEvents {
    pub fn oracle_info(&self, event_name: &String) -> Option<OracleInfo> {
        match self.events.get(event_name) {
            Some(pk) => Some(OracleInfo {
                public_key: self.public_key,
                nonces: vec![*pk],
            }),
            None => None,
        }
    }
}
