use std::collections::hash_map;

use crate::crypto::{self, KeyPair};

#[derive(Debug, PartialEq)]
pub struct Channel {
    client_list: hash_map::HashMap<[u8; 32], [u8; 32]>,
    handshake_key: KeyPair,
    encryption_key: [u8; 32],
}

impl Channel {
    pub fn new() -> Self {
        let client_list = hash_map::HashMap::new();
        let handshake_key = crypto::generate_key_pair(crypto::Algorithm::X25519);
        let encryption_key = crypto::generate_symmetric_key();

        Self {
            client_list,
            handshake_key,
            encryption_key,
        }
    }
}
