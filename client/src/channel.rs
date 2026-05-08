use std::collections::hash_map;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as fmtResult};

use crate::crypto::{self, KeyPair};
use crate::message::PayLoad;

#[derive(Debug, PartialEq)]
pub enum ChannelErrors {
    UnknownClient,
    AlreadyJoined,
    FailedToJoin,
}

impl Display for ChannelErrors {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match *self {
            ChannelErrors::UnknownClient => {
                f.write_str("This client is not registered yet. Unknown client.")
            }
            ChannelErrors::AlreadyJoined => f.write_str("cannot add this client. Already joined."),
            ChannelErrors::FailedToJoin => {
                f.write_str("Failed to join the channel. please try again.")
            }
        }
    }
}

impl Error for ChannelErrors {}

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

    pub fn callout(&self) -> &[u8] {
        &self.handshake_key.pub_key()
    }

    pub fn join(&self, otherside_pubkey: [u8; 32]) -> Result<PayLoad, ChannelErrors> {
        let shared_secret = crypto::derive_shared_secret(&otherside_pubkey);

        let payload = crypto::encrypt(self.encryption_key.into(), &shared_secret)
            .map_err(|_| ChannelErrors::AlreadyJoined)?;

        Ok(payload)
    }

    pub fn on_join(
        &mut self,
        otherside_handshake: PayLoad,
        otherside_pubkey: [u8; 32],
    ) -> Result<(), ChannelErrors> {
        let shared_secret = crypto::derive_shared_secret(&otherside_pubkey);
        let encryption_key = crypto::decrypt(otherside_handshake, &shared_secret)
            .map_err(|_| ChannelErrors::FailedToJoin)?;
        let encryption_key = encryption_key.try_into().expect("key must be 32 bytes");

        if self.client_list.contains_key(&otherside_pubkey) {
            return Err(ChannelErrors::AlreadyJoined);
        }

        self.client_list.insert(otherside_pubkey, encryption_key);

        Ok(())
    }

    /// this suppose to delete the left client from client list, rotate the encryption key, resend
    /// the handshake.
    pub fn on_leave(&mut self, left_client_pubkey: [u8; 32]) {
        self.client_list.remove(&left_client_pubkey);

        self.encryption_key = crypto::generate_symmetric_key();
    }
}
