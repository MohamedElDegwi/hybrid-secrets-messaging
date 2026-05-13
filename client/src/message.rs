//! Message module provides the data contract for client-server communication.
//! It defines the structures used for represent and validate client messages on the wire.

use std::error::Error;
use std::fmt::{Display, Formatter, Result as fmtResult};

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
pub enum MessageError {
    WrongSignatureSize(usize),
    WrongPublicKeySize(usize),
    EmptyPayload,
}

impl Display for MessageError {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match *self {
            MessageError::WrongSignatureSize(wrong_size) => {
                write!(f, "Signature is wrong size: {wrong_size}. Must be 64 bytes")
            }
            MessageError::WrongPublicKeySize(wrong_size) => {
                write!(
                    f,
                    "Public key is wrong size: {wrong_size}. Must be 32 bytes"
                )
            }
            MessageError::EmptyPayload => {
                f.write_str("Payload is empty. It must contain cipher text AND nonce")
            }
        }
    }
}
impl Error for MessageError {}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PayLoad {
    pub nonce: [u8; 12],
    pub cipher_text: Vec<u8>,
}

impl PayLoad {
    pub fn new(cipher_text: Vec<u8>, nonce: [u8; 12]) -> Result<Self, MessageError> {
        if cipher_text.is_empty() || nonce.is_empty() {
            return Err(MessageError::EmptyPayload);
        }

        Ok(Self { cipher_text, nonce })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = self.nonce.to_vec();
        res.extend_from_slice(&self.cipher_text);

        res
    }
}

/// Represents a single message block, containing sender public key, nonce, cipher text, and sender signature. # Constraints - `pub_key` must be 32 bytes - `nonce` must be 12 bytes - `cipher_text` must not be empty
/// - `signature` must be 64 bytes
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub_key: Vec<u8>,
    payload: PayLoad,
    signature: Vec<u8>,
}

impl Message {
    pub fn new(
        pub_key: Vec<u8>,
        payload: PayLoad,
        signature: Vec<u8>,
    ) -> Result<Self, MessageError> {
        if pub_key.len() != 32 {
            return Err(MessageError::WrongPublicKeySize(pub_key.len()));
        }

        if signature.len() != 64 {
            return Err(MessageError::WrongSignatureSize(signature.len()));
        }

        Ok(Self {
            pub_key,
            payload,
            signature,
        })
    }

    pub fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    pub fn payload(&self) -> &PayLoad {
        &self.payload
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path() {
        let pub_key = vec![0u8; 32];
        let payload = PayLoad {
            nonce: [0u8; 12],
            cipher_text: vec![0u8; 256],
        };

        let signature = vec![0u8; 64];

        let message = Message::new(pub_key.clone(), payload.clone(), signature.clone()).unwrap();

        assert_eq!(pub_key, message.pub_key());
        assert_eq!(&payload, message.payload());
        assert_eq!(signature, message.signature());
    }

    #[test]
    fn wrong_signature_size() {
        let pub_key = vec![0u8; 32];
        let payload = PayLoad {
            nonce: [0u8; 12],
            cipher_text: vec![0u8; 256],
        };

        let signature = vec![0u8; 6];

        let message = Message::new(pub_key, payload, signature.clone()).unwrap_err();

        assert_eq!(message, MessageError::WrongSignatureSize(signature.len()));
    }

    #[test]
    fn wrong_pub_key_size() {
        let pub_key = vec![0u8; 3];
        let payload = PayLoad {
            nonce: [0u8; 12],
            cipher_text: vec![0u8; 256],
        };
        let signature = vec![0u8; 64];

        let message = Message::new(pub_key.clone(), payload, signature).unwrap_err();

        assert_eq!(message, MessageError::WrongPublicKeySize(pub_key.len()));
    }

    #[test]
    fn empty_payload() {
        let payload = PayLoad::new(Vec::default(), [0u8; 12]).unwrap_err();

        assert_eq!(payload, MessageError::EmptyPayload);
    }
}
