//! Message module provides the data contract for client-server communication.
//! It defines the structures used for represent and validate client messages on the wire.

use std::error::Error;
use std::fmt::{Display, Formatter, Result as fmtResult};

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
pub enum MessageError {
    WrongSignatureSize(usize),
    WrongPublicKeySize(usize),
    EmptyCipherText,
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
            MessageError::EmptyCipherText => {
                f.write_str("Cipher text is empty. It must contain value")
            }
        }
    }
}

impl Error for MessageError {}

/// Represents a single message block, containing sender public key, nonce, cipher text, and sender
/// signature.
///
/// # Constraints
/// - `pub_key` must be 32 bytes
/// - `nonce` must be 12 bytes
/// - `cipher_text` must not be empty
/// - `signature` must be 64 bytes
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub_key: Vec<u8>,
    nonce: [u8; 12],
    cipher_text: Vec<u8>,
    signature: Vec<u8>,
}

impl Message {
    pub fn new(
        pub_key: Vec<u8>,
        nonce: [u8; 12],
        cipher_text: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, MessageError> {
        if pub_key.len() != 32 {
            return Err(MessageError::WrongPublicKeySize(pub_key.len()));
        }

        if signature.len() != 64 {
            return Err(MessageError::WrongSignatureSize(signature.len()));
        }

        if cipher_text.is_empty() {
            return Err(MessageError::EmptyCipherText);
        }

        Ok(Self {
            pub_key,
            nonce,
            cipher_text,
            signature,
        })
    }

    pub fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
    pub fn cipher_text(&self) -> &[u8] {
        &self.cipher_text
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
        let nonce = [0u8; 12];
        let signature = vec![0u8; 64];
        let cipher_text = vec![0u8; 256];

        let message = Message::new(
            pub_key.clone(),
            nonce.clone(),
            cipher_text.clone(),
            signature.clone(),
        )
        .unwrap();

        assert_eq!(pub_key, message.pub_key());
        assert_eq!(nonce, message.nonce());
        assert_eq!(cipher_text, message.cipher_text());
        assert_eq!(signature, message.signature());
    }

    #[test]
    fn wrong_signature_size() {
        let pub_key = vec![0u8; 32];
        let nonce = [0u8; 12];
        let signature = vec![0u8; 6];
        let cipher_text = vec![0u8; 256];

        let message = Message::new(pub_key, nonce, cipher_text, signature.clone()).unwrap_err();

        assert_eq!(message, MessageError::WrongSignatureSize(signature.len()));
    }

    #[test]
    fn wrong_pub_key_size() {
        let pub_key = vec![0u8; 3];
        let nonce = [0u8; 12];
        let signature = vec![0u8; 64];
        let cipher_text = vec![0u8; 256];

        let message = Message::new(pub_key.clone(), nonce, cipher_text, signature).unwrap_err();

        assert_eq!(message, MessageError::WrongPublicKeySize(pub_key.len()));
    }

    #[test]
    fn empty_cipher_text() {
        let pub_key = vec![0u8; 32];
        let nonce = [0u8; 12];
        let signature = vec![0u8; 64];
        let cipher_text = Vec::new();

        let message = Message::new(pub_key, nonce, cipher_text, signature).unwrap_err();

        assert_eq!(message, MessageError::EmptyCipherText);
    }
}
