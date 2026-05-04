use std::error::Error;
use std::fmt::{Display, Formatter, Result as fmtResult};

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
pub enum MessageError {
    WrongSignatureSize,
    WrongNonceSize,
    EmptyCipherText,
}

impl Display for MessageError {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        let description = match *self {
            MessageError::WrongNonceSize => "Nonce is wrong size. Must be 12 byte",
            MessageError::WrongSignatureSize => "Signature is wrong size. Must be 64 byte",
            MessageError::EmptyCipherText => "Cipher text is empty. It must contain value",
        };

        f.write_str(description)
    }
}

impl Error for MessageError {}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SignedMessage {
    sender: String,
    nonce: Vec<u8>,
    cipher_text: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    signed_message: SignedMessage,
    signature: Vec<u8>,
}

impl Message {
    pub fn new(
        sender: String,
        nonce: Vec<u8>,
        cipher_text: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, MessageError> {
        // TODO: handle error in input here.

        if nonce.len() != 12 {
            return Err(MessageError::WrongNonceSize);
        }

        if signature.len() != 64 {
            return Err(MessageError::WrongSignatureSize);
        }

        if cipher_text.len() == 0 {
            return Err(MessageError::EmptyCipherText);
        }

        let signed_message = SignedMessage {
            sender,
            nonce,
            cipher_text,
        };

        Ok(Self {
            signed_message,
            signature,
        })
    }

    pub fn signed_message(&self) -> &SignedMessage {
        &self.signed_message
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
        let sender = "random dude".to_string();
        let nonce = vec![0u8; 12];
        let signature = vec![0u8; 64];
        let cipher_text = vec![0x0, 0x1];

        let message = Message::new(
            sender.clone(),
            nonce.clone(),
            cipher_text.clone(),
            signature.clone(),
        )
        .unwrap();

        let signed_message = SignedMessage {
            sender: sender.clone(),
            nonce: nonce.clone(),
            cipher_text: cipher_text.clone(),
        };

        assert_eq!(signature, message.signature());
        assert_eq!(signed_message, *message.signed_message());
    }

    #[test]
    fn wrong_nonce_size() {
        let sender = "random dude".to_string();
        let nonce = vec![0u8; 1];
        let signature = vec![0u8; 64];
        let cipher_text = vec![0x0, 0x1];

        let message = Message::new(sender, nonce, cipher_text, signature).unwrap_err();

        assert_eq!(message, MessageError::WrongNonceSize);
    }

    #[test]
    fn wrong_signature_size() {
        let sender = "random dude".to_string();
        let nonce = vec![0u8; 12];
        let signature = vec![0u8; 6];
        let cipher_text = vec![0x0, 0x1];

        let message = Message::new(sender, nonce, cipher_text, signature).unwrap_err();

        assert_eq!(message, MessageError::WrongSignatureSize);
    }

    #[test]
    fn empty_cipher_text() {
        let sender = "random dude".to_string();
        let nonce = vec![0u8; 12];
        let signature = vec![0u8; 64];
        let cipher_text = Vec::new();

        let message = Message::new(sender, nonce, cipher_text, signature).unwrap_err();

        assert_eq!(message, MessageError::EmptyCipherText);
    }
}
