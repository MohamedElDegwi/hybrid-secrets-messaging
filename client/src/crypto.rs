//! Crypto module provides the cryptographic operations needed to for enctypting, decrypting, and
//! signing messages for end to end encryption.

use std::error::Error;
use std::fmt::{Display, Formatter, Result as fmtResult};

#[derive(Debug, PartialEq)]
pub enum CryptoErrors {
    EmptyRawMessage,
    TamperedMessage,
    InvalidSigningKey,
    InvalidPublicKey,
    FailedNonceGen,
    UnVerifiableMessage,
}

impl Display for CryptoErrors {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match *self {
            CryptoErrors::EmptyRawMessage => f.write_str("Serialized raw message is empty."),
            CryptoErrors::TamperedMessage => f.write_str("Cipher text is tampered. Cannot decrypt"),
            CryptoErrors::InvalidSigningKey => f.write_str("Invalid signing key."),
            CryptoErrors::InvalidPublicKey => f.write_str("Invalid public key."),
            CryptoErrors::FailedNonceGen => f.write_str("Failed to generate nonce."),
            CryptoErrors::UnVerifiableMessage => {
                f.write_str("Cannot verify the authenticity of the message")
            }
        }
    }
}

impl Error for CryptoErrors {}

pub fn encrypt(
    message: Vec<u8>,
    encryption_key: [u8; 32],
) -> Result<(Vec<u8>, [u8; 12]), CryptoErrors> {
    Ok((vec![0u8; 1], [0u8; 12]))
}

pub fn decrypt(
    cipher_text: Vec<u8>,
    nonce: [u8; 12],
    decryption_key: [u8; 32],
) -> Result<Vec<u8>, CryptoErrors> {
    Ok(vec![0u8; 1])
}

pub fn sign(
    cipher_text: Vec<u8>,
    nonce: [u8; 12],
    signing_key: [u8; 32],
) -> Result<[u8; 64], CryptoErrors> {
    Ok([0u8; 64])
}

pub fn verify(
    cipher_text: Vec<u8>,
    nonce: [u8; 12],
    signature: [u8; 64],
    pub_key: [u8; 32],
) -> Result<(), CryptoErrors> {
    Ok(())
}

pub fn generate_key_pair() -> Result<([u8; 32], [u8; 32]), CryptoErrors> {
    Ok(([0u8; 32], [0u8; 32]))
} // Ok((priv_key, pub_key))

pub fn generate_channel_key() -> Result<[u8; 32], CryptoErrors> {
    Ok([0u8; 32])
}

pub fn derive_shared_secret(
    priv_key: [u8; 32],
    pub_key: [u8; 32],
) -> Result<[u8; 32], CryptoErrors> {
    Ok([0u8; 32])
}
