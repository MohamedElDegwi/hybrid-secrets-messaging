//! Crypto module provides the cryptographic operations needed to for enctypting, decrypting,
//! signing, verifying, generating keys, and derive shared secret for E2EE operations.

use std::error::Error;
use std::fmt::{Display, Formatter, Result as fmtResult};

use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::message::PayLoad;

pub enum Algorithm {
    Ed25519,
    X25519,
}

#[derive(Debug, PartialEq)]
pub enum CryptoErrors {
    EmptyRawMessage,
    TamperedMessage,
    InvalidPublicKey,
    FailedEncryption,
    UnVerifiableMessage,
}

impl Display for CryptoErrors {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match *self {
            CryptoErrors::EmptyRawMessage => f.write_str("Serialized raw message is empty."),
            CryptoErrors::TamperedMessage => {
                f.write_str("Cipher text is tampered. Cannot decrypt.")
            }
            CryptoErrors::InvalidPublicKey => f.write_str("Invalid public key."),
            CryptoErrors::FailedEncryption => f.write_str("Encryption process failed."),
            CryptoErrors::UnVerifiableMessage => {
                f.write_str("Cannot verify the authenticity of the message")
            }
        }
    }
}

impl Error for CryptoErrors {}

#[derive(Debug, PartialEq)]
pub struct KeyPair {
    priv_key: [u8; 32],
    pub_key: [u8; 32],
}

impl KeyPair {
    pub fn new(priv_key: [u8; 32], pub_key: [u8; 32]) -> Self {
        Self { priv_key, pub_key }
    }

    pub fn priv_key(&self) -> &[u8] {
        &self.priv_key
    }

    pub fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }
}

pub fn encrypt(message: Vec<u8>, encryption_key: &[u8; 32]) -> Result<PayLoad, CryptoErrors> {
    if message.is_empty() {
        return Err(CryptoErrors::EmptyRawMessage);
    }

    let key: &Key<Aes256Gcm> = encryption_key.into();
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(OsRng);

    let cipher_text = cipher
        .encrypt(&nonce, message.as_ref())
        .map_err(|_| CryptoErrors::FailedEncryption)?;

    let nonce: [u8; 12] = nonce.into();

    let payload = PayLoad::new(cipher_text, nonce).expect("error in creating payload");

    Ok(payload)
}

pub fn decrypt(payload: PayLoad, decryption_key: &[u8; 32]) -> Result<Vec<u8>, CryptoErrors> {
    let key: &Key<Aes256Gcm> = decryption_key.into();
    let cipher = Aes256Gcm::new(key);

    let message = cipher
        .decrypt(&payload.nonce.into(), payload.cipher_text.as_ref())
        .map_err(|_| CryptoErrors::TamperedMessage)?;

    Ok(message)
}

pub fn sign(payload: &PayLoad, signing_key: &[u8; 32]) -> [u8; 64] {
    let priv_key: SigningKey = SigningKey::from_bytes(signing_key);
    let signature: Signature = priv_key.sign(&payload.to_bytes());

    signature.to_bytes()
}

pub fn verify(
    payload: &PayLoad,
    signature: &[u8; 64],
    pub_key: &[u8; 32],
) -> Result<(), CryptoErrors> {
    let verifying_key: VerifyingKey =
        VerifyingKey::from_bytes(pub_key).map_err(|_| CryptoErrors::InvalidPublicKey)?;
    let signature: Signature = Signature::from_bytes(signature);

    verifying_key
        .verify(&payload.to_bytes(), &signature)
        .map_err(|_| CryptoErrors::UnVerifiableMessage)?;

    Ok(())
}

pub fn generate_symmetric_key() -> [u8; 32] {
    let encryption_key = Aes256Gcm::generate_key(OsRng);
    encryption_key.into()
}

pub fn generate_key_pair(key_type: Algorithm) -> KeyPair {
    match key_type {
        Algorithm::Ed25519 => {
            let key_pair: SigningKey = SigningKey::generate(&mut OsRng);
            KeyPair::new(key_pair.to_bytes(), key_pair.verifying_key().to_bytes())
        }
        Algorithm::X25519 => {
            let priv_key = StaticSecret::random_from_rng(OsRng);
            let pub_key = PublicKey::from(&priv_key);

            KeyPair::new(priv_key.to_bytes(), pub_key.to_bytes())
        }
    }
}

pub fn generate_channel_key() -> [u8; 32] {
    let channel_key = Aes256Gcm::generate_key(OsRng);

    channel_key.into()
}

pub fn derive_shared_secret(pub_key: &[u8; 32]) -> [u8; 32] {
    let priv_key = EphemeralSecret::random_from_rng(OsRng);
    let pub_key = PublicKey::from(*pub_key);
    let shared_secret = priv_key.diffie_hellman(&pub_key);

    *shared_secret.as_bytes()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let encryption_key = Aes256Gcm::generate_key(OsRng);

        let expected_message = b"some super secret message";

        let payload = encrypt(expected_message.into(), &encryption_key.into()).unwrap();

        let message = decrypt(payload, &encryption_key.into()).unwrap();

        assert_eq!(expected_message, message.as_slice())
    }

    #[test]
    fn encrypt_empty_message() {
        let message = Vec::default();

        let encryption_key = generate_symmetric_key();

        let err = encrypt(message, &encryption_key).unwrap_err();

        assert_eq!(err, CryptoErrors::EmptyRawMessage)
    }

    #[test]
    fn decrypt_tampered_cipher_text() {
        let message: Vec<u8> = Vec::from(b"mrdigo: some super secret message!");
        let encryption_key = generate_symmetric_key();
        let mut payload = encrypt(message, &encryption_key).unwrap();

        payload.cipher_text.iter_mut().for_each(|b| *b = 0xFF);

        let err = decrypt(payload, &encryption_key).unwrap_err();

        assert_eq!(err, CryptoErrors::TamperedMessage)
    }

    #[test]
    fn verify_unverified_cipher_text() {
        let message: Vec<u8> = Vec::from(b"mrdigo: some super secret message!");
        let encryption_key = generate_symmetric_key();
        let payload = encrypt(message, &encryption_key).unwrap();

        let signing_key = generate_key_pair(Algorithm::Ed25519);
        let signature = sign(&payload, &signing_key.priv_key);

        let wrong_key = generate_key_pair(Algorithm::Ed25519);
        let err = verify(&payload, &signature, &wrong_key.pub_key).unwrap_err();

        assert_eq!(err, CryptoErrors::UnVerifiableMessage)
    }
}
