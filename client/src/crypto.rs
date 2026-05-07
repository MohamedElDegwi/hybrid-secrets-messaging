//! Crypto module provides the cryptographic operations needed to for enctypting, decrypting, and
//! signing messages for end to end encryption.

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

pub fn sign(payload: &PayLoad, signing_key: &[u8; 32]) -> Result<[u8; 64], CryptoErrors> {
    let priv_key: SigningKey = SigningKey::from_bytes(signing_key);
    let signature: Signature = priv_key.sign(&payload.to_bytes());

    Ok(signature.to_bytes())
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

pub fn generate_key_pair(key_type: Algorithm) -> ([u8; 32], [u8; 32]) {
    match key_type {
        Algorithm::Ed25519 => {
            let key_pair: SigningKey = SigningKey::generate(&mut OsRng);

            (key_pair.to_bytes(), key_pair.verifying_key().to_bytes())
        }
        Algorithm::X25519 => {
            let priv_key = StaticSecret::random_from_rng(OsRng);
            let pub_key = PublicKey::from(&priv_key);

            (*priv_key.as_bytes(), *pub_key.as_bytes())
        }
    }
} // Ok((priv_key, pub_key)) -- TODO: use struct User::KeyPair once it ready.

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
}
