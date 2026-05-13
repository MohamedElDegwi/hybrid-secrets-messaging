use std::error::Error;
use std::fmt::{Display, Formatter, Result as fmtResult};

use crate::crypto::{self, KeyPair};

#[derive(Debug, PartialEq)]
pub enum UserErrors {
    InvalidName,
    InvalidNickname,
}

impl Display for UserErrors {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match *self {
            UserErrors::InvalidName => {
                f.write_str("Invalid user name, it must start with 3 alphabitic letters at least.")
            }
            UserErrors::InvalidNickname => {
                f.write_str("Invalid nickname, it must start with 3 alphabitic letters at least.")
            }
        }
    }
}

impl Error for UserErrors {}

#[derive(Debug, PartialEq)]
pub struct User {
    name: String,
    nickname: Option<String>,
    signing_key: KeyPair,
}

impl User {
    pub fn new(name: String, nickname: Option<String>) -> Result<Self, UserErrors> {
        if name.len() < 3 || !&name[..3].chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(UserErrors::InvalidName);
        }
        if let Some(ref nick) = nickname {
            if nick.len() < 3 || !&nick[..3].chars().all(|c| c.is_ascii_alphabetic()) {
                return Err(UserErrors::InvalidNickname);
            }
        }
        let signing_key = crypto::generate_key_pair(crypto::Algorithm::Ed25519);

        Ok(Self {
            name,
            nickname,
            signing_key,
        })
    }
}
