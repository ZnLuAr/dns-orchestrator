use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Domain not found: {0}")]
    DomainNotFound(String),

    #[error("Record not found: {0}")]
    RecordNotFound(String),

    #[error("Credential error: {0}")]
    CredentialError(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl Serialize for DnsError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, DnsError>;
