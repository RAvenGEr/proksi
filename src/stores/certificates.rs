use openssl::{
    base64,
    pkey::{PKey, Private},
    x509::X509,
};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Clone)]
pub struct Certificate {
    pub key: PKey<Private>,
    pub leaf: X509,
    pub chain: Vec<X509>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SerializableCertificate {
    key: String,
    leaf: String,
    chain: Vec<String>,
}

impl Certificate {
    pub fn to_serializable(&self) -> Result<SerializableCertificate, Box<dyn Error>> {
        Ok(SerializableCertificate {
            key: base64::encode_block(&self.key.private_key_to_pem_pkcs8()?),
            leaf: base64::encode_block(&self.leaf.to_pem()?),
            chain: self
                .chain
                .iter()
                .map(|c| base64::encode_block(&c.to_pem().unwrap_or_default()))
                .collect(),
        })
    }

    pub fn from_serializable(cert: SerializableCertificate) -> Result<Self, Box<dyn Error>> {
        let key_data = base64::decode_block(&cert.key)?;
        let leaf_data = base64::decode_block(&cert.leaf)?;

        let key = PKey::private_key_from_pem(&key_data)?;
        let leaf = X509::from_pem(&leaf_data)?;
        let chain = cert
            .chain
            .into_iter()
            .map(|chain_b64| {
                let chain_data = base64::decode_block(&chain_b64)?;
                Ok(X509::from_pem(&chain_data)?)
            })
            .collect::<Result<Vec<X509>, Box<dyn Error>>>()?;

        Ok(Certificate { key, leaf, chain })
    }
}
