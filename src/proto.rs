use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as b64};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeypairFile {
    pub alias: Option<String>,
    pub public_key: String, // hex
    pub secret_key: String, // base64 keypair bytes (ed25519-dalek v2)
}

impl KeypairFile {
    pub fn generate(alias: Option<String>) -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        Self {
            alias,
            public_key: hex::encode(pk.as_bytes()),
            secret_key: b64.encode(sk.to_keypair_bytes()),
        }
    }
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
    pub fn load(path: &std::path::Path) -> Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
    pub fn signing_key(&self) -> Result<SigningKey> {
        let bytes = b64.decode(&self.secret_key)?;
        let arr: [u8; 64] = bytes.try_into().map_err(|_| anyhow!("bad key bytes"))?;
        Ok(SigningKey::from_keypair_bytes(&arr)?)
    }
    #[allow(dead_code)]
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let pk = hex::decode(&self.public_key)?;
        let arr: [u8; 32] = pk.try_into().map_err(|_| anyhow!("bad pk bytes"))?;
        Ok(VerifyingKey::from_bytes(&arr)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub ts: i64,
    pub r#type: MsgType,
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub refs: Vec<String>,
    pub body: Body,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Body {
    Text { text: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MsgType {
    Post,
    Reply,
    Vote,
    Mod,
}

impl Message {
    pub fn new_text(
        title: Option<String>,
        tags: Vec<String>,
        text: String,
        refs: Vec<String>,
    ) -> Self {
        Self {
            ts: Utc::now().timestamp(),
            r#type: MsgType::Post,
            title,
            tags,
            refs,
            body: Body::Text { text },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub id: String, // blake3(body)
    pub channel: String,
    pub from: String, // pubkey hex
    pub from_alias: Option<String>,
    pub ts: i64,
    pub sig: String, // ed25519 sig hex
    pub msg: Message,
}

impl Envelope {
    pub fn sign(kf: KeypairFile, channel: &str, msg: Message) -> Result<Self> {
        let body_bytes = serde_json::to_vec(&msg)?;
        let id = hex::encode(blake3::hash(&body_bytes).as_bytes());
        let sk = kf.signing_key()?;
        let sig = sk.sign(&body_bytes);
        Ok(Self {
            id,
            channel: channel.to_string(),
            from: kf.public_key,
            from_alias: kf.alias,
            ts: msg.ts,
            sig: hex::encode(sig.to_bytes()),
            msg,
        })
    }
    pub fn verify(&self) -> Result<()> {
        let pk_bytes: [u8; 32] = hex::decode(&self.from)?
            .try_into()
            .map_err(|_| anyhow!("bad pk"))?;
        let pk = VerifyingKey::from_bytes(&pk_bytes)?;
        let body = serde_json::to_vec(&self.msg)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.sig)?
            .try_into()
            .map_err(|_| anyhow!("bad sig"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        pk.verify(&body, &sig)?;
        Ok(())
    }
    pub fn body_text(&self) -> Option<&str> {
        match &self.msg.body {
            Body::Text { text } => Some(text.as_str()),
        }
    }
}
