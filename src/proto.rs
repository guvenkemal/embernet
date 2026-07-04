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
    pub id: String, // blake3(msg_bytes) — content hash
    pub channel: String,
    pub from: String, // pubkey hex
    pub from_alias: Option<String>,
    pub ts: i64,
    pub sig: String, // ed25519 sig hex over (channel_bytes || b'\n' || msg_bytes)
    pub msg: Message,
}

impl Envelope {
    /// Create a signed envelope.
    ///
    /// * `id` = blake3(serde_json(msg))
    /// * `sig` = ed25519(channel_bytes || b'\n' || serde_json(msg))
    pub fn sign(kf: KeypairFile, channel: &str, msg: Message) -> Result<Self> {
        let msg_bytes = serde_json::to_vec(&msg)?;
        let id = hex::encode(blake3::hash(&msg_bytes).as_bytes());

        // Sign over channel || separator || message to bind channel to signature
        let channel_bytes = channel.as_bytes();
        let mut signed_payload = Vec::with_capacity(channel_bytes.len() + 1 + msg_bytes.len());
        signed_payload.extend_from_slice(channel_bytes);
        signed_payload.push(b'\n');
        signed_payload.extend_from_slice(&msg_bytes);

        let sk = kf.signing_key()?;
        let sig = sk.sign(&signed_payload);
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

    /// Verify the envelope's signature and content-id integrity.
    ///
    /// Checks:
    /// 1. The Ed25519 signature over `(channel || '\n' || serde_json(msg))`
    ///    is valid for the claimed `from` public key.
    /// 2. The `id` field matches blake3(serde_json(msg)) — closing the
    ///    lying-id gap.
    pub fn verify(&self) -> Result<()> {
        // ── recompute signed payload (channel || '\n' || msg_bytes) ──
        let msg_bytes = serde_json::to_vec(&self.msg)?;
        let channel_bytes = self.channel.as_bytes();
        let mut signed_payload = Vec::with_capacity(channel_bytes.len() + 1 + msg_bytes.len());
        signed_payload.extend_from_slice(channel_bytes);
        signed_payload.push(b'\n');
        signed_payload.extend_from_slice(&msg_bytes);

        // ── verify signature ──
        let pk_bytes: [u8; 32] = hex::decode(&self.from)?
            .try_into()
            .map_err(|_| anyhow!("bad pk"))?;
        let pk = VerifyingKey::from_bytes(&pk_bytes)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.sig)?
            .try_into()
            .map_err(|_| anyhow!("bad sig"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        pk.verify(&signed_payload, &sig)
            .map_err(|e| anyhow!("signature verification failed: {e}"))?;

        // ── verify id matches content ──
        let expected_id = hex::encode(blake3::hash(&msg_bytes).as_bytes());
        if self.id != expected_id {
            return Err(anyhow!(
                "id mismatch: claimed {} but computed {}",
                self.id,
                expected_id
            ));
        }

        Ok(())
    }

    pub fn body_text(&self) -> Option<&str> {
        match &self.msg.body {
            Body::Text { text } => Some(text.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_keypair(alias: &str) -> KeypairFile {
        KeypairFile::generate(Some(alias.to_string()))
    }

    fn make_msg(body: &str) -> Message {
        Message {
            ts: Utc::now().timestamp(),
            r#type: MsgType::Post,
            title: Some("test".into()),
            tags: vec!["test".into()],
            refs: vec![],
            body: Body::Text { text: body.into() },
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = make_keypair("alice");
        let msg = make_msg("hello embernet");
        let env = Envelope::sign(kp, "tech/test", msg).unwrap();
        env.verify().unwrap();
    }

    #[test]
    fn tampered_sig_fails() {
        let kp = make_keypair("alice");
        let msg = make_msg("hello embernet");
        let mut env = Envelope::sign(kp, "tech/test", msg).unwrap();

        // flip last byte of signature
        let mut sig_bytes = hex::decode(&env.sig).unwrap();
        sig_bytes[63] ^= 1;
        env.sig = hex::encode(&sig_bytes);

        assert!(env.verify().is_err());
    }

    #[test]
    fn tampered_body_fails() {
        let kp = make_keypair("alice");
        let msg = make_msg("hello embernet");
        let mut env = Envelope::sign(kp, "tech/test", msg).unwrap();

        // modify message body after signing
        #[allow(irrefutable_let_patterns)]
        if let Body::Text { ref mut text } = env.msg.body {
            *text = "hacked!".into();
        }

        assert!(env.verify().is_err());
    }

    #[test]
    fn wrong_channel_fails_signature() {
        let kp = make_keypair("alice");
        let msg = make_msg("hello embernet");
        let mut env = Envelope::sign(kp, "tech/test", msg).unwrap();

        // channel not included → signature should reject replay
        env.channel = "evil/hijacked".into();
        assert!(env.verify().is_err());
    }

    #[test]
    fn mismatched_id_fails() {
        let kp = make_keypair("alice");
        let msg = make_msg("hello embernet");
        let mut env = Envelope::sign(kp, "tech/test", msg).unwrap();

        // Fabricate a different id
        env.id = "deadbeef".repeat(8); // 64 hex chars
        assert!(env.verify().is_err());
    }

    #[test]
    fn keypair_generate_roundtrip() {
        let kp = KeypairFile::generate(Some("bob".into()));
        let temp = std::env::temp_dir().join("embernet_test_keypair.json");
        kp.save(&temp).unwrap();
        let loaded = KeypairFile::load(&temp).unwrap();
        let _ = std::fs::remove_file(&temp);
        assert_eq!(kp.public_key, loaded.public_key);
        assert_eq!(kp.alias, loaded.alias);
        // secret key round-trips through b64
        let sk1 = kp.signing_key().unwrap();
        let sk2 = loaded.signing_key().unwrap();
        assert_eq!(
            sk1.verifying_key().as_bytes(),
            sk2.verifying_key().as_bytes()
        );
    }
}
