use crate::proto::{Body, Envelope, KeypairFile, Message, verify_bytes};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as b64};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use fs2::FileExt;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct ChannelKey {
    pub id: String,
    pub key: String,
}

impl std::fmt::Debug for ChannelKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChannelKey")
            .field("id", &self.id)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyOffer {
    pub channel: String,
    pub key_id: String,
    pub sender: String,
    pub recipient: String,
    pub nonce: String,
    pub ciphertext: String,
    pub sig: String,
}

#[derive(Serialize)]
struct KeyOfferPayload<'a> {
    channel: &'a str,
    key_id: &'a str,
    sender: &'a str,
    recipient: &'a str,
    nonce: &'a str,
    ciphertext: &'a str,
}

fn keyring_path(base: &Path, channel: &str) -> std::path::PathBuf {
    crate::util::channel_to_path(base, channel).join("channel-keys.json")
}

fn lock_keyring(base: &Path, channel: &str) -> Result<std::fs::File> {
    let path = crate::util::channel_to_path(base, channel).join("channel-keys.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    file.lock_exclusive()
        .with_context(|| format!("lock {}", path.display()))?;
    Ok(file)
}

pub fn load_keys(base: &Path, channel: &str) -> Result<Vec<ChannelKey>> {
    let path = keyring_path(base, channel);
    if !path.exists() {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("invalid channel keyring {}", path.display()))
}

fn save_keys(base: &Path, channel: &str, keys: &[ChannelKey]) -> Result<()> {
    let path = keyring_path(base, channel);
    let temp = path.with_extension(format!("json.tmp-{:016x}", rand::random::<u64>()));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    use std::io::Write;
    file.write_all(&serde_json::to_vec_pretty(keys)?)?;
    file.sync_all()?;
    std::fs::rename(temp, path)?;
    Ok(())
}

pub fn generate_channel_key(base: &Path, channel: &str) -> Result<ChannelKey> {
    let _lock = lock_keyring(base, channel)?;
    let mut raw = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(&mut *raw);
    let key = ChannelKey {
        id: hex::encode(blake3::hash(&*raw).as_bytes()),
        key: b64.encode(raw.as_slice()),
    };
    let mut keys = load_keys(base, channel)?;
    keys.retain(|existing| existing.id != key.id);
    keys.push(key.clone());
    save_keys(base, channel, &keys)?;
    Ok(key)
}

pub fn current_channel_key(base: &Path, channel: &str) -> Result<ChannelKey> {
    load_keys(base, channel)?.last().cloned().with_context(|| {
        format!("no encryption key for private channel {channel}; synchronize with a member first")
    })
}

fn decode_key(key: &ChannelKey) -> Result<[u8; 32]> {
    Zeroizing::new(b64.decode(&key.key)?)
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("channel key must contain 32 bytes"))
}

fn message_aad(channel: &str, key_id: &str) -> Vec<u8> {
    format!("embernet-message-v1\n{channel}\n{key_id}").into_bytes()
}

pub fn encrypt_message(base: &Path, channel: &str, mut message: Message) -> Result<Message> {
    let key = current_channel_key(base, channel)?;
    let raw_key = Zeroizing::new(decode_key(&key)?);
    let plaintext = match message.body {
        Body::Text { text } => text.into_bytes(),
        Body::Encrypted { .. } => bail!("message is already encrypted"),
    };
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new((&*raw_key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &message_aad(channel, &key.id),
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt private-channel message"))?;
    message.body = Body::Encrypted {
        key_id: key.id.clone(),
        nonce: b64.encode(nonce),
        ciphertext: b64.encode(ciphertext),
    };
    Ok(message)
}

pub fn decrypt_envelope(base: &Path, envelope: &Envelope) -> Result<Envelope> {
    let Body::Encrypted {
        key_id,
        nonce,
        ciphertext,
    } = &envelope.msg.body
    else {
        return Ok(envelope.clone());
    };
    let key = load_keys(base, &envelope.channel)?
        .into_iter()
        .find(|key| key.id == *key_id)
        .with_context(|| format!("missing decryption key {}", key_id))?;
    let raw_key = Zeroizing::new(decode_key(&key)?);
    let nonce: [u8; 24] = b64
        .decode(nonce)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("encrypted message nonce must contain 24 bytes"))?;
    let ciphertext = b64.decode(ciphertext)?;
    let plaintext = XChaCha20Poly1305::new((&*raw_key).into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &message_aad(&envelope.channel, key_id),
            },
        )
        .map_err(|_| anyhow::anyhow!("decrypt private-channel message {}", envelope.id))?;
    let mut decrypted = envelope.clone();
    decrypted.msg.body = Body::Text {
        text: String::from_utf8(plaintext).context("decrypted message is not UTF-8")?,
    };
    Ok(decrypted)
}

fn x25519_secret(identity: &KeypairFile) -> Result<StaticSecret> {
    let seed = identity.signing_key()?.to_bytes();
    let digest = Sha512::digest(seed);
    let mut scalar = [0_u8; 32];
    scalar.copy_from_slice(&digest[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    Ok(StaticSecret::from(scalar))
}

fn x25519_public(ed25519_public: &str) -> Result<PublicKey> {
    let bytes: [u8; 32] = hex::decode(ed25519_public)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad Ed25519 public key"))?;
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .context("invalid Ed25519 public key")?;
    Ok(PublicKey::from(point.to_montgomery().to_bytes()))
}

fn offer_wrap_key(
    identity: &KeypairFile,
    other: &str,
    channel: &str,
    key_id: &str,
) -> Result<[u8; 32]> {
    let shared = x25519_secret(identity)?.diffie_hellman(&x25519_public(other)?);
    if !shared.was_contributory() {
        bail!("refusing non-contributory X25519 key exchange");
    }
    let mut material = Zeroizing::new(b"embernet-key-wrap-v1\n".to_vec());
    material.extend_from_slice(shared.as_bytes());
    material.extend_from_slice(channel.as_bytes());
    material.push(b'\n');
    material.extend_from_slice(key_id.as_bytes());
    Ok(*blake3::hash(&material).as_bytes())
}

fn offer_aad(channel: &str, key_id: &str, sender: &str, recipient: &str) -> Vec<u8> {
    format!("embernet-key-offer-v1\n{channel}\n{key_id}\n{sender}\n{recipient}").into_bytes()
}

pub fn make_key_offers(
    base: &Path,
    channel: &str,
    sender: &KeypairFile,
    recipient: &str,
) -> Result<Vec<KeyOffer>> {
    load_keys(base, channel)?
        .into_iter()
        .map(|key| {
            let raw = Zeroizing::new(decode_key(&key)?);
            let wrap_key = Zeroizing::new(offer_wrap_key(sender, recipient, channel, &key.id)?);
            let mut nonce = [0_u8; 24];
            OsRng.fill_bytes(&mut nonce);
            let ciphertext = XChaCha20Poly1305::new((&*wrap_key).into())
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: raw.as_slice(),
                        aad: &offer_aad(channel, &key.id, &sender.public_key, recipient),
                    },
                )
                .map_err(|_| anyhow::anyhow!("wrap channel key"))?;
            let nonce = b64.encode(nonce);
            let ciphertext = b64.encode(ciphertext);
            let payload = KeyOfferPayload {
                channel,
                key_id: &key.id,
                sender: &sender.public_key,
                recipient,
                nonce: &nonce,
                ciphertext: &ciphertext,
            };
            let mut signed = b"embernet-key-offer-signature-v1\n".to_vec();
            signed.extend_from_slice(&serde_json::to_vec(&payload)?);
            Ok(KeyOffer {
                channel: channel.to_string(),
                key_id: key.id.clone(),
                sender: sender.public_key.clone(),
                recipient: recipient.to_string(),
                nonce,
                ciphertext,
                sig: sender.sign_bytes(&signed)?,
            })
        })
        .collect()
}

pub fn accept_key_offers(
    base: &Path,
    channel: &str,
    recipient: &KeypairFile,
    offers: &[KeyOffer],
) -> Result<usize> {
    let _lock = lock_keyring(base, channel)?;
    let mut keys = load_keys(base, channel)?;
    let mut accepted = 0;
    for offer in offers {
        if offer.channel != channel || offer.recipient != recipient.public_key {
            bail!("channel key offer has the wrong channel or recipient");
        }
        let payload = KeyOfferPayload {
            channel: &offer.channel,
            key_id: &offer.key_id,
            sender: &offer.sender,
            recipient: &offer.recipient,
            nonce: &offer.nonce,
            ciphertext: &offer.ciphertext,
        };
        let mut signed = b"embernet-key-offer-signature-v1\n".to_vec();
        signed.extend_from_slice(&serde_json::to_vec(&payload)?);
        verify_bytes(&offer.sender, &offer.sig, &signed)?;
        let wrap_key = Zeroizing::new(offer_wrap_key(
            recipient,
            &offer.sender,
            channel,
            &offer.key_id,
        )?);
        let nonce: [u8; 24] = b64
            .decode(&offer.nonce)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("key offer nonce must contain 24 bytes"))?;
        let ciphertext = b64.decode(&offer.ciphertext)?;
        let raw = Zeroizing::new(
            XChaCha20Poly1305::new((&*wrap_key).into())
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &offer_aad(channel, &offer.key_id, &offer.sender, &offer.recipient),
                    },
                )
                .map_err(|_| anyhow::anyhow!("unwrap channel key"))?,
        );
        if raw.len() != 32 {
            bail!("unwrapped channel key must contain 32 bytes");
        }
        if hex::encode(blake3::hash(&raw).as_bytes()) != offer.key_id {
            bail!("channel key offer id does not match its key");
        }
        if !keys.iter().any(|key| key.id == offer.key_id) {
            keys.push(ChannelKey {
                id: offer.key_id.clone(),
                key: b64.encode(raw),
            });
            accepted += 1;
        }
    }
    if accepted > 0 {
        save_keys(base, channel, &keys)?;
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Message;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "embernet_crypto_{name}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(path.join("channels/private/test")).unwrap();
        path
    }

    #[test]
    fn encrypted_message_round_trip_and_wrong_key_fails() {
        let base = temp_dir("message");
        let channel = "private/test";
        generate_channel_key(&base, channel).unwrap();
        let message = Message::new_text(None, Vec::new(), "secret".into(), Vec::new());
        let encrypted = encrypt_message(&base, channel, message).unwrap();
        assert!(matches!(encrypted.body, Body::Encrypted { .. }));
        let identity = KeypairFile::generate(Some("alice".into()));
        let envelope = Envelope::sign(identity, channel, encrypted).unwrap();
        assert_eq!(
            decrypt_envelope(&base, &envelope).unwrap().body_text(),
            Some("secret")
        );

        let outsider = temp_dir("outsider");
        assert!(decrypt_envelope(&outsider, &envelope).is_err());
        let _ = std::fs::remove_dir_all(base);
        let _ = std::fs::remove_dir_all(outsider);
    }

    #[test]
    fn member_can_accept_authenticated_wrapped_keys() {
        let alice_dir = temp_dir("alice");
        let bob_dir = temp_dir("bob");
        let channel = "private/test";
        let alice = KeypairFile::generate(Some("alice".into()));
        let bob = KeypairFile::generate(Some("bob".into()));
        let expected = generate_channel_key(&alice_dir, channel).unwrap();
        let offers = make_key_offers(&alice_dir, channel, &alice, &bob.public_key).unwrap();
        assert_eq!(
            accept_key_offers(&bob_dir, channel, &bob, &offers).unwrap(),
            1
        );
        assert_eq!(load_keys(&bob_dir, channel).unwrap(), vec![expected]);
        assert_eq!(
            accept_key_offers(&bob_dir, channel, &bob, &offers).unwrap(),
            0
        );
        let _ = std::fs::remove_dir_all(alice_dir);
        let _ = std::fs::remove_dir_all(bob_dir);
    }

    #[test]
    fn key_offer_cannot_be_redirected_to_another_identity() {
        let base = temp_dir("redirect");
        let channel = "private/test";
        let alice = KeypairFile::generate(Some("alice".into()));
        let bob = KeypairFile::generate(Some("bob".into()));
        let eve = KeypairFile::generate(Some("eve".into()));
        generate_channel_key(&base, channel).unwrap();
        let offers = make_key_offers(&base, channel, &alice, &bob.public_key).unwrap();
        assert!(accept_key_offers(&base, channel, &eve, &offers).is_err());
        let _ = std::fs::remove_dir_all(base);
    }
}
