//! XEAPI CSR format, ported from api-enhanced 4a7d557 (2026-11-06).
use super::*;
use aes_gcm::{aead::Aead, Aes128Gcm, Nonce};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Read;
use x25519_dalek::{PublicKey, StaticSecret};

const STATIC_KEY: [u8; 32] = [
    0xab, 0x1d, 0x5a, 0x43, 0x0f, 0x6b, 0xb0, 0x4a, 0x3f, 0x01, 0xe8, 0x1d, 0xdd, 0x72, 0xbd, 0x91,
    0x6d, 0x5c, 0xe5, 0x91, 0x24, 0x8a, 0xc1, 0x28, 0x71, 0x48, 0x06, 0xd7, 0xf8, 0xfb, 0x1b, 0x84,
];
const SIGN_KEY: &[u8] =
    b"mUHCwVNWJbunMqAHf5MImuirT6plvs6VSFW62MGHstFQxhBGdEoIhLItH3djc4+FB/OKty3+lL2rGeoFBpVe5g==";
const MAX_PLAINTEXT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XeapiPublicKey {
    pub public_key: String,
    pub version: String,
    pub sk: String,
}

impl XeapiPublicKey {
    pub fn validate(&self) -> Result<[u8; 32], String> {
        if self.sk.is_empty() || self.version.is_empty() {
            return Err("XEAPI key response missing sk/version".into());
        }
        STANDARD
            .decode(&self.public_key)
            .map_err(|_| "invalid XEAPI public key encoding".to_owned())?
            .try_into()
            .map_err(|_| "XEAPI X25519 public key must be 32 bytes".into())
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn xeapi_sign(timestamp: &str, nonce: &str) -> String {
    STANDARD.encode(hmac(SIGN_KEY, format!("{timestamp}{nonce}").as_bytes()))
}

pub fn xeapi_verify_signature(timestamp: &str, nonce: &str, signature: &str) -> bool {
    let Ok(signature) = STANDARD.decode(signature) else {
        return false;
    };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(SIGN_KEY).expect("valid HMAC key");
    mac.update(format!("{timestamp}{nonce}").as_bytes());
    mac.verify_slice(&signature).is_ok()
}

fn ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    match key.len() {
        16 => Ok(ecb::Encryptor::<aes::Aes128>::new_from_slice(key)
            .map_err(|_| "invalid AES key")?
            .encrypt_padded_vec_mut::<Pkcs7>(data)),
        32 => Ok(ecb::Encryptor::<aes::Aes256>::new_from_slice(key)
            .map_err(|_| "invalid AES key")?
            .encrypt_padded_vec_mut::<Pkcs7>(data)),
        _ => Err("XEAPI session key must be 16 or 32 bytes".into()),
    }
}

fn ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    match key.len() {
        16 => ecb::Decryptor::<aes::Aes128>::new_from_slice(key)
            .map_err(|_| "invalid AES key")?
            .decrypt_padded_vec_mut::<Pkcs7>(data),
        32 => ecb::Decryptor::<aes::Aes256>::new_from_slice(key)
            .map_err(|_| "invalid AES key")?
            .decrypt_padded_vec_mut::<Pkcs7>(data),
        _ => return Err("invalid AES key length".into()),
    }
    .map_err(|_| "XEAPI AES response decryption/padding failed".into())
}

fn form_content(data: &serde_json::Value) -> Result<String, String> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    if let Some(data) = data.as_object() {
        for (key, value) in data {
            if key == "e_r" {
                continue;
            }
            let value = match value {
                serde_json::Value::String(value) => value.clone(),
                // URLSearchParams uses JavaScript's String conversion.
                serde_json::Value::Array(values) => values
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string())
                    })
                    .collect::<Vec<_>>()
                    .join(","),
                serde_json::Value::Object(_) => "[object Object]".into(),
                _ => value.to_string(),
            };
            serializer.append_pair(key, &value);
        }
    } else {
        return Err("XEAPI data must be a JSON object".into());
    }
    Ok(serializer.finish())
}

pub fn xeapi(
    uri: &str,
    data: &serde_json::Value,
    key: &XeapiPublicKey,
    os: &str,
    session: Option<(&str, &str)>,
) -> Result<HashMap<String, String>, String> {
    let mut entropy = [0u8; 76];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    xeapi_with_entropy(uri, data, key, os, session, entropy)
}

fn xeapi_with_entropy(
    uri: &str,
    data: &serde_json::Value,
    key: &XeapiPublicKey,
    os: &str,
    session: Option<(&str, &str)>,
    entropy: [u8; 76],
) -> Result<HashMap<String, String>, String> {
    let peer = PublicKey::from(key.validate()?);
    let dynamic_key = session
        .map(|(_, key)| key.as_bytes())
        .unwrap_or(&entropy[..16]);
    let mut fields = serde_json::Map::new();
    let content = form_content(data)?;
    if !content.is_empty() {
        fields.insert("content".into(), content.into());
    }
    let query = uri
        .split_once('?')
        .map(|(_, query)| format!("{query}&e_r=true"))
        .unwrap_or_else(|| "e_r=true".into());
    fields.insert("queryString".into(), query.into());
    let plaintext = serde_json::to_vec(&fields).map_err(|_| "XEAPI JSON serialization failed")?;
    let mut middle = ecb_encrypt(&STATIC_KEY, &plaintext)?;
    let mask = &entropy[16..32];
    for (i, byte) in middle.iter_mut().enumerate() {
        *byte ^= mask[i % 16];
    }
    let rotation = usize::from(mask[0] & 15) % middle.len();
    middle.rotate_left(rotation);
    let mut masked = mask.to_vec();
    masked.extend(middle);
    let c = ecb_encrypt(dynamic_key, &masked)?;

    let secret = StaticSecret::from(<[u8; 32]>::try_from(&entropy[32..64]).expect("fixed slice"));
    let ephemeral = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&peer);
    if !shared.was_contributory() {
        return Err("XEAPI server public key produced an invalid shared secret".into());
    }
    let prk = hmac(&[0u8; 32], shared.as_bytes());
    let mut info = ephemeral.as_bytes().to_vec();
    info.push(1);
    let expanded = hmac(&prk, &info);
    let cipher = <Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(&expanded[..16])
        .map_err(|_| "invalid XEAPI GCM key")?;
    let plaintext = format!("{}|{os}|{}", STANDARD.encode(dynamic_key), key.sk);
    let sealed = cipher
        .encrypt(Nonce::from_slice(&entropy[64..76]), plaintext.as_bytes())
        .map_err(|_| "XEAPI GCM encryption failed")?;
    let mut s = ephemeral.as_bytes().to_vec();
    s.extend_from_slice(&entropy[64..76]);
    s.extend(sealed);
    let r = ecb_encrypt(
        &STATIC_KEY,
        format!(
            "{}|{}",
            key.version,
            session.map(|(id, _)| id).unwrap_or("")
        )
        .as_bytes(),
    )?;
    Ok(HashMap::from([
        ("C".into(), URL_SAFE_NO_PAD.encode(c)),
        ("S".into(), STANDARD.encode(s)),
        ("R".into(), STANDARD.encode(r)),
    ]))
}

pub fn xeapi_decrypt_public_key(encoded: &str) -> Result<XeapiPublicKey, String> {
    let ciphertext = STANDARD
        .decode(encoded)
        .map_err(|_| "XEAPI public key response is not base64")?;
    let bytes = ecb_decrypt(&STATIC_KEY, &ciphertext)?;
    let key: XeapiPublicKey = serde_json::from_slice(&bytes)
        .map_err(|_| "XEAPI public key response is not valid JSON")?;
    key.validate()?;
    Ok(key)
}

pub fn xeapi_res_decrypt(ciphertext: &[u8]) -> Result<serde_json::Value, String> {
    let bytes = ecb_decrypt(EAPI_KEY, ciphertext)?;
    let plaintext = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .take(MAX_PLAINTEXT_BYTES + 1)
            .read_to_end(&mut decoded)
            .map_err(|_| "XEAPI gzip response decompression failed")?;
        if decoded.len() as u64 > MAX_PLAINTEXT_BYTES {
            return Err("XEAPI decompressed response exceeds 16 MiB".into());
        }
        decoded
    } else {
        bytes
    };
    serde_json::from_slice(&plaintext)
        .map_err(|_| "XEAPI decrypted response is not valid JSON".into())
}

/// Debugging helper: decoding requests requires the matching server private key.
pub fn xeapi_req_decrypt(
    form: &HashMap<String, String>,
    server_private: [u8; 32],
) -> Result<serde_json::Value, String> {
    let s = STANDARD
        .decode(form.get("S").ok_or("missing XEAPI S")?)
        .map_err(|_| "invalid S encoding")?;
    if s.len() < 60 {
        return Err("truncated XEAPI S".into());
    }
    let ephemeral =
        PublicKey::from(<[u8; 32]>::try_from(&s[..32]).map_err(|_| "invalid ephemeral key")?);
    let secret = StaticSecret::from(server_private);
    let shared = secret.diffie_hellman(&ephemeral);
    let prk = hmac(&[0u8; 32], shared.as_bytes());
    let mut info = s[..32].to_vec();
    info.push(1);
    let expanded = hmac(&prk, &info);
    let cipher = <Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(&expanded[..16])
        .map_err(|_| "invalid key")?;
    let session = cipher
        .decrypt(Nonce::from_slice(&s[32..44]), &s[44..])
        .map_err(|_| "XEAPI request authentication failed")?;
    let session = String::from_utf8(session).map_err(|_| "invalid session text")?;
    let dynamic = STANDARD
        .decode(session.split('|').next().ok_or("missing key")?)
        .map_err(|_| "invalid dynamic key")?;
    let c = URL_SAFE_NO_PAD
        .decode(form.get("C").ok_or("missing XEAPI C")?)
        .map_err(|_| "invalid C encoding")?;
    let middle = ecb_decrypt(&dynamic, &c)?;
    if middle.len() <= 16 {
        return Err("truncated XEAPI C".into());
    }
    let mask = &middle[..16];
    let mut bytes = middle[16..].to_vec();
    let rotation = usize::from(mask[0] & 15) % bytes.len();
    bytes.rotate_right(rotation);
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte ^= mask[i % 16];
    }
    serde_json::from_slice(&ecb_decrypt(&STATIC_KEY, &bytes)?)
        .map_err(|_| "invalid request plaintext".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../tests/fixtures/xeapi-node.json")).unwrap()
    }

    #[test]
    fn csr_ciphertext_and_signature_match_current_node_upstream() {
        let fixture = fixture();
        let key = serde_json::from_value(fixture["publicKey"].clone()).unwrap();
        let entropy: Vec<u8> = serde_json::from_value(fixture["entropy"].clone()).unwrap();
        let request = xeapi_with_entropy(
            "/api/song/enhance/player/url/v1",
            &fixture["data"],
            &key,
            "android",
            None,
            entropy.try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), fixture["request"]);
        let entropy: Vec<u8> = serde_json::from_value(fixture["entropy"].clone()).unwrap();
        let session_request = xeapi_with_entropy(
            "/api/song/enhance/player/url/v1",
            &fixture["data"],
            &key,
            "android",
            Some(("fixture-session", "0123456789abcdef")),
            entropy.try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(session_request).unwrap(),
            fixture["sessionRequest"]
        );
        assert_eq!(
            xeapi_sign("1794492360000", "0123456789012345"),
            fixture["sign"]
        );
        assert!(xeapi_verify_signature(
            "1794492360000",
            "0123456789012345",
            fixture["sign"].as_str().unwrap()
        ));
        assert!(!xeapi_verify_signature(
            "1794492360001",
            "0123456789012345",
            fixture["sign"].as_str().unwrap()
        ));
        let secret: Vec<u8> = serde_json::from_value(fixture["serverSecret"].clone()).unwrap();
        let decoded = xeapi_req_decrypt(&request, secret.try_into().unwrap()).unwrap();
        assert!(decoded["content"].as_str().unwrap().contains("level=hires"));
        assert_eq!(decoded["queryString"], "e_r=true");
    }

    #[test]
    fn node_key_and_compressed_response_fixtures_decrypt() {
        let fixture = fixture();
        let key = xeapi_decrypt_public_key(fixture["encryptedKey"].as_str().unwrap()).unwrap();
        assert_eq!(serde_json::to_value(key).unwrap(), fixture["publicKey"]);
        for field in ["encryptedResponse", "compressedResponse"] {
            assert_eq!(
                xeapi_res_decrypt(&STANDARD.decode(fixture[field].as_str().unwrap()).unwrap())
                    .unwrap(),
                fixture["response"]
            );
        }
        assert!(xeapi_res_decrypt(b"bad ciphertext").is_err());
    }
}
