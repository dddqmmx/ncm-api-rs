//! Per-client, per-device and per-account XEAPI keys and session state.
use super::*;
use crate::crypto::{xeapi_decrypt_public_key, xeapi_sign, xeapi_verify_signature, XeapiPublicKey};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
pub(super) struct XeapiState {
    key: Option<XeapiPublicKey>,
    session: Option<(String, String)>,
}

impl std::fmt::Debug for XeapiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XeapiState")
            .field("key_loaded", &self.key.is_some())
            .field("session_loaded", &self.session.is_some())
            .finish()
    }
}

pub(super) type XeapiContexts = Arc<Mutex<HashMap<String, Arc<Mutex<XeapiState>>>>>;

impl ApiClient {
    pub(crate) async fn fetch_checktoken_v3(&self, domain: Option<&str>) -> Result<String> {
        let response = self
            .client
            .get(format!(
                "{}/v3/b?pn=YD00000558929251",
                domain
                    .filter(|d| !d.is_empty())
                    .unwrap_or("https://ac.dun.163yun.com")
            ))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| NcmError::Http(e.without_url()))?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .map_err(|e| NcmError::Http(e.without_url()))?;
        static TOKEN: LazyLock<regex_lite::Regex> = LazyLock::new(|| {
            regex_lite::Regex::new(r#"null\(\[(\d+),\d+,"([^"]+)"\]\)"#).expect("valid token regex")
        });
        if status == 200 {
            if let Some(captures) = TOKEN
                .captures(&body)
                .filter(|captures| &captures[1] == "200")
            {
                return Ok(captures[2].to_owned());
            }
        }
        Err(NcmError::Crypto(format!(
            "checkToken v3 response invalid (HTTP {status})"
        )))
    }
    pub(crate) async fn fetch_xeapi_key(
        &self,
        domain: Option<&str>,
        device_id: &str,
        current_version: &str,
    ) -> Result<XeapiPublicKey> {
        let nonce: String = (0..16)
            .map(|_| char::from(b'0' + rand::thread_rng().gen_range(0..10)))
            .collect();
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let params = [
            ("appVersion", "9.5.61"),
            ("currentKeyVersion", current_version),
            ("deviceId", device_id),
            ("nonce", &nonce),
            ("os", "android"),
            ("requestType", "active"),
            ("signature", &xeapi_sign(&timestamp, &nonce)),
            ("t1", ""),
            ("t2", ""),
            ("timestamp", &timestamp),
            ("uid", ""),
        ];
        let response = self.client.post(format!("{}/api/bsr/sk/get", domain.filter(|d| !d.is_empty()).unwrap_or(API_DOMAIN)))
            .header(USER_AGENT, "NeteaseMusic/9.5.61.260802021928(9005061);Dalvik/2.1.0 (Linux; U; Android 12; HBN-AL00 Build/cd737a2.0)")
            .header(COOKIE, format!("deviceId={}", urlencoding::encode(device_id)))
            .timeout(std::time::Duration::from_secs(15))
            .form(&params).send().await.map_err(|e| NcmError::Http(e.without_url()))?;
        let status = response.status().as_u16();
        let body: Value = response
            .json()
            .await
            .map_err(|e| NcmError::Http(e.without_url()))?;
        let code = business_code(&body).unwrap_or(i64::from(status));
        if status != 200 || code != 200 {
            return Err(response_error(
                "/api/bsr/sk/get",
                status,
                code,
                body,
                vec![],
            ));
        }
        let data = &body["data"];
        let response_timestamp = data["timestamp"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| data["timestamp"].as_i64().map(|value| value.to_string()))
            .ok_or_else(|| {
                NcmError::Crypto("XEAPI public key response missing timestamp".into())
            })?;
        let signature = data["signature"].as_str().unwrap_or("");
        if !xeapi_verify_signature(&response_timestamp, &nonce, signature) {
            return Err(NcmError::Crypto(
                "XEAPI public key response signature mismatch".into(),
            ));
        }
        xeapi_decrypt_public_key(data["encryptedData"].as_str().unwrap_or(""))
            .map_err(NcmError::Crypto)
    }

    pub(super) async fn request_xeapi(
        &self,
        uri: &str,
        data: Value,
        options: RequestOption,
        mut cookies: HashMap<String, String>,
        mut headers: HeaderMap,
    ) -> Result<ApiResponse> {
        let domain = options.domain.as_deref().filter(|d| !d.is_empty());
        let origin = domain.unwrap_or(XEAPI_DOMAIN);
        let device = cookies
            .get("deviceId")
            .cloned()
            .unwrap_or_else(|| self.get_device_id().into());
        // Authentication cookies supplied by each request stay isolated, even
        // when concurrent callers share one ApiClient or clone it.
        let auth = format!(
            "{}|{}",
            cookies.get("MUSIC_U").map(String::as_str).unwrap_or(""),
            cookies.get("MUSIC_A").map(String::as_str).unwrap_or("")
        );
        let context_key = format!("{origin}|{device}|{:x}", Sha256::digest(auth.as_bytes()));
        let context = {
            let mut contexts = self.xeapi_contexts.lock().await;
            if contexts.len() >= 64 && !contexts.contains_key(&context_key) {
                contexts.retain(|_, context| Arc::strong_count(context) > 1);
            }
            contexts.entry(context_key).or_default().clone()
        };
        let mut state = context.lock().await;
        if state.key.is_none() {
            state.key = Some(self.fetch_xeapi_key(domain, &device, "").await?);
        }
        let android = cookies.get("os").is_some_and(|os| os == "android");
        let appver = if android {
            cookies
                .get("appver")
                .cloned()
                .unwrap_or_else(|| "9.1.65".into())
        } else {
            "9.1.65".into()
        };
        let osver = if android {
            cookies.get("osver").cloned().unwrap_or_else(|| "16".into())
        } else {
            "16".into()
        };
        let buildver = cookies
            .get("buildver")
            .cloned()
            .unwrap_or_else(|| chrono::Utc::now().timestamp().to_string());
        let secondary = cookies
            .get("sDeviceId")
            .cloned()
            .unwrap_or_else(|| device.clone());
        for (name, value) in [
            ("x-deviceid", device.as_str()),
            ("x-os", "android"),
            ("x-osver", &osver),
            ("x-appver", &appver),
            ("x-sdeviceid", &secondary),
            ("x-buildver", &buildver),
        ] {
            headers.insert(name, header_value(value));
        }
        if let Some(cookie) = cookies.get("MUSIC_U") {
            headers.insert("x-music-u", header_value(cookie));
        }
        if options.check_token {
            headers.insert("X-antiCheatToken", header_value(CHECK_TOKEN));
        }
        headers.insert(
            USER_AGENT,
            header_value(
                options
                    .ua
                    .as_deref()
                    .unwrap_or_else(|| choose_user_agent("api", "android")),
            ),
        );
        headers.insert("X-Client-Enc-State", header_value("ENCRYPTED"));
        headers.insert("x-aeapi", header_value("true"));
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            header_value("application/x-www-form-urlencoded;charset=utf-8"),
        );
        for (name, value) in [
            ("os", "android".to_owned()),
            ("osver", osver),
            ("appver", appver),
            ("buildver", buildver),
            ("sDeviceId", secondary),
        ] {
            cookies.insert(name.into(), value);
        }
        headers.insert(COOKIE, header_value(&cookie_obj_to_string(&cookies)));
        let form = crypto::xeapi(
            uri,
            &data,
            state.key.as_ref().expect("key initialized"),
            "android",
            state
                .session
                .as_ref()
                .map(|(id, key)| (id.as_str(), key.as_str())),
        )
        .map_err(NcmError::Crypto)?;
        let client = if let Some(proxy) = options.proxy {
            reqwest::Client::builder()
                .proxy(
                    reqwest::Proxy::all(proxy)
                        .map_err(|_| NcmError::InvalidParam("invalid proxy URL".into()))?,
                )
                .build()?
        } else {
            self.client.clone()
        };
        let response = client
            .post(format!(
                "{origin}/xeapi/{}",
                uri.strip_prefix("/api/")
                    .ok_or_else(|| NcmError::InvalidParam(
                        "XEAPI endpoint must start with /api/".into()
                    ))?
            ))
            .headers(headers)
            .form(&form)
            .send()
            .await
            .map_err(|e| NcmError::Http(e.without_url()))?;
        let http_status = response.status().as_u16();
        let cookies = response_cookies(&response);
        let session = response
            .headers()
            .get("x-encr-ssid")
            .and_then(|h| h.to_str().ok())
            .zip(
                response
                    .headers()
                    .get("x-encr-sskey")
                    .and_then(|h| h.to_str().ok()),
            )
            .map(|(id, key)| (id.to_owned(), key.to_owned()));
        let bytes = response
            .bytes()
            .await
            .map_err(|e| NcmError::Http(e.without_url()))?;
        // Error responses can be plain JSON; never turn failed AES/JSON decoding
        // into Value::Null and accidentally report success.
        let body = match serde_json::from_slice::<Value>(&bytes) {
            Ok(body) if body.is_object() => body,
            _ => crypto::xeapi_res_decrypt(&bytes).map_err(|message| {
                NcmError::Crypto(format!(
                    "{uri}: HTTP {http_status}: {message} ({} bytes)",
                    bytes.len()
                ))
            })?,
        };
        let answer = finish_response(uri, http_status, body, cookies)?;
        if let Some((id, key)) = session {
            if !id.is_empty() && matches!(key.len(), 16 | 32) {
                state.session = Some((id, key));
            }
        }
        Ok(answer)
    }
}
