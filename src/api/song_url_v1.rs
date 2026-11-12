use super::Query;
use crate::error::Result;
/// 歌曲播放链接 v1
/// 对应 Node.js module/song_url_v1.js
use crate::request::{ApiClient, ApiResponse, CryptoType};
use serde_json::json;

impl ApiClient {
    /// 歌曲播放链接
    /// 对应 /song/url/v1
    pub async fn song_url_v1(&self, query: &Query) -> Result<ApiResponse> {
        let id = query.get_or("id", "0");
        let level = query.get_or("level", "standard");
        let mut data = json!({
            "ids": format!("[{}]", id),
            "level": level,
            "encodeType": "flac"
        });
        if level == "sky" {
            data["immerseType"] = json!(query.get_or("immerseType", "c51"));
        }
        let mut options = query.to_option(CryptoType::Xeapi);
        if level == "vivid" {
            data["encodeType"] = json!("mp3");
            let mut cookie =
                crate::util::cookie::cookie_to_json(options.cookie.as_deref().unwrap_or(""));
            cookie.insert("os".into(), "android".into());
            cookie.insert("appver".into(), "9.5.61".into());
            options.cookie = Some(crate::util::cookie::cookie_obj_to_string(&cookie));
        }
        self.request("/api/song/enhance/player/url/v1", data, options)
            .await
    }
}
