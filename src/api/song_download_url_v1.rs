use super::Query;
use crate::error::Result;
/// 歌曲下载链接 v1
/// 对应 Node.js module/song_download_url_v1.js
use crate::request::{ApiClient, ApiResponse, CryptoType};
use serde_json::json;

impl ApiClient {
    /// 歌曲下载链接 v1
    /// 对应 /song/download/url/v1
    pub async fn song_download_url_v1(&self, query: &Query) -> Result<ApiResponse> {
        let data = json!({
            "id": query.get_or("id", "0"),
            "immerseType": "c51",
            "level": query.get_or("level", "standard")
        });
        let mut options = query.to_option(CryptoType::default());
        if query.get_or("level", "standard") == "vivid" {
            let mut cookie =
                crate::util::cookie::cookie_to_json(options.cookie.as_deref().unwrap_or(""));
            cookie.insert("os".into(), "android".into());
            cookie.insert("appver".into(), "9.5.61".into());
            options.cookie = Some(crate::util::cookie::cookie_obj_to_string(&cookie));
        }
        self.request("/api/song/enhance/download/url/v1", data, options)
            .await
    }
}
