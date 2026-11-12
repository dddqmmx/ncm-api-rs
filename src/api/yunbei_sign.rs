use super::Query;
use crate::error::Result;
/// 云贝签到
/// 对应 Node.js module/yunbei_sign.js
use crate::request::{ApiClient, ApiResponse, CryptoType};
use serde_json::json;

impl ApiClient {
    /// 云贝签到
    /// 对应 /yunbei/sign
    pub async fn yunbei_sign(&self, query: &Query) -> Result<ApiResponse> {
        let data = json!({});
        let mut options = query.to_option(CryptoType::Xeapi);
        if options.check_token_version.is_none() {
            options.check_token_version = Some("v3".into());
        }
        self.request("/api/pointmall/user/sign", data, options)
            .await
    }
}
