use super::Query;
use crate::error::Result;
/// 回复评论
/// 对应 Node.js module/comment_reply.js
use crate::request::{ApiClient, ApiResponse, CryptoType};
use serde_json::json;

impl ApiClient {
    /// 回复评论
    /// 对应 /comment/reply
    pub async fn comment_reply(&self, query: &Query) -> Result<ApiResponse> {
        let data = json!({
            "threadId": query.get_or("threadId", &format!("{}{}", crate::util::config::RESOURCE_TYPE_MAP.get(query.get_or("type", "0").as_str()).copied().unwrap_or("R_SO_4_"), query.get_or("id", ""))),
            "commentId": query.get_or("cid", &query.get_or("commentId", "")),
            "content": query.get_or("content", ""),
            "resourceType": "0"
        });
        let mut options = query.to_option(CryptoType::Xeapi);
        if options.check_token_version.is_none() {
            options.check_token_version = Some("v3".into());
        }
        self.request("/api/v1/resource/comments/reply", data, options)
            .await
    }
}
