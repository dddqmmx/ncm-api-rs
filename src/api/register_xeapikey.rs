use super::Query;
use crate::{error::Result, ApiClient, ApiResponse};

impl ApiClient {
    /// Fetch and authenticate the current XEAPI server public key.
    pub async fn register_xeapikey(&self, query: &Query) -> Result<ApiResponse> {
        let device_id = query.get_or("deviceId", self.get_device_id());
        let key = self
            .fetch_xeapi_key(
                query.domain.as_deref(),
                &device_id,
                &query.get_or("currentKeyVersion", ""),
            )
            .await?;
        let mut body = serde_json::to_value(key)?;
        body["deviceId"] = device_id.into();
        Ok(ApiResponse {
            status: 200,
            body,
            cookie: vec![],
        })
    }
}
