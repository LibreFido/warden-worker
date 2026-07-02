use worker::{Env, Fetch, Method, Request, RequestInit};
use crate::error::AppError;

/// Verify Yubico OTP
/// Returns the first 12-character device ID on success, or an error on failure or network timeout
pub async fn verify_yubico_otp(env: &Env, otp: &str) -> Result<String, AppError> {
    if otp.len() != 44 {
        return Err(AppError::BadRequest("Invalid YubiKey OTP format, expected 44 characters".to_string()));
    }

    // === [Security] Strict whitelist validation of Modhex charset to prevent injection attacks ===
    if !otp.chars().all(|c| "cbdefghijklnrtuv".contains(c)) {
        return Err(AppError::BadRequest("YubiKey OTP contains invalid characters".to_string()));
    }

    // Get environment variables
    let client_id = env.var("YUBICO_CLIENT_ID")
        .map(|v| v.to_string())
        .map_err(|_| AppError::BadRequest("Administrator has not configured this feature".to_string()))?;

    let device_id = &otp[0..12]; 
    let nonce = uuid::Uuid::new_v4().to_string().replace("-", "");
    
    let url = format!(
        "https://api.yubico.com/wsapi/2.0/verify?id={}&otp={}&nonce={}",
        client_id, otp, nonce
    );

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let req = Request::new_with_init(&url, &init).map_err(|_| AppError::Internal)?;

    match Fetch::Request(req).send().await {
        Ok(mut response) => {
            let body = response.text().await.unwrap_or_default();
            
            // === [Security] Mandatory integrity check to confirm Yubico returned our nonce and otp exactly ===
            if body.contains("status=OK") 
                && body.contains(&format!("otp={}", otp)) 
                && body.contains(&format!("nonce={}", nonce)) 
            {
                Ok(device_id.to_string())
            } else {
                Err(AppError::BadRequest("Yubico verification failed (Invalid OTP or abnormal response)".to_string()))
            }
        },
        Err(_) => Err(AppError::BadRequest("Yubico verification network timeout or exception".to_string())),
    }
}