use axum::{extract::State, Json};
use serde_json::Value;
use std::sync::Arc;
use worker::Env;

use crate::d1_query;
use crate::{
    auth::AuthUser,
    crypto::{base32_decode, ct_eq, generate_recovery_code, generate_totp_secret, validate_totp},
    db,
    error::AppError,
    handlers::allow_totp_drift,
    models::twofactor::{
        DisableAuthenticatorData, DisableTwoFactorData, EnableAuthenticatorData, TwoFactor,
        TwoFactorType, EnableYubikeyData,
    },
    models::user::{PasswordOrOtpData, User},
};

/// List all 2FA records for a user (excludes atype >= 1000).
pub(crate) async fn list_user_twofactors(
    db: &crate::db::Db,
    user_id: &str,
) -> Result<Vec<TwoFactor>, AppError> {
    db.prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000")
        .bind(&[user_id.to_string().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<TwoFactor>()
        .map_err(|_| AppError::Database)
}

/// Whether the user has 2FA enabled.
///
/// For now, we intentionally only treat Authenticator (TOTP) as a real 2FA provider.
/// Remember-device tokens are never considered a 2FA method by themselves.
pub(crate) fn is_twofactor_enabled(twofactors: &[TwoFactor]) -> bool {
    twofactors
        .iter()
        .any(|tf| tf.enabled && (tf.atype == TwoFactorType::Authenticator as i32 || tf.atype == TwoFactorType::YubiKey as i32))
}

/// GET /api/two-factor - Get all enabled 2FA providers for current user
#[worker::send]
pub async fn get_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let twofactors = list_user_twofactors(&db, &user_id).await?;
    let twofactors: Vec<Value> = twofactors.iter().map(|tf| tf.to_json_provider()).collect();

    Ok(Json(serde_json::json!({
        "data": twofactors,
        "object": "list",
        "continuationToken": null,
    })))
}

/// POST /api/two-factor/get-authenticator - Get or generate TOTP secret
#[worker::send]
pub async fn get_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(&user, &data).await?;

    // Check if TOTP is already configured
    let existing: Option<Value> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.clone().into(),
            (TwoFactorType::Authenticator as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let (enabled, key) = match existing {
        Some(tf_value) => {
            let tf: TwoFactor = serde_json::from_value(tf_value).map_err(|_| AppError::Internal)?;
            (true, tf.data)
        }
        None => (false, generate_totp_secret()?),
    };

    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// POST /api/two-factor/authenticator - Activate TOTP
#[worker::send]
pub async fn activate_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    let key = data.key.to_uppercase();

    // Validate key format (Base32, 20 bytes = 32 characters without padding)
    let decoded_key = base32_decode(&key)?;
    if decoded_key.len() != 20 {
        return Err(AppError::BadRequest("Invalid key length".to_string()));
    }

    // Check if TOTP is already configured - reuse existing record for replay protection
    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.clone().into(),
            (TwoFactorType::Authenticator as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    // Get last_used from existing record to prevent replay during reconfiguration
    let previous_last_used = existing.as_ref().map(|tf| tf.last_used).unwrap_or(0);

    // Validate TOTP code and capture time step for replay protection
    let allow_drift = allow_totp_drift(&env);
    let last_used_step = validate_totp(&data.token, &key, previous_last_used, allow_drift).await?;

    // Delete existing TOTP and any remember-device tokens bound to it to avoid stale bypass
    d1_query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype IN (?2, ?3)",
        &user_id,
        TwoFactorType::Authenticator as i32,
        TwoFactorType::Remember as i32
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Create new TOTP entry
    let mut twofactor = TwoFactor::new(user_id.clone(), TwoFactorType::Authenticator, key.clone());
    twofactor.last_used = last_used_step;

    d1_query!(
        &db,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &twofactor.uuid,
        &twofactor.user_uuid,
        twofactor.atype,
        twofactor.enabled as i32,
        &twofactor.data,
        twofactor.last_used
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Generate recovery code if not exists
    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// PUT /api/two-factor/authenticator - Same as POST
#[worker::send]
pub async fn activate_authenticator_put(
    state: State<Arc<Env>>,
    auth_user: AuthUser,
    json: Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    activate_authenticator(state, auth_user, json).await
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[worker::send]
pub async fn disable_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    let type_ = data.r#type;

    // Delete the specified 2FA type
    d1_query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &user_id,
        type_
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    log::info!("User {} disabled 2FA type {}", user_id, type_);

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": type_,
        "object": "twoFactorProvider"
    })))
}

/// DELETE /api/two-factor/authenticator - Disable TOTP with key verification
#[worker::send]
pub async fn disable_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    if data.r#type != TwoFactorType::Authenticator as i32 {
        return Err(AppError::BadRequest("Invalid two factor type".to_string()));
    }

    // Verify master password (OTP not supported in this minimal implementation)
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    // Fetch existing TOTP and verify key matches before deleting
    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[user_id.clone().into(), data.r#type.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    let Some(tf) = existing else {
        return Err(AppError::BadRequest("TOTP not configured".to_string()));
    };

    // Compare keys case-insensitively (key is stored uppercased during activation)
    if !ct_eq(&tf.data, &data.key.to_uppercase()) {
        return Err(AppError::BadRequest(
            "TOTP key does not match recorded value".to_string(),
        ));
    }

    d1_query!(&db, "DELETE FROM twofactor WHERE uuid = ?1", &tf.uuid)
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    log::info!(
        "User {} disabled authenticator (2FA type {})",
        user_id,
        data.r#type
    );

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": data.r#type,
        "object": "twoFactorProvider"
    })))
}

/// PUT /api/two-factor/disable - Same as POST
#[worker::send]
pub async fn disable_twofactor_put(
    state: State<Arc<Env>>,
    auth_user: AuthUser,
    json: Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    disable_twofactor(state, auth_user, json).await
}

/// POST /api/two-factor/get-recover - Get recovery code
#[worker::send]
pub async fn get_recover(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(&user, &data).await?;

    Ok(Json(serde_json::json!({
        "code": user.totp_recover,
        "object": "twoFactorRecover"
    })))
}

// Helper functions

async fn validate_password_or_otp(user: &User, data: &PasswordOrOtpData) -> Result<(), AppError> {
    if let Some(ref password_hash) = data.master_password_hash {
        let verification = user.verify_master_password(password_hash).await?;
        if verification.is_valid() {
            return Ok(());
        }
    }

    // OTP validation would be handled here if we had protected actions support
    // For now, master password is required

    Err(AppError::Unauthorized("Invalid password".to_string()))
}

async fn generate_recovery_code_for_user(
    db: &crate::db::Db,
    user_id: &str,
) -> Result<(), AppError> {
    // Check if recovery code already exists
    let user_value: Value = db
        .prepare("SELECT totp_recover FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let totp_recover: Option<String> = user_value
        .get("totp_recover")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if totp_recover.is_none() {
        let recovery_code = generate_recovery_code()?;
        d1_query!(
            db,
            "UPDATE users SET totp_recover = ?1 WHERE id = ?2",
            &recovery_code,
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}

/// Clear recovery code when no real 2FA providers remain.
async fn clear_recovery_if_no_twofactor(db: &crate::db::Db, user_id: &str) -> Result<(), AppError> {
    let remaining: Vec<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000 AND atype != ?2")
        .bind(&[
            user_id.to_string().into(),
            (TwoFactorType::Remember as i32).into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    if remaining.is_empty() {
        d1_query!(
            db,
            "UPDATE users SET totp_recover = NULL WHERE id = ?1",
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}

/// POST /api/two-factor/yubikey - Activate YubiKey
#[worker::send]
pub async fn activate_yubikey(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableYubikeyData>,
) -> Result<Json<Value>, AppError> {
    // === [Security] Add rate limiting to prevent brute force ===
    if let Ok(rate_limiter) = env.rate_limiter("LOGIN_RATE_LIMITER") {
        let rate_limit_key = format!("2fa-check:{}", user_id);
        if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await {
            if !outcome.success {
                return Err(AppError::TooManyRequests("Too many validation attempts. Please try again later.".to_string()));
            }
        }
    }
    let db = db::get_db(&env)?;

    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: None,
        },
    )
    .await?;

    // [Security 1]: Automatically trim leading/trailing whitespace/newlines to improve fault tolerance
    let keys = vec![data.key1, data.key2, data.key3, data.key4, data.key5]
        .into_iter()
        .filter_map(|k| k.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .collect::<Vec<String>>();

    if keys.is_empty() {
        return Err(AppError::BadRequest("At least one YubiKey OTP must be provided.".to_string()));
    }

    // [Fix 1]: Use Vec instead of HashSet to preserve the order of user-provided YubiKey slots
    let mut devices_array = Vec::new();
    for item in keys {
        let item_len = item.len();
        let device_id = if item_len == 12 {
            // Already a bound device ID (old key), reuse directly without remote verification
            if !item.chars().all(|c| "cbdefghijklnrtuv".contains(c)) {
                return Err(AppError::BadRequest("Contains invalid YubiKey device ID.".to_string()));
            }
            item
        } else if item_len == 44 {
            // Newly entered OTP (new key), verify against official servers
            crate::yubico::verify_yubico_otp(&env, &item).await?
        } else {
            return Err(AppError::BadRequest("Invalid YubiKey format, expected 12-char ID or 44-char OTP.".to_string()));
        };

        // Insert deduplicated items in order
        if !devices_array.contains(&device_id) {
            devices_array.push(device_id);
        }
    }

    if devices_array.len() > 5 {
        return Err(AppError::BadRequest("A maximum of 5 YubiKeys can be bound.".to_string()));
    }

    let data_json = serde_json::to_string(&devices_array).map_err(|_| AppError::Internal)?;

    let mut twofactor = TwoFactor::new(user_id.clone(), TwoFactorType::YubiKey, data_json);
    twofactor.last_used = 0;

    // [Security 2]: Use DB Batch transaction to group DELETE and INSERT operations
    let del_stmt = crate::d1_query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &user_id,
        TwoFactorType::YubiKey as i32
    ).map_err(|_| AppError::Database)?;

    let ins_stmt = crate::d1_query!(
        &db,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &twofactor.uuid,
        &twofactor.user_uuid,
        twofactor.atype,
        twofactor.enabled as i32,
        &twofactor.data,
        twofactor.last_used
    ).map_err(|_| AppError::Database)?;

    // Submit atomic operation at once to prevent 2FA loss due to disconnection
    db.batch(vec![del_stmt, ins_stmt]).await.map_err(|_| AppError::Database)?;

    generate_recovery_code_for_user(&db, &user_id).await?;

    // [Fix 2]: Return the twoFactorYubiKey object format expected by the Bitwarden frontend!
    // This ensures the frontend immediately renders the saved keys in the corresponding input fields upon receiving the response
    let mut response = serde_json::json!({
        "enabled": true,
        "key1": null, "key2": null, "key3": null, "key4": null, "key5": null,
        "object": "twoFactorYubiKey"
    });

    for (i, dev) in devices_array.iter().enumerate() {
        if i < 5 {
            let key_name = format!("key{}", i + 1);
            response[&key_name] = serde_json::Value::String(dev.clone());
        }
    }

    Ok(Json(response))
}

/// GET /api/two-factor/yubikey - Get current YubiKey status
#[worker::send]
pub async fn get_yubikey(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    // === [Security] Add rate limiting to prevent brute force ===
    if let Ok(rate_limiter) = env.rate_limiter("LOGIN_RATE_LIMITER") {
        let rate_limit_key = format!("2fa-check:{}", user_id);
        if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await {
            if !outcome.success {
                return Err(AppError::TooManyRequests("Too many validation attempts. Please try again later.".to_string()));
            }
        }
    }
    let db = db::get_db(&env)?;

    // Verify master password (Bitwarden official security specification)
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(&user, &data).await?;

    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[user_id.clone().into(), (TwoFactorType::YubiKey as i32).into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    let mut response = serde_json::json!({
        "enabled": false,
        "key1": null, "key2": null, "key3": null, "key4": null, "key5": null,
        "object": "twoFactorYubiKey"
    });

    if let Some(tf) = existing {
        response["enabled"] = serde_json::Value::Bool(true);
        let bound_devices: Vec<String> = serde_json::from_str(&tf.data).unwrap_or_default();
        for (i, dev) in bound_devices.iter().enumerate() {
            if i < 5 {
                let key_name = format!("key{}", i + 1);
                response[&key_name] = serde_json::Value::String(dev.clone());
            }
        }
    }

    Ok(Json(response))
}