//! auth.rs — Asymmetric Ed25519 License Validation & JWT Session Management
//!
//! Provides:
//!   1. Offline verification of Ed25519-signed customer license keys.
//!   2. Short-lived (72h) JSON Web Token (JWT) issuance upon successful activation.
//!   3. Axum middleware guard requiring `Authorization: Bearer <JWT>` for all `/api/scan*`, `/api/status`, and `/api/export*` routes.

use axum::{
    body::Body,
    extract::Request,
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// Master NexGen Forensics Ed25519 Public Key.
/// Embedded directly in the binary — zero internet connection required for validation.
pub const EMBEDDED_PUBLIC_KEY: [u8; 32] = [
    157, 193, 240, 196, 220, 46, 110, 113, 104, 222, 197, 248, 111, 248, 165, 207, 7, 145, 142, 159, 120, 202, 222, 106, 43, 113, 25, 37, 190, 209, 85, 81
];

/// Ephemeral HMAC secret generated at server boot for signing internal local session JWTs.
pub static JWT_SECRET: Lazy<[u8; 32]> = Lazy::new(|| {
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
});

#[derive(Debug, Serialize, Deserialize)]
pub struct LicensePayload {
    pub customer_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub plan: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,       // Customer ID or license signature digest
    pub plan: String,      // License tier
    pub exp: usize,        // Expiration timestamp (72 hours)
    pub iat: usize,        // Issued at
}

#[derive(Debug, Deserialize)]
pub struct ActivationRequest {
    pub license_key: String,
}

#[derive(Debug, Serialize)]
pub struct ActivationResponse {
    pub token: String,
    pub customer: String,
    pub plan: String,
    pub expires_at: i64,
}

/// Verify an incoming customer license string.
/// Format expected: `NEXGEN-<base64_payload>.<base64_sig>`
pub fn verify_license_key(license_str: &str) -> Result<LicensePayload, String> {
    let raw = license_str.trim();
    let body = raw
        .strip_prefix("NEXGEN-")
        .ok_or_else(|| "Invalid license format: Missing 'NEXGEN-' prefix".to_string())?;

    let parts: Vec<&str> = body.split('.').collect();
    if parts.len() != 2 {
        return Err("Malformed license key structure (expected payload.signature)".to_string());
    }

    let payload_bytes = B64
        .decode(parts[0])
        .map_err(|e| format!("Invalid base64 payload: {}", e))?;

    let sig_bytes = B64
        .decode(parts[1])
        .map_err(|e| format!("Invalid base64 signature: {}", e))?;

    if sig_bytes.len() != 64 {
        return Err("Invalid signature length (expected 64 bytes)".to_string());
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let verifying_key = VerifyingKey::from_bytes(&EMBEDDED_PUBLIC_KEY)
        .map_err(|e| format!("Corrupted embedded public key: {}", e))?;

    // Verify cryptographic signature against payload bytes
    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| "Cryptographic signature mismatch: License key is invalid or forged".to_string())?;

    // Deserialize and check expiration date
    let payload: LicensePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("Invalid JSON inside license payload: {}", e))?;

    let now = Utc::now().timestamp();
    if payload.expires_at < now {
        return Err(format!(
            "License expired on {}",
            chrono::DateTime::from_timestamp(payload.expires_at, 0).unwrap_or_default()
        ));
    }

    Ok(payload)
}

/// Mint a 72-hour session JWT for verified local client
pub fn mint_jwt(payload: &LicensePayload) -> Result<String, String> {
    let now = Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: payload.customer_id.clone(),
        plan: payload.plan.clone(),
        iat: now,
        exp: now + (72 * 3600), // 72 hours
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&*JWT_SECRET),
    )
    .map_err(|e| format!("JWT generation error: {}", e))
}

/// Validate a bearer JWT token
pub fn validate_jwt(token: &str) -> Result<Claims, String> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&*JWT_SECRET),
        &validation,
    )
    .map_err(|e| format!("Unauthorized token: {}", e))?;

    Ok(token_data.claims)
}

/// Axum Middleware: Intercepts protected `/api/*` endpoints and validates Bearer token
pub async fn auth_middleware(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_string();

    // Whitelisted routes: activation, token verification, health check, and SSE status/progress streams
    if path == "/api/activate"
        || path == "/api/health"
        || path.starts_with("/api/scan/status/")
        || path.starts_with("/api/scan/progress/")
        || path.starts_with("/dist")
        || !path.starts_with("/api")
    {
        return next.run(req).await;
    }

    // Extract Authorization header or ?token= query parameter (for browser EventSource)
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token_from_query = req.uri().query().and_then(|q| {
        q.split('&').find_map(|pair| {
            let mut parts = pair.split('=');
            if parts.next() == Some("token") {
                parts.next()
            } else {
                None
            }
        })
    });

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => Some(&header[7..]),
        _ => token_from_query,
    };

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing or malformed Authorization header. Please activate your license."
                })),
            )
                .into_response();
        }
    };

    match validate_jwt(token) {
        Ok(_claims) => next.run(req).await,
        Err(err) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Session token expired or invalid.",
                "details": err
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_license() {
        let key = "NEXGEN-eyJjdXN0b21lcl9pZCI6Ik5leEdlbi1Gb3VuZGVyIiwiaXNzdWVkX2F0IjoxNzkzMzM0OTg5LCJleHBpcmVzX2F0IjoxODI0ODcwOTg5LCJwbGFuIjoiRW50ZXJwcmlzZS1VbmxpbWl0ZWQifQ.1w_Q2HVJ16KZrt1tAncjbzRvvyaGPCLIBZMDLjgnowGaB_XUVRoJyhpo029Z322m4kCeRUa_YHDcr9Sw2u0nDA";
        let res = verify_license_key(key);
        assert!(res.is_ok(), "License verification failed: {:?}", res.err());
        let payload = res.unwrap();
        assert_eq!(payload.customer_id, "NexGen-Founder");
    }
}
