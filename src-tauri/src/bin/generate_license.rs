//! generate_license.rs — Standalone Offline Ed25519 License Key Generator
//!
//! Generates a master Ed25519 keypair:
//!   - `nexgen_private.key` (Keep secret at NexGen Forensics HQ)
//!   - `nexgen_public.key`  (Public key embedded into the server binary)
//!
//! When given customer information (e.g. customer name/email, expiration timestamp),
//! this tool signs a structured license payload and outputs a cryptographically
//! unforgeable license string `NEXGEN-<base64_payload>.<base64_sig>`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct LicensePayload {
    pub customer_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub plan: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let private_key_file = "nexgen_private.key";
    let public_key_file = "nexgen_public.key";

    // 1. Generate or load master keypair
    let signing_key: SigningKey = if Path::new(private_key_file).exists() {
        println!("[*] Loading existing master signing key from {}", private_key_file);
        let bytes = fs::read(private_key_file)?;
        if bytes.len() != 32 {
            panic!("Invalid private key length: expected 32 bytes");
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&bytes);
        SigningKey::from_bytes(&key_arr)
    } else {
        println!("[+] Generating brand new master Ed25519 keypair...");
        let mut csprng = OsRng;
        let key = SigningKey::generate(&mut csprng);
        fs::write(private_key_file, key.to_bytes())?;

        let verifying_key: VerifyingKey = key.verifying_key();
        fs::write(public_key_file, verifying_key.to_bytes())?;

        println!("[+] Master keys generated successfully!");
        println!("    Private Key: {} (KEEP THIS SECRET!)", private_key_file);
        println!("    Public Key:  {} (Embed this in nexgen-server)", public_key_file);
        println!("    Public Key (Hex): {}", hex::encode(verifying_key.to_bytes()));
        key
    };

    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let pub_bytes = verifying_key.to_bytes();
    println!("\n=======================================================");
    println!("NEXGEN EMBEDDED PUBLIC KEY CONSTANT (FOR auth.rs):");
    println!("pub const EMBEDDED_PUBLIC_KEY: [u8; 32] = {:?};", pub_bytes);
    println!("=======================================================\n");

    // 2. Issue a customer license
    let customer_id = args.get(1).cloned().unwrap_or_else(|| "CLIENT-FORENSICS-INC".to_string());
    let days_valid: i64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(365);

    let now = chrono::Utc::now().timestamp();
    let expires = now + (days_valid * 86400);

    let payload = LicensePayload {
        customer_id: customer_id.clone(),
        issued_at: now,
        expires_at: expires,
        plan: "Enterprise-Unlimited".to_string(),
    };

    let payload_json = serde_json::to_string(&payload)?;
    let payload_b64 = B64.encode(payload_json.as_bytes());

    // Sign the raw JSON payload bytes with Ed25519
    let signature = signing_key.sign(payload_json.as_bytes());
    let sig_b64 = B64.encode(signature.to_bytes());

    let license_key = format!("NEXGEN-{}.{}", payload_b64, sig_b64);

    println!("[+] Generated Cryptographic License Key for: {}", customer_id);
    println!("    Valid for:  {} days (Expires: {})", days_valid, chrono::DateTime::from_timestamp(expires, 0).unwrap_or_default());
    println!("\n>>> LICENSE KEY TO SEND TO CUSTOMER <<<");
    println!("{}\n", license_key);

    Ok(())
}

mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}
