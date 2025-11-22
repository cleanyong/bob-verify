use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct AliceMessage {
    message: String,
    signature: String,
    // public_key 现在是可选的: 没有的话就完全忽略
    public_key: Option<String>,
}

fn main() {
    // 用法: cargo run -- alice.json
    let json_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: bob-verify <alice.json>");
        std::process::exit(1);
    });

    if let Err(e) = verify_from_files(&json_path, "alice_public_key_for_verify") {
        eprintln!("Verification failed: {e}");
        std::process::exit(1);
    } else {
        println!("Verification succeeded.");
    }
}

fn verify_from_files<P: AsRef<Path>, Q: AsRef<Path>>(
    json_file: P,
    stored_pubkey_file: Q,
) -> Result<(), String> {
    let json_content =
        fs::read_to_string(json_file).map_err(|e| format!("read JSON file error: {e}"))?;
    let alice_msg: AliceMessage =
        serde_json::from_str(&json_content).map_err(|e| format!("parse JSON error: {e}"))?;

    let stored_pubkey_b64 = fs::read_to_string(stored_pubkey_file)
        .map_err(|e| format!("read stored public key file error: {e}"))?
        .trim()
        .to_string();

    let stored_pubkey_bytes = STANDARD
        .decode(stored_pubkey_b64)
        .map_err(|e| format!("base64 decode stored public key error: {e}"))?;

    let verifying_key = VerifyingKey::from_bytes(
        stored_pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid stored public key length".to_string())?,
    )
    .map_err(|e| format!("create verifying key error: {e}"))?;

    // 如果 JSON 里有 public_key，就顺便校验是否和本地的一致;
    // 如果 JSON 里没有 public_key，就忽略它，只用本地公钥验签。
    if let Some(json_pubkey_b64) = alice_msg.public_key {
        let json_pubkey_bytes = STANDARD
            .decode(json_pubkey_b64)
            .map_err(|e| format!("base64 decode JSON public key error: {e}"))?;
        if json_pubkey_bytes != stored_pubkey_bytes {
            return Err("public key in JSON does not match stored public key".to_string());
        }
    }

    let signature_bytes = STANDARD
        .decode(alice_msg.signature)
        .map_err(|e| format!("base64 decode signature error: {e}"))?;
    let signature = Signature::from_bytes(
        &signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid signature length".to_string())?,
    );

    verifying_key
        .verify(alice_msg.message.as_bytes(), &signature)
        .map_err(|e| format!("signature verification error: {e}"))?;

    Ok(())
}
