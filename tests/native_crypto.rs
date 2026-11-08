use base64::Engine as _;
use cipherbox_pqc_native::*;

#[test]
fn mlkem_roundtrip() {
    let kp = MlKemKeyPair::new().expect("keygen");
    let (ct, ss1) = kp.encapsulate().expect("encapsulate");
    let ss2 = kp.decapsulate(&ct).expect("decapsulate");
    assert_eq!(ss1, ss2, "shared secrets must match");
    assert_eq!(ss1.len(), 32, "ML-KEM-768 shared secret is 32 bytes");
}

#[test]
fn mldsa_sign_verify_roundtrip() {
    let kp = MlDsaKeyPair::new();
    let msg = b"post-quantum signature test";
    let sig = kp.sign(msg);
    assert!(kp.verify(msg, &sig), "valid signature must verify");
    assert!(
        !kp.verify(b"tampered message", &sig),
        "tampered message must fail"
    );
}

#[test]
fn mldsa_export_import_roundtrip() {
    let kp = MlDsaKeyPair::new();
    let (seed, vk) = kp.export_keys();
    assert_eq!(seed.len(), 32, "ML-DSA signing key seed must be 32 bytes");
    let kp2 = MlDsaKeyPair::import_keys(&seed, &vk).expect("import");
    let msg = b"roundtrip";
    let sig = kp2.sign(msg);
    assert!(kp2.verify(msg, &sig));
}

#[test]
fn decrypt_with_wrong_passphrase_fails() {
    let plaintext = b"secret key material";
    let encrypted = encrypt_private_key(plaintext, "correct-pass").expect("encrypt");
    let result = decrypt_private_key(&encrypted, "wrong-pass");
    assert!(
        result.is_err(),
        "wrong passphrase must produce an error, not empty Vec"
    );
}

#[test]
fn decrypt_with_correct_passphrase_works() {
    let plaintext = b"secret key material";
    let encrypted = encrypt_private_key(plaintext, "correct-pass").expect("encrypt");
    let decrypted = decrypt_private_key(&encrypted, "correct-pass").expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn wrap_room_key_roundtrip() {
    // 1. User generates a KEM keypair
    let user_kp = MlKemKeyPair::new().expect("keygen");
    let (_, ek_bytes) = user_kp.export_keys();

    // 2. Server wraps a room key using the user's public key
    let room_key = "room-key-abc-123";
    let ek_b64 = base64::engine::general_purpose::STANDARD.encode(&ek_bytes);
    let wrapped_json = wrap_room_key_for_user(&ek_b64, room_key).expect("wrap");

    // 3. Parse JSON and recover the room key on the user side
    let v: serde_json::Value = serde_json::from_str(&wrapped_json).expect("json");
    let ct_b64 = v["ct"].as_str().expect("ct");
    let iv_b64 = v["iv"].as_str().expect("iv");
    let enc_aes_b64 = v["enc_aes"].as_str().expect("enc_aes");

    let ct = base64::engine::general_purpose::STANDARD
        .decode(ct_b64)
        .unwrap();
    let iv = base64::engine::general_purpose::STANDARD
        .decode(iv_b64)
        .unwrap();
    let enc_aes = base64::engine::general_purpose::STANDARD
        .decode(enc_aes_b64)
        .unwrap();

    let ss = user_kp.decapsulate(&ct).expect("decapsulate");
    use chacha20poly1305::aead::{Aead, KeyInit};
    let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&ss).unwrap();
    let nonce = chacha20poly1305::Nonce::from_slice(&iv);
    let recovered = cipher
        .decrypt(nonce, enc_aes.as_ref())
        .expect("decrypt room key");
    assert_eq!(std::str::from_utf8(&recovered).unwrap(), room_key);
}
