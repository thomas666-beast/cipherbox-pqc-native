use kyberlib::{KemCore, MlKem768};
use ml_dsa::{MlDsa65, KeyGen, SigningKey, VerifyingKey, Signature};
use ml_dsa::signature::{Signer, Verifier};
use rand::rngs::OsRng;
use rand::RngCore;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose};

// ==========================================
// ML-KEM (Kyber) - Key Exchange
// ==========================================

pub struct MlKemKeyPair {
    pub dk_bytes: Vec<u8>,
    pub ek_bytes: Vec<u8>,
}

impl MlKemKeyPair {
    pub fn new() -> Result<Self, String> {
        let (dk, ek) = MlKem768::generate(&mut OsRng)
            .map_err(|e| format!("KeyGen error: {:?}", e))?;
        
        Ok(MlKemKeyPair {
            dk_bytes: dk.as_bytes().to_vec(),
            ek_bytes: ek.as_bytes().to_vec(),
        })
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (ct, ss) = kyberlib::encapsulate(&self.ek_bytes, &mut OsRng)
            .map_err(|e| format!("Encapsulation error: {:?}", e))?;
        Ok((ct.to_vec(), ss.to_vec()))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let ss = kyberlib::decapsulate(ciphertext, &self.dk_bytes)
            .map_err(|e| format!("Decapsulation error: {:?}", e))?;
        Ok(ss.to_vec())
    }
}

// ==========================================
// ML-DSA (Dilithium) - Signatures
// ==========================================

pub struct MlDsaKeyPair {
    pub sk: SigningKey<MlDsa65>,
    pub vk: VerifyingKey<MlDsa65>,
}

impl MlDsaKeyPair {
    pub fn new() -> Self {
        let keypair = MlDsa65::key_gen(&mut OsRng);
        let sk = keypair.signing_key().clone();
        let vk = keypair.verifying_key().clone();
        MlDsaKeyPair { sk, vk }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.sk.sign(message);
        sig.encode().to_vec()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let sig_arr: &ml_dsa::EncodedSignature<MlDsa65> = match signature.try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let sig = match Signature::<MlDsa65>::decode(sig_arr) {
            Some(s) => s,
            None => return false,
        };
        self.vk.verify(message, &sig).is_ok()
    }
}

// ==========================================
// PASSPHRASE ENCRYPTION (Argon2 + ChaCha20)
// ==========================================

pub fn encrypt_private_key(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);

    let argon2 = Argon2::default();
    let mut key_bytes = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut key_bytes)
        .expect("Argon2 hashing failed");
    
    let key = Key::from_slice(&key_bytes);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("Encryption failed");

    let mut result = salt_bytes.to_vec();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

pub fn decrypt_private_key(encrypted: &[u8], passphrase: &str) -> Vec<u8> {
    if encrypted.len() < 28 {
        return Vec::new();
    }

    let salt_bytes = &encrypted[0..16];
    let nonce_bytes = &encrypted[16..28];
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = &encrypted[28..];

    let argon2 = Argon2::default();
    let mut key_bytes = [0u8; 32];
    if argon2.hash_password_into(passphrase.as_bytes(), salt_bytes, &mut key_bytes).is_err() {
        return Vec::new();
    }
    
    let key = Key::from_slice(&key_bytes);

    let cipher = ChaCha20Poly1305::new(key);
    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => Vec::new(),
    }
}

// ==========================================
// SERVER-SIDE HELPERS (Key Wrapping)
// ==========================================

/// Wraps a plaintext room key for a given user's Kyber public key.
/// Returns a JSON string: {"ct":"...","iv":"...","enc_aes":"..."}
pub fn wrap_room_key_for_user(
    user_pk_b64: &str,
    room_key_plaintext: &str,
) -> Result<String, String> {
    let pk_bytes = general_purpose::STANDARD
        .decode(user_pk_b64)
        .map_err(|e| format!("invalid pk b64: {}", e))?;

    let (ct, ss) = kyberlib::encapsulate(&pk_bytes, &mut OsRng)
        .map_err(|e| format!("kyber encaps failed: {:?}", e))?;

    let aes_key = Key::from_slice(&ss);
    let cipher  = ChaCha20Poly1305::new(aes_key);

    let mut iv_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    let enc_aes = cipher
        .encrypt(nonce, room_key_plaintext.as_bytes())
        .map_err(|e| format!("encrypt failed: {:?}", e))?;

    Ok(format!(
        r#"{{"ct":"{}","iv":"{}","enc_aes":"{}"}}"#,
        general_purpose::STANDARD.encode(&ct),
        general_purpose::STANDARD.encode(&iv_bytes),
        general_purpose::STANDARD.encode(&enc_aes)
    ))
}
