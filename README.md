# Cipherbox PQC Native

**Post-Quantum Cryptography for Servers (ML-KEM, ML-DSA, ChaCha20, Argon2)**

`cipherbox-pqc-native` provides a complete, high-performance implementation of the NIST Post-Quantum Cryptography standards for native environments (servers, desktops, and CLI tools). It is the native counterpart to `cipherbox-pqc-wasm` and exposes the exact same cryptographic functions.

## Features

- **ML-KEM (Kyber-768)**: Post-Quantum Key Encapsulation (KEM).
- **ML-DSA (Dilithium-3)**: Post-Quantum Digital Signatures.
- **ChaCha20-Poly1305**: Symmetric encryption (AEAD).
- **Argon2**: Memory-hard passphrase-based key derivation (for encrypting private keys).
- **Key Wrapping**: Server-side helpers to wrap room keys for users.

## Installation

Build the binaries from source using Cargo:

    git clone https://github.com/yourusername/cipherbox-pqc-native.git
    cd cipherbox-pqc-native
    cargo build --release

The compiled binaries will be available in `target/release/`:
- `cipherbox-pqc-verify`
- `cipherbox-pqc-wrap`

## Usage as a Library

Add the crate to your project:

    cargo add cipherbox-pqc-native

Then use the exposed functions:

    use cipherbox_pqc_native::{MlKemKeyPair, MlDsaKeyPair, encrypt_private_key, decrypt_private_key};

    fn main() {
        // Generate keys
        let kem = MlKemKeyPair::new().unwrap();
        let dsa = MlDsaKeyPair::new();

        // Encrypt private keys
        let passphrase = "my-secret";
        let encrypted_dsa_sk = encrypt_private_key(&dsa.sk.encode(), passphrase);
        
        // Decrypt private keys
        let decrypted_dsa_sk = decrypt_private_key(&encrypted_dsa_sk, passphrase);
        assert!(!decrypted_dsa_sk.is_empty());
    }

## CLI Tools

### 1. Verify Signatures (ML-DSA)

    ./cipherbox-pqc-verify <public_key_b64> <message_b64> <signature_b64>

Outputs `true` if the signature is valid, `false` otherwise.

### 2. Wrap Encryption Keys (ML-KEM)

    ./cipherbox-pqc-wrap <user_kyber_pk_b64> <plaintext_room_key>

Outputs a JSON string containing the encrypted key:

    {"ct":"...","iv":"...","enc_aes":"..."}

## Security Considerations

- **Key Management**: Never expose the plaintext private keys on the server.
- **Memory Safety**: This project uses Rust's memory safety guarantees.
- **Argon2 Parameters**: The default Argon2 parameters are secure for most use cases, but you may want to tune them for your hardware.

## License

This project is licensed under the MIT License.
