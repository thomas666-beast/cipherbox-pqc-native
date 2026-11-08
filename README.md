================================================================================
                        CIPHERBOX PQC NATIVE
================================================================================

     Post-Quantum Cryptography for Servers
     ML-KEM  |  ML-DSA  |  ChaCha20-Poly1305  |  Argon2

     Version 0.2.0  |  MIT License

cipherbox-pqc-native is a batteries-included toolkit for server-side
post-quantum key wrapping, private-key encryption, and signature
verification. Built on the RustCrypto ml-kem and ml-dsa crates, it ships
as both a library and two CLI binaries.

--------------------------------------------------------------------------------
                              TABLE OF CONTENTS
--------------------------------------------------------------------------------

  1.  Why This Crate
  2.  Features
  3.  Installation
  4.  Library Usage
  5.  CLI Tools
  6.  API Overview
  7.  On-Disk Format
  8.  Security Model
  9.  Testing
 10.  Dependency Audit Notes
 11.  License
 12.  Contact


================================================================================
  1.  WHY THIS CRATE
================================================================================

You can import ml-kem and ml-dsa directly. This crate exists because the
following still have to be assembled, tested, and kept consistent:

  *  A stable on-disk format for encrypting private keys with a passphrase
     (Argon2 -> ChaCha20-Poly1305, with salt and nonce layout defined here).

  *  A one-call "wrap a room key for a user" primitive that encapsulates
     to the user's ML-KEM public key and encrypts a payload, returning
     JSON that front-end and back-end can both consume.

  *  A CLI for operations staff who do not write Rust: signature
     verification and room-key wrapping as standalone binaries.

  *  Error semantics that distinguish "malformed key" from "wrong
     passphrase" from "internal failure," so callers can act on them.

  *  Canonical FIPS 203 / FIPS 204 seed-based key serialization
     (not the deprecated expanded form).

If none of that is what you need, use the underlying crates directly --
the wrapper layer is not the value proposition.


================================================================================
  2.  FEATURES
================================================================================

  *  ML-KEM-768 (FIPS 203)         --  key encapsulation
  *  ML-DSA-65  (FIPS 204)         --  digital signatures
  *  ChaCha20-Poly1305             --  symmetric AEAD
  *  Argon2 (default parameters)   --  passphrase-based KDF
  *  Seed-based key serialization  --  canonical FIPS forms
  *  Two CLI binaries              --  verify + wrap
  *  Structured error type         --  actionable failure modes

Key serialization details
-------------------------

  ML-KEM decapsulation key  :  64-byte seed (d || z)
  ML-DSA signing key        :  32-byte seed
  Both are ZeroizeOnDrop in the underlying crates.


================================================================================
  3.  INSTALLATION
================================================================================

As a library
------------

  Add to Cargo.toml:

      [dependencies]
      cipherbox-pqc-native = "0.2"

As CLI binaries
---------------

      git clone https://github.com/thomas666-beast/cipherbox-pqc-native.git
      cd cipherbox-pqc-native
      cargo build --release

  Binaries produced at:

      target/release/cipherbox-pqc-verify
      target/release/cipherbox-pqc-wrap


================================================================================
  4.  LIBRARY USAGE
================================================================================

Generate keys and encrypt a private key
---------------------------------------

      use cipherbox_pqc_native::{
          MlKemKeyPair, MlDsaKeyPair, encrypt_private_key, decrypt_private_key,
      };

      fn main() -> Result<(), Box<dyn std::error::Error>> {
          let kem = MlKemKeyPair::new()?;
          let dsa = MlDsaKeyPair::new();

          // Export canonical seeds and public keys.
          //   kem:  (dk_seed 64 bytes, ek 1184 bytes)
          //   dsa:  (sk_seed 32 bytes, vk 1952 bytes)
          let (kem_dk_seed, kem_ek) = kem.export_keys();
          let (dsa_sk_seed, dsa_vk) = dsa.export_keys();

          // Encrypt the DSA signing-key seed with a passphrase.
          let encrypted = encrypt_private_key(&dsa_sk_seed, "my-secret")?;
          let recovered = decrypt_private_key(&encrypted, "my-secret")?;
          assert_eq!(recovered, dsa_sk_seed);

          // Round-trip a KEM keypair.
          let kem_restored = MlKemKeyPair::import_keys(&kem_dk_seed, &kem_ek)?;
          let (ct, ss_sender) = kem_restored.encapsulate()?;
          let ss_recipient = kem.decapsulate(&ct)?;
          assert_eq!(ss_sender, ss_recipient);

          Ok(())
      }

Sign and verify with ML-DSA
---------------------------

      let dsa = cipherbox_pqc_native::MlDsaKeyPair::new();
      let message = b"hello, post-quantum world";
      let signature = dsa.sign(message);

      assert!(dsa.verify(message, &signature));
      assert!(!dsa.verify(b"tampered", &signature));

Wrap a room key for a user (server-side)
----------------------------------------

      let user_kem = cipherbox_pqc_native::MlKemKeyPair::new()?;
      let (_, user_ek) = user_kem.export_keys();
      let user_ek_b64 =
          base64::engine::general_purpose::STANDARD.encode(&user_ek);

      let wrapped_json = cipherbox_pqc_native::wrap_room_key_for_user(
          &user_ek_b64,
          "room-key-abc-123",
      )?;

      // Result: {"ct":"...","iv":"...","enc_aes":"..."}


================================================================================
  5.  CLI TOOLS
================================================================================

cipherbox-pqc-verify
--------------------

  Verify an ML-DSA-65 signature offline.

      cipherbox-pqc-verify <public_key_b64> <message_b64> <signature_b64>

  Behaviour:

      Valid signature         ->  prints "true",  exits 0
      Invalid signature       ->  prints "false", exits 1
      Malformed input         ->  prints "false", exits 1

  Size constraints:

      Public key   :  1952 bytes (ML-DSA-65)
      Signature    :  3309 bytes (ML-DSA-65)

cipherbox-pqc-wrap
------------------

  Wrap a plaintext room key to a user's ML-KEM-768 public key.

      cipherbox-pqc-wrap <user_kyber_pk_b64> <plaintext_room_key>

  Output format (single line, JSON):

      {"ct":"...","iv":"...","enc_aes":"..."}

  Field meaning:

      ct         ML-KEM-768 ciphertext            (1088 bytes, base64)
      iv         ChaCha20-Poly1305 nonce          (12 bytes,   base64)
      enc_aes    encrypted room key + AEAD tag    (base64)

  Recipient workflow:

      1.  Decapsulate ct with the ML-KEM decapsulation key.
      2.  Obtain the 32-byte shared secret.
      3.  Decrypt enc_aes with ChaCha20-Poly1305, using iv as the nonce.


================================================================================
  6.  API OVERVIEW
================================================================================

MlKemKeyPair
------------

      new()
          Result<Self, CipherboxError>
          Generate a fresh ML-KEM-768 keypair.

      encapsulate()
          Result<(Vec<u8>, Vec<u8>), CipherboxError>
          Produce (ciphertext, shared_secret).

      decapsulate(ciphertext: &[u8])
          Result<Vec<u8>, CipherboxError>
          Recover the shared secret.

      export_keys()
          (Vec<u8>, Vec<u8>)
          Return (dk_seed_64, ek_1184).

      import_keys(dk_seed: &[u8], ek: &[u8])
          Result<Self, CipherboxError>
          Rebuild from exported bytes.

MlDsaKeyPair
------------

      new()
          Self
          Generate a fresh ML-DSA-65 keypair.

      sign(message: &[u8])
          Vec<u8>
          Produce a 3309-byte signature.

      verify(message: &[u8], signature: &[u8])
          bool
          Returns false on malformed input; never panics.

      export_keys()
          (Vec<u8>, Vec<u8>)
          Return (sk_seed_32, vk_1952).

      import_keys(seed: &[u8], vk: &[u8])
          Result<Self, CipherboxError>
          Rebuild from exported bytes.

Free functions
--------------

      encrypt_private_key(plaintext: &[u8], passphrase: &str)
          Result<Vec<u8>, CipherboxError>

      decrypt_private_key(encrypted: &[u8], passphrase: &str)
          Result<Vec<u8>, CipherboxError>

      wrap_room_key_for_user(user_pk_b64: &str, room_key: &str)
          Result<String, CipherboxError>

CipherboxError
--------------

      pub enum CipherboxError {
          KeyGen(String),
          Encapsulation(String),
          Decapsulation(String),
          InvalidKeyLength { expected: usize, got: usize },
          Crypto(String),
      }

  InvalidKeyLength is returned before any cryptographic operation runs,
  so callers can distinguish structural problems from key-material
  problems.


================================================================================
  7.  ON-DISK FORMAT
================================================================================

encrypt_private_key output layout
---------------------------------

      +--------------+---------------+------------------------------+
      |  salt (16 B) | nonce (12 B)  | ChaCha20-Poly1305 ct + tag   |
      +--------------+---------------+------------------------------+

  Length:  28 + n + 16 bytes, where n is the plaintext length.

  KDF:     Argon2id, default parameters (m=19456 KiB, t=2, p=1),
           produces a 32-byte key.

  AEAD:    ChaCha20-Poly1305, 12-byte nonce.

  Failure: decrypt_private_key errors on:
             - length < 28 bytes
             - Argon2 failure
             - AEAD tag mismatch (wrong passphrase or tampered data)

wrap_room_key_for_user JSON fields
----------------------------------

      ct       base64(ML-KEM-768 ciphertext, 1088 bytes)
      iv       base64(ChaCha20-Poly1305 nonce, 12 bytes)
      enc_aes  base64(room_key_plaintext + 16-byte tag)

  The 32-byte ML-KEM shared secret is used directly as the ChaCha20-
  Poly1305 key. It is never persisted.


================================================================================
  8.  SECURITY MODEL
================================================================================

Dependencies
------------

  ML-KEM is provided by RustCrypto ml-kem (0.3.x, security-assessed by
  Cure53 for Bitwarden). ML-DSA is provided by RustCrypto ml-dsa (0.1.x,
  includes fixes for CVE-2026-24850 and RUSTSEC-2025-0144).

  Neither has a formal third-party audit. This crate provides composition
  and delivery, not cryptographic primitives.

Key serialization
-----------------

  ML-KEM decapsulation keys export as the 64-byte seed (d || z).
  ML-DSA signing keys export as the 32-byte seed.
  Both are the canonical FIPS 203 / FIPS 204 forms and are ZeroizeOnDrop
  in the underlying crates.

Key wrapping
------------

  wrap_room_key_for_user encapsulates to the user's public key, derives a
  ChaCha20-Poly1305 key from the shared secret, and returns JSON with
  base64-encoded ciphertext, IV, and encrypted room key. The shared
  secret exists only as a 32-byte stack value during the call.

Argon2 parameters
-----------------

  Argon2::default() is used:
      Argon2id, m=19456 KiB, t=2, p=1

  Suitable for interactive passphrase-based decryption on server
  hardware. Changing these parameters is a breaking format change --
  the current layout has no version byte.

What this crate does NOT protect against
----------------------------------------

  *  Side-channel attacks in the underlying crates beyond their
     published guarantees. WebAssembly or JIT environments may
     introduce timing variation not present in native builds. The
     native crate is intended for server-side use.

  *  Compromised passphrases. The passphrase is the only barrier
     between an attacker with the encrypted blob and the plaintext
     key material.

  *  Memory inspection of a running process. Keys are zeroized on
     drop, but an attacker with process memory read access can
     observe them while in use.


================================================================================
  9.  TESTING
================================================================================

Test suite
----------

      mlkem_roundtrip
          Generate, encapsulate, decapsulate, compare shared secrets.

      mlkem_export_import_roundtrip
          Export (dk_seed, ek), import, encapsulate, decapsulate
          against the original keypair.

      mldsa_sign_verify_roundtrip
          Sign, verify, tamper, verify fails.

      mldsa_export_import_roundtrip
          Export (sk_seed, vk), import, sign, verify.

      decrypt_with_wrong_passphrase_fails
          Encrypt with one passphrase, decrypt with another,
          expect an error (not an empty Vec).

      decrypt_with_correct_passphrase_works
          Round-trip a plaintext.

      wrap_room_key_roundtrip
          Wrap a room key to a user's public key, unwrap on the
          user side, compare plaintext.

Running tests
-------------

      cargo test --all-targets

Full CI gate
------------

      cargo fmt --all -- --check
      cargo clippy --all-targets -- -D warnings
      cargo test --all-targets

  A Makefile target `make ci` runs all three in order.


================================================================================
 10.  DEPENDENCY AUDIT NOTES
================================================================================

ml-kem 0.3.x
------------

  *  Security assessment by Cure53 (commissioned by Bitwarden) confirms
     constant-time Decaps and Zeroize on key material.

  *  Known low-risk issues:
        BWN-13-001  DecapsulationKey.d not zeroized.
        BWN-13-002  Incomplete input validation.
     Both are documented and acceptable for server-side use.

  *  ACVP coverage gap: the crate does not expose EncapsKeyCheck /
     DecapsKeyCheck as standalone functions, so 60 ACVP vectors are not
     exercisable through the public API. This is an API surface issue,
     not a correctness issue.

ml-dsa 0.1.x
------------

  *  Fixes CVE-2026-24850 (signature verification bypass via duplicate
     hint indices) and RUSTSEC-2025-0144 (timing side-channel in the
     signing Decompose algorithm).

  *  Versions before 0.1.0-rc.4 are vulnerable to CVE-2026-24850.

  *  This crate pins ml-dsa = "=0.1.2" to avoid silent resolution drift.

Formal audit status
-------------------

  Neither dependency has a formal third-party audit. If your deployment
  requires one, use libcrux-ml-kem's verification path or wait for an
  audited release of the RustCrypto crates.


================================================================================
 11.  LICENSE
================================================================================

  MIT. See LICENSE file for the full text.


================================================================================
 12.  CONTACT
================================================================================

  Repository   https://github.com/thomas666-beast/cipherbox-pqc-native
  Author       Thomas <selfworker112@mailfence.com>

================================================================================
