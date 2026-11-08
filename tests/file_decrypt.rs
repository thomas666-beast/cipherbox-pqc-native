//! End-to-end tests that invoke the CLI binaries.

use base64::{engine::general_purpose, Engine as _};
use cipherbox_pqc_core::MlKemKeyPair;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn tmpdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cipherbox-cli-test-{}-{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fresh_keypair_b64() -> (String, String) {
    let kp = MlKemKeyPair::new().unwrap();
    let (dk_seed, ek) = kp.export_keys();
    (
        general_purpose::STANDARD.encode(&ek),
        general_purpose::STANDARD.encode(&dk_seed),
    )
}

#[test]
fn keygen_stdout_format() {
    let out = Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-keygen"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("EK="));
    assert!(text.contains("\nDK_SEED="));
    let ek_len = text.lines().next().unwrap()[3..].len();
    let dk_len = text.lines().nth(1).unwrap()[8..].len();
    // 1184 bytes -> 1580 base64 chars; 64 bytes -> 88 base64 chars
    assert_eq!(ek_len, 1580);
    assert_eq!(dk_len, 88);
}

#[test]
fn keygen_out_dir_writes_files() {
    let dir = tmpdir("keygen-out");
    let status = Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-keygen"))
        .arg("--out")
        .arg(&dir)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(dir.join("ek.b64").exists());
    assert!(dir.join("dk_seed.b64").exists());
    let ek = fs::read_to_string(dir.join("ek.b64")).unwrap();
    let dk = fs::read_to_string(dir.join("dk_seed.b64")).unwrap();
    assert_eq!(ek.len(), 1580);
    assert_eq!(dk.len(), 88);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn full_roundtrip_short() {
    let (ek_b64, dk_b64) = fresh_keypair_b64();
    let dir = tmpdir("rt-short");
    let input = dir.join("in.bin");
    let enc = dir.join("enc.bin");
    let dec = dir.join("dec.bin");
    let payload = b"hello from the CLI roundtrip test";
    fs::write(&input, payload).unwrap();

    assert!(Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-encrypt"))
        .arg(&ek_b64)
        .arg(&input)
        .arg(&enc)
        .status()
        .unwrap()
        .success());

    assert!(Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-decrypt"))
        .arg(&dk_b64)
        .arg(&enc)
        .arg(&dec)
        .status()
        .unwrap()
        .success());

    assert_eq!(fs::read(&dec).unwrap(), payload);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn full_roundtrip_empty() {
    let (ek_b64, dk_b64) = fresh_keypair_b64();
    let dir = tmpdir("rt-empty");
    let input = dir.join("in.bin");
    let enc = dir.join("enc.bin");
    let dec = dir.join("dec.bin");
    fs::write(&input, b"").unwrap();

    assert!(Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-encrypt"))
        .arg(&ek_b64)
        .arg(&input)
        .arg(&enc)
        .status()
        .unwrap()
        .success());

    assert!(Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-decrypt"))
        .arg(&dk_b64)
        .arg(&enc)
        .arg(&dec)
        .status()
        .unwrap()
        .success());

    assert_eq!(fs::read(&dec).unwrap(), b"");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn full_roundtrip_large_with_small_chunks() {
    let (ek_b64, dk_b64) = fresh_keypair_b64();
    let dir = tmpdir("rt-large");
    let input = dir.join("in.bin");
    let enc = dir.join("enc.bin");
    let dec = dir.join("dec.bin");
    let payload: Vec<u8> = (0..100_000usize).map(|i| (i % 256) as u8).collect();
    fs::write(&input, &payload).unwrap();

    assert!(Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-encrypt"))
        .arg(&ek_b64)
        .arg(&input)
        .arg(&enc)
        .arg("64")
        .status()
        .unwrap()
        .success());

    assert!(Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-decrypt"))
        .arg(&dk_b64)
        .arg(&enc)
        .arg(&dec)
        .status()
        .unwrap()
        .success());

    assert_eq!(fs::read(&dec).unwrap(), payload);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn wrong_key_fails() {
    let (ek_b64, _) = fresh_keypair_b64();
    let (_, other_dk) = fresh_keypair_b64();
    let dir = tmpdir("wrong-key");
    let input = dir.join("in.bin");
    let enc = dir.join("enc.bin");
    let dec = dir.join("dec.bin");
    fs::write(&input, b"payload").unwrap();

    assert!(Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-encrypt"))
        .arg(&ek_b64)
        .arg(&input)
        .arg(&enc)
        .status()
        .unwrap()
        .success());

    let status = Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-decrypt"))
        .arg(&other_dk)
        .arg(&enc)
        .arg(&dec)
        .status()
        .unwrap();
    assert!(!status.success());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn truncated_ciphertext_fails() {
    let (ek_b64, dk_b64) = fresh_keypair_b64();
    let dir = tmpdir("truncated");
    let input = dir.join("in.bin");
    let enc = dir.join("enc.bin");
    let dec = dir.join("dec.bin");
    fs::write(&input, b"payload that will be truncated").unwrap();

    assert!(Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-encrypt"))
        .arg(&ek_b64)
        .arg(&input)
        .arg(&enc)
        .status()
        .unwrap()
        .success());

    // Drop the last 4 bytes.
    let mut data = fs::read(&enc).unwrap();
    data.truncate(data.len() - 4);
    fs::write(&enc, &data).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-decrypt"))
        .arg(&dk_b64)
        .arg(&enc)
        .arg(&dec)
        .status()
        .unwrap();
    assert!(!status.success());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn invalid_chunk_size_rejected() {
    let (ek_b64, _) = fresh_keypair_b64();
    let dir = tmpdir("bad-chunk");
    let input = dir.join("in.bin");
    let enc = dir.join("enc.bin");
    fs::write(&input, b"x").unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-file-encrypt"))
        .arg(&ek_b64)
        .arg(&input)
        .arg(&enc)
        .arg("1") // below CHUNK_SIZE_MIN (64)
        .status()
        .unwrap();
    assert!(!status.success());
    let _ = fs::remove_dir_all(&dir);
}
