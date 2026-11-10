use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn bin(name: &str) -> Command {
    Command::new(match name {
        "keygen" => env!("CARGO_BIN_EXE_cipherbox-pqc-keygen"),
        "enc" => env!("CARGO_BIN_EXE_cipherbox-pqc-file-encrypt"),
        "dec" => env!("CARGO_BIN_EXE_cipherbox-pqc-file-decrypt"),
        "wrap" => env!("CARGO_BIN_EXE_cipherbox-pqc-wrap"),
        "unwrap" => env!("CARGO_BIN_EXE_cipherbox-pqc-unwrap"),
        _ => unreachable!(),
    })
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cipherbox-test-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn ok(o: &Output) {
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

fn leftovers(d: &PathBuf) -> usize {
    fs::read_dir(d)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .count()
}

fn keygen(dir: &PathBuf, level: &str) {
    ok(&bin("keygen")
        .arg("--out")
        .arg(dir)
        .args(["--level", level])
        .output()
        .unwrap());
}

#[test]
fn encrypt_decrypt_and_tamper_both_levels() {
    for level in ["768", "1024"] {
        let d = scratch(&format!("rt{level}"));
        let keys = d.join("keys");
        keygen(&keys, level);
        let ek = fs::read_to_string(keys.join("ek.b64")).unwrap();

        let plain: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(d.join("in.bin"), &plain).unwrap();

        ok(&bin("enc")
            .args([ek.as_str(), d.join("in.bin").to_str().unwrap(), d.join("c.cbox").to_str().unwrap()])
            .output()
            .unwrap());

        let dk_arg = format!("file:{}", keys.join("dk_seed.b64").display());
        ok(&bin("dec")
            .args([dk_arg.as_str(), d.join("c.cbox").to_str().unwrap(), d.join("out.bin").to_str().unwrap()])
            .output()
            .unwrap());
        assert_eq!(fs::read(d.join("out.bin")).unwrap(), plain, "level {level}");

        // Truncated ciphertext must fail and leave no output or temp file.
        let mut c = fs::read(d.join("c.cbox")).unwrap();
        c.truncate(c.len() - 1000);
        fs::write(d.join("bad.cbox"), &c).unwrap();
        let o = bin("dec")
            .args([dk_arg.as_str(), d.join("bad.cbox").to_str().unwrap(), d.join("bad.out").to_str().unwrap()])
            .output()
            .unwrap();
        assert!(!o.status.success());
        assert!(!d.join("bad.out").exists());
        assert_eq!(leftovers(&d), 0);
        let _ = fs::remove_dir_all(&d);
    }
}

#[test]
fn passphrase_protected_seed() {
    let d = scratch("pw");
    let keys = d.join("keys");
    ok(&bin("keygen")
        .arg("--out")
        .arg(&keys)
        .args(["--level", "1024", "--passphrase", "env:CBX_PW"])
        .env("CBX_PW", "correct horse")
        .output()
        .unwrap());
    assert!(keys.join("dk_seed.enc.b64").exists());
    assert!(!keys.join("dk_seed.b64").exists());

    let ek = fs::read_to_string(keys.join("ek.b64")).unwrap();
    fs::write(d.join("in.txt"), b"hello").unwrap();
    ok(&bin("enc")
        .args([ek.as_str(), d.join("in.txt").to_str().unwrap(), d.join("c").to_str().unwrap()])
        .output()
        .unwrap());

    let dk_arg = format!("file:{}", keys.join("dk_seed.enc.b64").display());
    let run = |pw: &str, out: &str| {
        bin("dec")
            .args([dk_arg.as_str(), d.join("c").to_str().unwrap(), d.join(out).to_str().unwrap()])
            .args(["--passphrase", "env:CBX_PW"])
            .env("CBX_PW", pw)
            .output()
            .unwrap()
    };
    assert!(!run("wrong", "o1").status.success());
    ok(&run("correct horse", "o2"));
    assert_eq!(fs::read(d.join("o2")).unwrap(), b"hello");
    let _ = fs::remove_dir_all(&d);
}

fn json_field(json: &str, key: &str) -> String {
    let pat = format!("\"{key}\":\"");
    let s = json.find(&pat).unwrap() + pat.len();
    json[s..s + json[s..].find('"').unwrap()].to_string()
}

#[test]
fn wrap_then_unwrap_both_levels() {
    for level in ["768", "1024"] {
        let d = scratch(&format!("wr{level}"));
        let keys = d.join("keys");
        keygen(&keys, level);
        let ek = fs::read_to_string(keys.join("ek.b64")).unwrap();

        let out = bin("wrap")
            .args([ek.as_str(), "env:CBX_ROOM"])
            .env("CBX_ROOM", "room-secret-key")
            .output()
            .unwrap();
        ok(&out);
        let json = String::from_utf8(out.stdout).unwrap();
        let dk_arg = format!("file:{}", keys.join("dk_seed.b64").display());
        let o = bin("unwrap")
            .args([
                dk_arg.as_str(),
                "2",
                &json_field(&json, "ct"),
                &json_field(&json, "iv"),
                &json_field(&json, "enc_aes"),
            ])
            .output()
            .unwrap();
        ok(&o);
        assert_eq!(String::from_utf8(o.stdout).unwrap().trim(), "room-secret-key");
        let _ = fs::remove_dir_all(&d);
    }
}

#[test]
fn keygen_never_overwrites_and_rejects_bad_level() {
    let d = scratch("ow");
    let keys = d.join("keys");
    keygen(&keys, "768");
    let again = bin("keygen").arg("--out").arg(&keys).output().unwrap();
    assert!(!again.status.success(), "second keygen must not overwrite the seed file");
    let bad = bin("keygen").args(["--level", "512"]).output().unwrap();
    assert!(!bad.status.success());
    let _ = fs::remove_dir_all(&d);
}

// ---------------------------------------------------------------------------
// Hybrid (X25519 + ML-KEM) keys through the CLI
// ---------------------------------------------------------------------------

fn keygen_hybrid(dir: &PathBuf, level: &str) {
    ok(&bin("keygen")
        .arg("--out")
        .arg(dir)
        .args(["--hybrid", "--level", level])
        .output()
        .unwrap());
}

#[test]
fn hybrid_file_roundtrip_and_tamper_both_levels() {
    for (level, ek_len) in [("768", 1216usize), ("1024", 1600usize)] {
        let d = scratch(&format!("hf{level}"));
        let keys = d.join("keys");
        keygen_hybrid(&keys, level);
        assert!(keys.join("hk_secret.b64").exists());
        assert!(!keys.join("dk_seed.b64").exists());

        let ek = fs::read_to_string(keys.join("ek.b64")).unwrap();
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        assert_eq!(STANDARD.decode(ek.trim()).unwrap().len(), ek_len);

        let plain: Vec<u8> = (0..150_000u32).map(|i| (i % 249) as u8).collect();
        fs::write(d.join("in.bin"), &plain).unwrap();
        ok(&bin("enc")
            .args([ek.as_str(), d.join("in.bin").to_str().unwrap(), d.join("c.cbox").to_str().unwrap()])
            .output()
            .unwrap());

        let dk_arg = format!("file:{}", keys.join("hk_secret.b64").display());
        ok(&bin("dec")
            .args([dk_arg.as_str(), d.join("c.cbox").to_str().unwrap(), d.join("out.bin").to_str().unwrap()])
            .output()
            .unwrap());
        assert_eq!(fs::read(d.join("out.bin")).unwrap(), plain, "hybrid {level}");

        // Truncation: failure, no output, no temp file.
        let mut c = fs::read(d.join("c.cbox")).unwrap();
        c.truncate(c.len() - 500);
        fs::write(d.join("bad.cbox"), &c).unwrap();
        let o = bin("dec")
            .args([dk_arg.as_str(), d.join("bad.cbox").to_str().unwrap(), d.join("bad.out").to_str().unwrap()])
            .output()
            .unwrap();
        assert!(!o.status.success());
        assert!(!d.join("bad.out").exists());
        assert_eq!(leftovers(&d), 0);

        // A plain key pair cannot open a hybrid file.
        let plain_keys = d.join("plain");
        keygen(&plain_keys, level);
        let plain_arg = format!("file:{}", plain_keys.join("dk_seed.b64").display());
        let o = bin("dec")
            .args([plain_arg.as_str(), d.join("c.cbox").to_str().unwrap(), d.join("nope.out").to_str().unwrap()])
            .output()
            .unwrap();
        assert!(!o.status.success());
        assert!(!d.join("nope.out").exists());
        let _ = fs::remove_dir_all(&d);
    }
}

#[test]
fn hybrid_passphrase_and_wrap_unwrap() {
    for level in ["768", "1024"] {
        let d = scratch(&format!("hw{level}"));
        let keys = d.join("keys");
        ok(&bin("keygen")
            .arg("--out")
            .arg(&keys)
            .args(["--hybrid", "--level", level, "--passphrase", "env:CBX_PW"])
            .env("CBX_PW", "correct horse")
            .output()
            .unwrap());
        assert!(keys.join("hk_secret.enc.b64").exists());
        let ek = fs::read_to_string(keys.join("ek.b64")).unwrap();

        let out = bin("wrap")
            .args([ek.as_str(), "env:CBX_ROOM"])
            .env("CBX_ROOM", "hybrid-room-key")
            .output()
            .unwrap();
        ok(&out);
        let json = String::from_utf8(out.stdout).unwrap();
        let dk_arg = format!("file:{}", keys.join("hk_secret.enc.b64").display());
        let run = |pw: &str| {
            bin("unwrap")
                .args([
                    dk_arg.as_str(),
                    "2",
                    &json_field(&json, "ct"),
                    &json_field(&json, "iv"),
                    &json_field(&json, "enc_aes"),
                ])
                .args(["--passphrase", "env:CBX_PW"])
                .env("CBX_PW", pw)
                .output()
                .unwrap()
        };
        assert!(!run("wrong").status.success());
        let o = run("correct horse");
        ok(&o);
        assert_eq!(String::from_utf8(o.stdout).unwrap().trim(), "hybrid-room-key");
        let _ = fs::remove_dir_all(&d);
    }
}

// ---------------------------------------------------------------------------
// Room auth verifier (known answer from the independent Python model)
// ---------------------------------------------------------------------------

#[test]
fn room_verifier_known_answer() {
    let bin = Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-room-verifier"))
        .args(["env:CBX_TOKEN"])
        .env("CBX_TOKEN", "cRAMnO2IFm3TAJygPWfNe8xM37V0BEYgtwB7SMhI17Y=")
        .output()
        .unwrap();
    ok(&bin);
    assert_eq!(
        String::from_utf8(bin.stdout).unwrap().trim(),
        "PEWRkvRzk40A2vlh7J4kENd2c5Wrs5koIZGoZlDJJuQ="
    );
    // wrong length is rejected
    let bad = Command::new(env!("CARGO_BIN_EXE_cipherbox-pqc-room-verifier"))
        .args(["env:CBX_TOKEN"])
        .env("CBX_TOKEN", "AAAA")
        .output()
        .unwrap();
    assert!(!bad.status.success());
}
