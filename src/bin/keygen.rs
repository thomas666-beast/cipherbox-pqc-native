use base64::{Engine as _, engine::general_purpose};
use cipherbox_pqc_native::cli::{fail, read_secret, take_passphrase_flag, write_secret_file};
use cipherbox_pqc_native::{HybridKeyPair, KemLevel, MlKemKeyPair, encrypt_private_key};
use std::env;
use std::fs;
use std::path::Path;

const USAGE: &str = "Usage: cipherbox-pqc-keygen [--hybrid] [--level 768|1024] [--out <dir>] [--passphrase <env:NAME|file:PATH|->]\n\
  --hybrid       X25519 + ML-KEM hybrid key (secret is 34 bytes, written as hk_secret.b64)\n\
  --level        ML-KEM parameter set (default 768; 1024 is the CNSA 2.0 level)\n\
  --out DIR      write ek.b64 and the secret seed file into DIR (mode 0600)\n\
  --passphrase   encrypt the secret seed (Argon2id + ChaCha20-Poly1305);\n\
                 it is then written as dk_seed.enc.b64\n\
Note: the seed does not record the level; the public key length does\n\
(1184 / 1568 bytes = plain 768 / 1024; 1216 / 1600 bytes = hybrid 768 / 1024).";

fn take_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    if i + 1 >= args.len() {
        fail(format!("{flag} needs a value"));
    }
    let v = args.remove(i + 1);
    args.remove(i);
    Some(v)
}

fn take_switch(args: &mut Vec<String>, flag: &str) -> bool {
    match args.iter().position(|a| a == flag) {
        Some(i) => {
            args.remove(i);
            true
        }
        None => false,
    }
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let pass_spec = take_passphrase_flag(&mut args);
    let hybrid = take_switch(&mut args, "--hybrid");
    let level = match take_value(&mut args, "--level") {
        None => KemLevel::MlKem768,
        Some(v) => v
            .parse::<u16>()
            .ok()
            .and_then(KemLevel::from_param)
            .unwrap_or_else(|| fail("--level must be 768 or 1024")),
    };
    let out_dir = take_value(&mut args, "--out");
    if !args.is_empty() {
        eprintln!("{USAGE}");
        std::process::exit(1);
    }

    // (secret bytes, public key bytes, plain file name for the secret, label)
    let (dk_seed, ek, plain_name, label) = if hybrid {
        let kp = HybridKeyPair::new(level).unwrap_or_else(|e| fail(e));
        (
            kp.export_secret(),
            kp.public_key().to_vec(),
            "hk_secret.b64",
            format!("X25519+{}", level.name()),
        )
    } else {
        let kp = MlKemKeyPair::new_with_level(level).unwrap_or_else(|e| fail(e));
        let (seed, ek) = kp.export_keys();
        (seed, ek, "dk_seed.b64", level.name().to_string())
    };
    let ek_b64 = general_purpose::STANDARD.encode(&ek);

    let (seed_b64, seed_name) = match &pass_spec {
        Some(spec) => {
            let pass = read_secret(spec).unwrap_or_else(|e| fail(e));
            if pass.is_empty() {
                fail("empty passphrase");
            }
            let blob = encrypt_private_key(&dk_seed, &pass).unwrap_or_else(|e| fail(e));
            let enc_name = plain_name.replace(".b64", ".enc.b64");
            (general_purpose::STANDARD.encode(blob), enc_name)
        }
        None => (
            general_purpose::STANDARD.encode(&dk_seed),
            plain_name.to_string(),
        ),
    };

    match out_dir {
        Some(dir) => {
            fs::create_dir_all(&dir).unwrap_or_else(|e| fail(format!("create dir: {e}")));
            let ek_path = Path::new(&dir).join("ek.b64");
            let sk_path = Path::new(&dir).join(&seed_name);
            // Never overwrite anything: an existing seed paired with a freshly
            // written public key would silently mismatch.
            for p in [&ek_path, &sk_path] {
                if p.exists() {
                    fail(format!("{} already exists; refusing to overwrite", p.display()));
                }
            }
            write_secret_file(&sk_path, &seed_b64)
                .unwrap_or_else(|e| fail(format!("write {seed_name}: {e}")));
            fs::write(&ek_path, &ek_b64).unwrap_or_else(|e| fail(format!("write ek.b64: {e}")));
            println!(
                "wrote {} and {} ({})",
                ek_path.display(),
                sk_path.display(),
                label
            );
        }
        None => {
            println!("EK={ek_b64}");
            println!("DK_SEED={seed_b64}");
        }
    }
}
