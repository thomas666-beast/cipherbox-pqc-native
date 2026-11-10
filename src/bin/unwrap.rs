use base64::{Engine as _, engine::general_purpose};
use cipherbox_pqc_native::cli::{fail, load_hybrid, load_keypair, take_passphrase_flag};
use cipherbox_pqc_native::{Suite, unwrap_room_key};
use std::env;
use std::process;

fn main() {
    let mut args: Vec<String> = env::args().collect();
    let pass_spec = take_passphrase_flag(&mut args);
    if args.len() != 6 {
        eprintln!(
            "Usage: {} <dk: file:PATH|env:NAME|-> <version 1|2> <ct_b64> <iv_b64> <enc_aes_b64> \
             [--passphrase <spec>]",
            args[0]
        );
        process::exit(1);
    }
    let version: u8 = args[2]
        .parse()
        .unwrap_or_else(|_| fail("version must be 1 (legacy) or 2"));
    // The suite (plain ML-KEM 768/1024 or hybrid) follows from the KEM
    // ciphertext size.
    let ct_len = general_purpose::STANDARD
        .decode(args[3].trim())
        .unwrap_or_else(|e| fail(format!("invalid ct b64: {e}")))
        .len();
    let suite = Suite::from_ct_len(ct_len)
        .unwrap_or_else(|| fail(format!("unrecognised KEM ciphertext length {ct_len}")));

    let result = match suite {
        Suite::Kem(level) => {
            let kp = load_keypair(&args[1], pass_spec.as_deref(), level).unwrap_or_else(|e| fail(e));
            unwrap_room_key(&kp, version, &args[3], &args[4], &args[5])
        }
        Suite::Hybrid(_) => {
            let kp = load_hybrid(&args[1], pass_spec.as_deref()).unwrap_or_else(|e| fail(e));
            unwrap_room_key(&kp, version, &args[3], &args[4], &args[5])
        }
    };
    match result {
        Ok(pt) => println!("{pt}"),
        Err(e) => fail(e),
    }
}
