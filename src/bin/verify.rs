use base64::{Engine as _, engine::general_purpose};
use ml_dsa::signature::Verifier;
use ml_dsa::{MlDsa65, MlDsa87, Signature, VerifyingKey};
use std::env;
use std::process;

// One verifier per parameter set, generated from the same code.
macro_rules! verifier {
    ($fn_name:ident, $param:ty) => {
        fn $fn_name(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
            let vk_arr: &ml_dsa::EncodedVerifyingKey<$param> = match pk_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let sig_arr: &ml_dsa::EncodedSignature<$param> = match sig_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let vk = VerifyingKey::<$param>::decode(vk_arr);
            let sig = match Signature::<$param>::decode(sig_arr) {
                Some(s) => s,
                None => return false,
            };
            vk.verify(msg, &sig).is_ok()
        }
    };
}

verifier!(verify_65, MlDsa65);
verifier!(verify_87, MlDsa87);

fn decode(arg: &str) -> Vec<u8> {
    match general_purpose::STANDARD.decode(arg) {
        Ok(b) => b,
        Err(_) => {
            println!("false");
            process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "Usage: {} <public_key_b64> <message_b64> <signature_b64>\n\
             (ML-DSA-65 or ML-DSA-87, chosen by public key length: 1952 / 2592 bytes)",
            args[0]
        );
        process::exit(1);
    }

    let pk_bytes = decode(&args[1]);
    let msg_bytes = decode(&args[2]);
    let sig_bytes = decode(&args[3]);

    let ok = match pk_bytes.len() {
        1952 => verify_65(&pk_bytes, &msg_bytes, &sig_bytes),
        2592 => verify_87(&pk_bytes, &msg_bytes, &sig_bytes),
        _ => false,
    };
    println!("{ok}");
    process::exit(if ok { 0 } else { 1 });
}
