use ml_dsa::{MlDsa65, VerifyingKey, Signature};
use ml_dsa::signature::Verifier;
use base64::{Engine as _, engine::general_purpose};
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <public_key_b64> <message_b64> <signature_b64>", args[0]);
        process::exit(1);
    }

    let pk_bytes = match general_purpose::STANDARD.decode(&args[1]) {
        Ok(b) => b, Err(_) => { println!("false"); process::exit(1); }
    };
    let msg_bytes = match general_purpose::STANDARD.decode(&args[2]) {
        Ok(b) => b, Err(_) => { println!("false"); process::exit(1); }
    };
    let sig_bytes = match general_purpose::STANDARD.decode(&args[3]) {
        Ok(b) => b, Err(_) => { println!("false"); process::exit(1); }
    };

    let vk_arr: &[u8; 1952] = match pk_bytes.as_slice().try_into() {
        Ok(a) => a, Err(_) => { println!("false"); process::exit(1); }
    };
    let sig_arr: &[u8; 3309] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a, Err(_) => { println!("false"); process::exit(1); }
    };

    let vk = VerifyingKey::<MlDsa65>::decode(vk_arr.into());
    let sig = match Signature::<MlDsa65>::decode(sig_arr.into()) {
        Some(s) => s, None => { println!("false"); process::exit(1); }
    };

    match vk.verify(&msg_bytes, &sig) {
        Ok(_) => { println!("true"); process::exit(0); }
        Err(_) => { println!("false"); process::exit(1); }
    }
}
