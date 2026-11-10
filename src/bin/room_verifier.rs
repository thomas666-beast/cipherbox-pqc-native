use base64::{Engine as _, engine::general_purpose};
use cipherbox_pqc_native::cli::{fail, read_secret};
use cipherbox_pqc_native::room::auth_verifier;
use std::env;
use std::process;

/// Turns a room auth token into the verifier a server should store.
/// The server keeps only the verifier; on join it hashes the presented token
/// the same way and compares, so it never learns anything usable to derive keys.
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!(
            "Usage: {} <auth_token: -|env:NAME|file:PATH|base64>\n\
             Prints base64(verifier). Compare it (constant-time) with the stored value.",
            args[0]
        );
        process::exit(1);
    }
    let b64 = read_secret(&args[1]).unwrap_or_else(|e| fail(e));
    let bytes = general_purpose::STANDARD
        .decode(b64.as_bytes())
        .unwrap_or_else(|e| fail(format!("invalid token b64: {e}")));
    let token: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| fail("auth token must be 32 bytes"));
    println!("{}", general_purpose::STANDARD.encode(auth_verifier(&token)));
}
