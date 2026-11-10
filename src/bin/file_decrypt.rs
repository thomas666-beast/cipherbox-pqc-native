use cipherbox_pqc_native::cli::{AtomicOutput, load_secret, take_passphrase_flag};
use cipherbox_pqc_native::file::FileDecryptor;
use std::env;
use std::fs::File;
use std::io::Read;
use std::process;
use zeroize::Zeroize;

// All work happens in `run` so that `AtomicOutput`'s destructor deletes the
// partial plaintext file on any error, before `main` calls `process::exit`.
fn run(args: &[String], pass_spec: Option<&str>) -> Result<(), String> {
    // 64 bytes = plain ML-KEM seed (level read from the file header);
    // 34 bytes = hybrid secret (level is inside it).
    let mut secret = load_secret(&args[1], pass_spec)?;
    let made = if secret.len() == 64 {
        FileDecryptor::from_seed(&secret)
    } else {
        FileDecryptor::from_hybrid_secret(&secret)
    };
    secret.zeroize();
    let mut dec = made.map_err(|e| e.to_string())?;
    let mut input = File::open(&args[2]).map_err(|e| format!("open input: {e}"))?;
    // Plaintext goes to a private (0600) temp file that is renamed into
    // place only after the final chunk authenticates.
    let mut output =
        AtomicOutput::create(&args[3], true).map_err(|e| format!("create output: {e}"))?;

    let mut buf = vec![0u8; 65536];
    let mut out_buf = Vec::with_capacity(buf.len());
    loop {
        let n = input.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        out_buf.clear();
        dec.update(&buf[..n], &mut out_buf).map_err(|e| e.to_string())?;
        if !out_buf.is_empty() {
            output.write_all(&out_buf).map_err(|e| format!("write: {e}"))?;
        }
    }
    out_buf.clear();
    dec.finish(&mut out_buf).map_err(|e| e.to_string())?;
    output.write_all(&out_buf).map_err(|e| format!("write: {e}"))?;
    output.commit().map_err(|e| format!("finalize output: {e}"))
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    let pass_spec = take_passphrase_flag(&mut args);
    if args.len() != 4 {
        eprintln!(
            "Usage: {} <dk_seed: file:PATH|env:NAME|-> <input_file> <output_file> \
             [--passphrase <env:NAME|file:PATH|->]",
            args[0]
        );
        process::exit(1);
    }
    if let Err(e) = run(&args, pass_spec.as_deref()) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
