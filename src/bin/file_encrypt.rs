use base64::{Engine as _, engine::general_purpose};
use cipherbox_pqc_native::cli::AtomicOutput;
use cipherbox_pqc_native::file::{CHUNK_SIZE_DEFAULT, FileEncryptor};
use cipherbox_pqc_native::validate_public_key;
use std::env;
use std::fs::File;
use std::io::Read;
use std::process;

// All work happens in `run` so destructors (temp-file cleanup) execute
// before `main` calls `process::exit`.
fn run(args: &[String]) -> Result<(), String> {
    let pk_bytes = general_purpose::STANDARD
        .decode(args[1].trim())
        .map_err(|e| format!("invalid pk b64: {e}"))?;
    // Accepts plain ML-KEM (1184/1568 B) and hybrid (1216/1600 B) public keys.
    validate_public_key(&pk_bytes).map_err(|e| e.to_string())?;

    let chunk_size = if args.len() == 5 {
        args[4]
            .parse::<usize>()
            .map_err(|e| format!("invalid chunk_size: {e}"))?
    } else {
        CHUNK_SIZE_DEFAULT
    };

    let mut input = File::open(&args[2]).map_err(|e| format!("open input: {e}"))?;
    let mut output =
        AtomicOutput::create(&args[3], false).map_err(|e| format!("create output: {e}"))?;
    let mut enc = FileEncryptor::new(&pk_bytes, chunk_size).map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; chunk_size];
    let mut out_buf = Vec::with_capacity(chunk_size + 32);
    loop {
        let n = input.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        out_buf.clear();
        enc.update(&buf[..n], &mut out_buf).map_err(|e| e.to_string())?;
        if !out_buf.is_empty() {
            output.write_all(&out_buf).map_err(|e| format!("write: {e}"))?;
        }
    }
    out_buf.clear();
    enc.finish(&mut out_buf).map_err(|e| e.to_string())?;
    output.write_all(&out_buf).map_err(|e| format!("write: {e}"))?;
    output.commit().map_err(|e| format!("finalize output: {e}"))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if !(4..=5).contains(&args.len()) {
        eprintln!(
            "Usage: {} <recipient_pk_b64> <input_file> <output_file> [chunk_size]",
            args[0]
        );
        process::exit(1);
    }
    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
