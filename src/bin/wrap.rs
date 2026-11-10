use cipherbox_pqc_native::cli::read_secret;
use cipherbox_pqc_native::wrap_room_key_for_user;
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "Usage: {} <user_kyber_pk_b64> <room_key: -|env:NAME|file:PATH|literal>",
            args[0]
        );
        process::exit(1);
    }
    let room_key = read_secret(&args[2]).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        process::exit(1);
    });

    match wrap_room_key_for_user(args[1].trim(), &room_key) {
        Ok(json_out) => println!("{json_out}"),
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    }
}
