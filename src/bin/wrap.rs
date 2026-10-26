use std::env;
use std::process;
use cipherbox_pqc_native::wrap_room_key_for_user;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <user_kyber_pk_b64> <plaintext_room_key>", args[0]);
        process::exit(1);
    }

    match wrap_room_key_for_user(&args[1], &args[2]) {
        Ok(json_out) => {
            println!("{}", json_out);
            process::exit(0);
        }
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}
