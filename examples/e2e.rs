use base64::{engine::general_purpose, Engine as _};
use cipherbox_pqc_native::MlDsaKeyPair;

fn main() {
    let kp = MlDsaKeyPair::new();
    let (_, vk) = kp.export_keys();
    let msg = b"hello";
    let sig = kp.sign(msg);

    println!("VK={}", general_purpose::STANDARD.encode(&vk));
    println!("MSG={}", general_purpose::STANDARD.encode(msg));
    println!("SIG={}", general_purpose::STANDARD.encode(&sig));
}
