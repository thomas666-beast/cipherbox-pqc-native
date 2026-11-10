//! Helpers shared by the CLI binaries: secret input, private file output,
//! and atomic output files.

use base64::{Engine as _, engine::general_purpose};
use cipherbox_pqc_core::hybrid::SECRET_BYTES as HYBRID_SECRET_BYTES;
use cipherbox_pqc_core::{HybridKeyPair, KemLevel, MlKemKeyPair, decrypt_private_key};
use zeroize::Zeroize;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;

pub fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}

/// Read a secret from a *source spec*:
///
/// - `-`          read all of stdin
/// - `env:NAME`   environment variable `NAME`
/// - `file:PATH`  contents of a file
///
/// Anything else is treated as the literal secret, which still works for
/// backwards compatibility but prints a warning: command-line arguments are
/// visible to other users (`ps`) and end up in shell history.
pub fn read_secret(spec: &str) -> Result<String, String> {
    let raw = if spec == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("read stdin: {e}"))?;
        s
    } else if let Some(name) = spec.strip_prefix("env:") {
        std::env::var(name).map_err(|_| format!("environment variable {name} is not set"))?
    } else if let Some(path) = spec.strip_prefix("file:") {
        fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?
    } else {
        eprintln!(
            "warning: secret passed on the command line is visible to other users; \
             prefer '-', 'env:NAME' or 'file:PATH'"
        );
        spec.to_string()
    };
    Ok(raw.trim().to_string())
}

/// Load a decoded secret: either a 64-byte ML-KEM seed (plain keys) or a
/// 34-byte hybrid secret. With a passphrase spec the stored value is treated
/// as the output of `encrypt_private_key` (base64). The caller should
/// `zeroize()` the result when done.
pub fn load_secret(dk_spec: &str, passphrase_spec: Option<&str>) -> Result<Vec<u8>, String> {
    let mut b64 = read_secret(dk_spec)?;
    let decoded = general_purpose::STANDARD.decode(b64.as_bytes());
    b64.zeroize();
    let mut bytes = decoded.map_err(|e| format!("invalid dk b64: {e}"))?;
    if let Some(p) = passphrase_spec {
        let mut pass = read_secret(p)?;
        let dec = decrypt_private_key(&bytes, &pass);
        pass.zeroize();
        bytes.zeroize();
        bytes = dec.map_err(|e| e.to_string())?;
    }
    if bytes.len() != 64 && bytes.len() != HYBRID_SECRET_BYTES {
        let n = bytes.len();
        bytes.zeroize();
        return Err(format!(
            "secret must be 64 bytes (ML-KEM seed) or {HYBRID_SECRET_BYTES} bytes (hybrid), got {n}"
        ));
    }
    Ok(bytes)
}

/// Load a plain ML-KEM seed (exactly 64 bytes).
pub fn load_seed(dk_spec: &str, passphrase_spec: Option<&str>) -> Result<Vec<u8>, String> {
    let mut v = load_secret(dk_spec, passphrase_spec)?;
    if v.len() != 64 {
        v.zeroize();
        return Err("expected a 64-byte ML-KEM seed but found a hybrid secret".into());
    }
    Ok(v)
}

/// Load a hybrid key pair from its 34-byte secret.
pub fn load_hybrid(
    dk_spec: &str,
    passphrase_spec: Option<&str>,
) -> Result<HybridKeyPair, String> {
    let mut v = load_secret(dk_spec, passphrase_spec)?;
    let kp = HybridKeyPair::from_secret(&v).map_err(|e| e.to_string());
    v.zeroize();
    kp
}

/// Seed -> key pair of the given level.
pub fn load_keypair(
    dk_spec: &str,
    passphrase_spec: Option<&str>,
    level: KemLevel,
) -> Result<MlKemKeyPair, String> {
    let mut seed = load_seed(dk_spec, passphrase_spec)?;
    let kp = MlKemKeyPair::from_seed_with_level(&seed, level).map_err(|e| e.to_string());
    seed.zeroize();
    kp
}

/// Split `--passphrase <spec>` out of an argument list.
pub fn take_passphrase_flag(args: &mut Vec<String>) -> Option<String> {
    let i = args.iter().position(|a| a == "--passphrase")?;
    if i + 1 >= args.len() {
        fail("--passphrase needs a value (env:NAME, file:PATH or -)");
    }
    let v = args.remove(i + 1);
    args.remove(i);
    Some(v)
}

/// Create a new file readable only by the owner (mode 0600 on Unix).
/// Refuses to overwrite an existing file.
pub fn create_private(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

pub fn write_secret_file(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut f = create_private(path)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()
}

/// Output file that only appears under its final name after `commit()`.
/// Dropping it without committing deletes the partial file, so a failed
/// decryption never leaves unauthenticated plaintext behind.
pub struct AtomicOutput {
    tmp: PathBuf,
    dest: PathBuf,
    file: Option<File>,
    committed: bool,
}

impl AtomicOutput {
    pub fn create(dest: &str, private: bool) -> std::io::Result<Self> {
        let dest = PathBuf::from(dest);
        let mut name = dest.as_os_str().to_owned();
        name.push(format!(".tmp-{}", process::id()));
        let tmp = PathBuf::from(name);
        let file = if private {
            create_private(&tmp)?
        } else {
            OpenOptions::new().write(true).create_new(true).open(&tmp)?
        };
        Ok(Self {
            tmp,
            dest,
            file: Some(file),
            committed: false,
        })
    }

    pub fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.file.as_mut().expect("file open").write_all(data)
    }

    pub fn commit(mut self) -> std::io::Result<()> {
        let f = self.file.take().expect("file open");
        f.sync_all()?;
        drop(f);
        fs::rename(&self.tmp, &self.dest)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        if !self.committed {
            self.file.take();
            let _ = fs::remove_file(&self.tmp);
        }
    }
}
