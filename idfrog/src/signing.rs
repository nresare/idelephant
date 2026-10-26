use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use idp_oauth::token::SigningKey;
use p256::{
    ecdsa::SigningKey as EcSigningKey,
    elliptic_curve::Generate,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path};

pub fn load(path: &Path) -> anyhow::Result<SigningKey> {
    let pem = std::fs::read_to_string(path).context("Could not read signing-key-file")?;
    let key = EcSigningKey::from_pkcs8_pem(&pem)
        .context("signing-key-file must contain a P-256 PKCS8 private key")?;
    let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(
        key.verifying_key().to_sec1_point(false).as_bytes(),
    ));
    Ok(SigningKey::from_pkcs8(
        &kid,
        key.to_pkcs8_der()?.as_bytes(),
    )?)
}

/// Create once, without overwriting an existing deployment's signing identity.
pub fn generate(path: &Path) -> anyhow::Result<()> {
    let key = EcSigningKey::generate().to_pkcs8_pem(LineEnding::LF)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("Refusing to overwrite an existing signing key")
        }
        Err(error) => return Err(error.into()),
    };
    file.write_all(key.as_bytes())?;
    Ok(())
}
