use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use sayeh_core::frame::Content;
use zeroize::Zeroizing;

pub enum OwnedContent {
    Text(Zeroizing<String>),
    File {
        name: String,
        bytes: Zeroizing<Vec<u8>>,
    },
}

impl OwnedContent {
    pub fn as_content(&self) -> Content<'_> {
        match self {
            Self::Text(text) => Content::Text(text.as_str()),
            Self::File { name, bytes } => Content::File {
                name,
                bytes: bytes.as_slice(),
            },
        }
    }
}

pub fn read_cover(cover: Option<String>, cover_file: Option<PathBuf>) -> Result<String> {
    match (cover, cover_file) {
        (Some(cover), None) => Ok(cover),
        (None, Some(path)) => fs::read_to_string(&path)
            .with_context(|| format!("read UTF-8 cover {}", path.display())),
        _ => bail!("choose exactly one of --cover and --cover-file"),
    }
}

pub fn read_content(secret_file: Option<PathBuf>, file: Option<PathBuf>) -> Result<OwnedContent> {
    match (secret_file, file) {
        (Some(path), None) => {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("read UTF-8 secret {}", path.display()))?;
            Ok(OwnedContent::Text(Zeroizing::new(text)))
        }
        (None, Some(path)) => {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .context("payload file name is not valid UTF-8")?
                .to_owned();
            let bytes =
                fs::read(&path).with_context(|| format!("read payload file {}", path.display()))?;
            Ok(OwnedContent::File {
                name,
                bytes: Zeroizing::new(bytes),
            })
        }
        _ => bail!("choose exactly one of --secret-file and --file"),
    }
}

pub fn read_text(input: Option<&Path>) -> Result<String> {
    match input {
        Some(path) => {
            fs::read_to_string(path).with_context(|| format!("read UTF-8 text {}", path.display()))
        }
        None => {
            let mut text = String::new();
            io::stdin()
                .read_to_string(&mut text)
                .context("read UTF-8 text from stdin")?;
            Ok(text)
        }
    }
}

pub fn password(
    file: Option<&Path>,
    environment: &str,
    prompt: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = if let Some(path) = file {
        let mut bytes =
            fs::read(path).with_context(|| format!("read password file {}", path.display()))?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        std::str::from_utf8(&bytes).context("password file is not UTF-8")?;
        bytes
    } else if let Ok(value) = env::var(environment) {
        value.into_bytes()
    } else {
        rpassword::prompt_password(prompt)
            .context("read password from terminal")?
            .into_bytes()
    };
    if bytes.is_empty() {
        bail!("password must not be empty");
    }
    Ok(Zeroizing::new(bytes))
}

pub fn new_vault_password() -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(value) = env::var("SAYEH_VAULT_PASSWORD") {
        if value.is_empty() {
            bail!("SAYEH_VAULT_PASSWORD must not be empty");
        }
        return Ok(Zeroizing::new(value.into_bytes()));
    }
    let first = Zeroizing::new(
        rpassword::prompt_password("New vault password: ")
            .context("read new vault password")?
            .into_bytes(),
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("Confirm vault password: ")
            .context("confirm new vault password")?
            .into_bytes(),
    );
    if first.is_empty() || first.as_slice() != second.as_slice() {
        bail!("vault passwords did not match");
    }
    Ok(first)
}

pub fn write_output(path: Option<&Path>, bytes: &[u8]) -> Result<()> {
    match path {
        Some(path) => {
            fs::write(path, bytes).with_context(|| format!("write output {}", path.display()))
        }
        None => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(bytes).context("write stdout")?;
            lock.flush().context("flush stdout")
        }
    }
}

pub fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")
        .map(|duration| duration.as_secs())
}
