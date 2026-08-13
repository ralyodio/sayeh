use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use sayeh_core::carrier::CarrierKind;
use sayeh_core::contact::{IdentityPublic, IdentitySecret};
use sayeh_core::crypto::Argon2Params;
use sayeh_core::vault::{open_vault, seal_vault};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    schema: u8,
    identity_secret: [u8; 32],
    #[serde(default)]
    pub contacts: Vec<ContactRecord>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ContactRecord {
    pub name: String,
    pub public_key: [u8; 32],
    pub carrier_id: u8,
    pub send_counter: u64,
    pub last_seen_counter: u64,
    #[serde(default)]
    pub probes: Vec<ProbePreference>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProbePreference {
    pub app: String,
    pub path: String,
    pub carrier_id: u8,
    pub measured_at: u64,
}

impl Vault {
    pub fn new(identity: &IdentitySecret) -> Self {
        let secret = identity.expose_for_backup();
        Self {
            schema: 1,
            identity_secret: *secret,
            contacts: Vec::new(),
        }
    }

    pub fn load(path: &Path, password: &[u8]) -> Result<Self> {
        let encrypted =
            fs::read(path).with_context(|| format!("read encrypted vault {}", path.display()))?;
        let plaintext = open_vault(&encrypted, password).context("open encrypted vault")?;
        let vault: Self =
            serde_json::from_slice(&plaintext).context("parse authenticated vault")?;
        if vault.schema != 1 {
            bail!("vault schema {} is not supported", vault.schema);
        }
        Ok(vault)
    }

    pub fn save(&self, path: &Path, password: &[u8]) -> Result<()> {
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("create vault directory {}", parent.display()))?;
        let serialized = Zeroizing::new(serde_json::to_vec(self).context("serialize vault")?);
        let encrypted =
            seal_vault(&serialized, password, Argon2Params::DEFAULT).context("encrypt vault")?;
        let mut temporary = NamedTempFile::new_in(parent).context("create vault temporary file")?;
        temporary
            .write_all(&encrypted)
            .context("write encrypted vault")?;
        temporary.flush().context("flush encrypted vault")?;
        temporary
            .as_file()
            .sync_all()
            .context("sync encrypted vault")?;
        temporary
            .persist(path)
            .map_err(|error| error.error)
            .with_context(|| format!("replace encrypted vault {}", path.display()))?;
        Ok(())
    }

    pub fn identity(&self) -> IdentitySecret {
        IdentitySecret::from_bytes(self.identity_secret)
    }

    pub fn contact_index(&self, name: &str) -> Option<usize> {
        self.contacts
            .iter()
            .position(|contact| contact.name.eq_ignore_ascii_case(name))
    }

    pub fn contact(&self, name: &str) -> Option<&ContactRecord> {
        self.contact_index(name)
            .and_then(|index| self.contacts.get(index))
    }

    pub fn contact_mut(&mut self, name: &str) -> Option<&mut ContactRecord> {
        self.contact_index(name)
            .and_then(|index| self.contacts.get_mut(index))
    }
}

impl ContactRecord {
    pub fn new(name: String, public: IdentityPublic) -> Self {
        Self {
            name,
            public_key: *public.as_bytes(),
            carrier_id: CarrierKind::ZeroWidth.id(),
            send_counter: 0,
            last_seen_counter: 0,
            probes: Vec::new(),
        }
    }

    pub fn public(&self) -> Result<IdentityPublic> {
        IdentityPublic::validate(self.public_key).context("contact public key is invalid")
    }

    pub fn carrier(&self) -> Result<CarrierKind> {
        CarrierKind::from_id(self.carrier_id).context("contact carrier id is invalid")
    }

    pub fn preferred_carrier(&self, app: Option<&str>, path: &str) -> Result<CarrierKind> {
        if let Some(app) = app
            && let Some(probe) = self.probes.iter().rev().find(|probe| {
                probe.app.eq_ignore_ascii_case(app) && probe.path.eq_ignore_ascii_case(path)
            })
        {
            return CarrierKind::from_id(probe.carrier_id).context("probe carrier id is invalid");
        }
        self.carrier()
    }

    pub fn set_probe(&mut self, app: String, path: String, carrier: CarrierKind, measured_at: u64) {
        if let Some(existing) = self.probes.iter_mut().find(|probe| {
            probe.app.eq_ignore_ascii_case(&app) && probe.path.eq_ignore_ascii_case(&path)
        }) {
            existing.carrier_id = carrier.id();
            existing.measured_at = measured_at;
            return;
        }
        self.probes.push(ProbePreference {
            app,
            path,
            carrier_id: carrier.id(),
            measured_at,
        });
    }
}

pub fn path(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path);
    }
    let directories = ProjectDirs::from("org", "sayeh", "Sayeh")
        .context("could not determine a local application-data directory")?;
    Ok(directories.data_local_dir().join("contacts.syk"))
}
