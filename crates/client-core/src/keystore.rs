//! Secret key storage (spec §5.3): one file per profile in `<config>/keys/`, 0600 inside
//! the 0700 config directory on Unix (Windows: the user profile's own permissions).
//! Secret keys never go in `profiles.json`.
//!
//! Optionally a key file is encrypted with a passphrase: Argon2id derives a key that
//! seals the secret with ChaCha20-Poly1305. The file then reads
//! `lwenc1:<salt>:<nonce>:<ciphertext>` (base64 parts).

use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use lemonwire_proto::keys::{self, KeyPair};
use zeroize::Zeroizing;

use crate::config::{create_private_dir, write_private};
use crate::error::{ClientError, Result};

const ENC_PREFIX: &str = "lwenc1:";

pub struct KeyStore {
    dir: PathBuf,
    passphrase: std::sync::Mutex<Option<Zeroizing<String>>>,
}

fn derive(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|e| ClientError::KeyStore(format!("key derivation failed: {e}")))?;
    Ok(out)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| ClientError::KeyStore("no randomness".into()))?;
    Ok(b)
}

fn seal(secret: &str, passphrase: &str) -> Result<String> {
    let salt = random::<16>()?;
    let nonce = random::<12>()?;
    let key = derive(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key");
    let ct = cipher
        .encrypt(&Nonce::from(nonce), secret.as_bytes())
        .map_err(|_| ClientError::KeyStore("encryption failed".into()))?;
    Ok(format!(
        "{ENC_PREFIX}{}:{}:{}",
        keys::b64_encode(&salt),
        keys::b64_encode(&nonce),
        keys::b64_encode(&ct)
    ))
}

fn open(sealed: &str, passphrase: &str) -> Result<Zeroizing<String>> {
    let bad = || ClientError::KeyStore("key file is damaged".into());
    let parts: Vec<&str> = sealed
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(bad)?
        .split(':')
        .collect();
    let [salt, nonce, ct] = parts.as_slice() else {
        return Err(bad());
    };
    let salt = keys::b64_decode(salt).map_err(|_| bad())?;
    let nonce: [u8; 12] = keys::b64_decode(nonce)
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    let ct = keys::b64_decode(ct).map_err(|_| bad())?;
    let key = derive(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key");
    let plain = cipher
        .decrypt(&Nonce::from(nonce), ct.as_slice())
        .map_err(|_| ClientError::WrongPassphrase)?;
    String::from_utf8(plain)
        .map(Zeroizing::new)
        .map_err(|_| bad())
}

impl KeyStore {
    /// `passphrase`: used to open protected key files, and to protect new ones.
    pub fn new(config_root: &Path, passphrase: Option<String>) -> Self {
        Self {
            dir: config_root.join("keys"),
            passphrase: std::sync::Mutex::new(passphrase.map(Zeroizing::new)),
        }
    }

    /// Change the passphrase used from now on (a GUI asks for it after start-up).
    pub fn set_passphrase(&self, passphrase: Option<String>) {
        *self.passphrase.lock().expect("passphrase lock") = passphrase.map(Zeroizing::new);
    }

    fn passphrase(&self) -> Option<Zeroizing<String>> {
        self.passphrase.lock().expect("passphrase lock").clone()
    }

    fn file(&self, profile: &str) -> PathBuf {
        self.dir.join(format!("{profile}.key"))
    }

    fn read(&self, profile: &str) -> Result<Option<Zeroizing<String>>> {
        let path = self.file(profile);
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(Some(Zeroizing::new(s.trim().to_owned()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ClientError::Io(path, e)),
        }
    }

    /// Is this profile's key file passphrase-protected?
    pub fn is_protected(&self, profile: &str) -> Result<bool> {
        Ok(self
            .read(profile)?
            .is_some_and(|s| s.starts_with(ENC_PREFIX)))
    }

    pub fn get(&self, profile: &str) -> Result<Option<KeyPair>> {
        let Some(contents) = self.read(profile)? else {
            return Ok(None);
        };
        let secret = if contents.starts_with(ENC_PREFIX) {
            let pass = self.passphrase().ok_or(ClientError::PassphraseRequired)?;
            open(&contents, &pass)?
        } else {
            contents
        };
        Ok(Some(KeyPair::from_secret_b64(&secret)?))
    }

    /// Store a key, protected with the passphrase if this store has one.
    pub fn put(&self, profile: &str, key: &KeyPair) -> Result<()> {
        let secret = Zeroizing::new(key.secret_b64());
        let contents = match self.passphrase() {
            Some(p) => Zeroizing::new(seal(&secret, &p)?),
            None => secret,
        };
        create_private_dir(&self.dir)?;
        write_private(&self.file(profile), contents.as_bytes())
    }

    /// Re-save a key with a new passphrase (`None` removes protection).
    pub fn protect(&self, profile: &str, new_passphrase: Option<&str>) -> Result<()> {
        let key = self
            .get(profile)?
            .ok_or_else(|| ClientError::KeyStore(format!("no key for profile {profile:?}")))?;
        let secret = Zeroizing::new(key.secret_b64());
        let contents = match new_passphrase {
            Some(p) if !p.is_empty() => Zeroizing::new(seal(&secret, p)?),
            Some(_) => return Err(ClientError::Invalid("the passphrase is empty".into())),
            None => secret,
        };
        write_private(&self.file(profile), contents.as_bytes())
    }

    pub fn delete(&self, profile: &str) -> Result<()> {
        let path = self.file(profile);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ClientError::Io(path, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::new(dir.path(), None);
        assert!(ks.get("home").unwrap().is_none());
        let kp = KeyPair::generate().unwrap();
        ks.put("home", &kp).unwrap();
        assert_eq!(ks.get("home").unwrap().unwrap().public(), kp.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("keys/home.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        ks.delete("home").unwrap();
        assert!(ks.get("home").unwrap().is_none());
    }

    #[test]
    fn passphrase_protection() {
        let dir = tempfile::tempdir().unwrap();
        let kp = KeyPair::generate().unwrap();
        KeyStore::new(dir.path(), None).put("home", &kp).unwrap();

        // Protect it; the file no longer contains the secret.
        let plain = KeyStore::new(dir.path(), None);
        plain.protect("home", Some("lemon tree")).unwrap();
        let file = std::fs::read_to_string(dir.path().join("keys/home.key")).unwrap();
        assert!(file.starts_with(ENC_PREFIX));
        assert!(!file.contains(&kp.secret_b64()));
        assert!(plain.is_protected("home").unwrap());

        // Opening needs the right passphrase.
        assert!(matches!(
            KeyStore::new(dir.path(), None).get("home"),
            Err(ClientError::PassphraseRequired)
        ));
        assert!(matches!(
            KeyStore::new(dir.path(), Some("wrong".into())).get("home"),
            Err(ClientError::WrongPassphrase)
        ));
        let later = KeyStore::new(dir.path(), None);
        later.set_passphrase(Some("lemon tree".into()));
        assert_eq!(later.get("home").unwrap().unwrap().public(), kp.public());
        let right = KeyStore::new(dir.path(), Some("lemon tree".into()));
        assert_eq!(right.get("home").unwrap().unwrap().public(), kp.public());

        // New keys from a store with a passphrase are protected too.
        let other = KeyPair::generate().unwrap();
        right.put("other", &other).unwrap();
        assert!(right.is_protected("other").unwrap());

        // And protection can be removed again.
        right.protect("home", None).unwrap();
        assert!(!right.is_protected("home").unwrap());
        assert_eq!(
            KeyStore::new(dir.path(), None)
                .get("home")
                .unwrap()
                .unwrap()
                .public(),
            kp.public()
        );
    }
}
