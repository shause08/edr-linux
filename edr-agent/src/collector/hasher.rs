//! Calcul de hash SHA-256 pour les binaires et fichiers.

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};

/// Taille maximale d'un fichier haché (50 Mo — conformément à EF-F06).
const MAX_HASH_SIZE: u64 = 50 * 1024 * 1024;

/// Calcule le SHA-256 d'un fichier.
///
/// Retourne `None` si le fichier est trop grand (> 50 Mo) ou inaccessible.
pub fn sha256_file(path: &str) -> Result<String> {
    let file = File::open(path)?;

    let size = file.metadata()?.len();
    if size > MAX_HASH_SIZE {
        anyhow::bail!("Fichier trop grand pour être haché ({} octets)", size);
    }

    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}
