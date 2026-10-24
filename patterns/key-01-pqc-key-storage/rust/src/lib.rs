//! Pattern KEY-01: generating, encoding and storing ML-DSA and ML-KEM keys.
//!
//! Private keys are stored as their seed (32 bytes for ML-DSA, 64 for
//! ML-KEM) in the seed-only PKCS#8 form of RFC 9881 and RFC 9935,
//! PEM-encoded as `PRIVATE KEY`. Public keys use SubjectPublicKeyInfo,
//! PEM-encoded as `PUBLIC KEY`. Parsing is strict: only the exact DER this
//! crate writes is accepted, so every key has one encoding and one key ID.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use aws_lc_rs::digest::{SHA256, digest};
use ml_dsa::signature::Keypair;
use ml_dsa::{MlDsa65, MlDsa87, SigningKey, VerifyingKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768, MlKem1024};
use pkcs8::der::Decode;
use pkcs8::spki::{DecodePublicKey, EncodePublicKey, SubjectPublicKeyInfoRef};
use pkcs8::{
    DecodePrivateKey, EncodePrivateKey, LineEnding, ObjectIdentifier, PrivateKeyInfoRef, SecretDocument,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    MlDsa65,
    /// CNSA 2.0.
    MlDsa87,
    MlKem768,
    /// CNSA 2.0.
    MlKem1024,
}

impl Algorithm {
    pub const ALL: [Algorithm; 4] = [
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
        Algorithm::MlKem768,
        Algorithm::MlKem1024,
    ];

    /// The FIPS name, such as `ML-DSA-65`.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
            Algorithm::MlKem768 => "ML-KEM-768",
            Algorithm::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// 32 bytes for ML-DSA (FIPS 204 xi), 64 bytes for ML-KEM (FIPS 203 d || z).
    pub fn seed_size(self) -> usize {
        match self {
            Algorithm::MlDsa65 | Algorithm::MlDsa87 => 32,
            Algorithm::MlKem768 | Algorithm::MlKem1024 => 64,
        }
    }

    fn oid(self) -> ObjectIdentifier {
        ObjectIdentifier::new_unwrap(match self {
            Algorithm::MlDsa65 => "2.16.840.1.101.3.4.3.18",
            Algorithm::MlDsa87 => "2.16.840.1.101.3.4.3.19",
            Algorithm::MlKem768 => "2.16.840.1.101.3.4.4.2",
            Algorithm::MlKem1024 => "2.16.840.1.101.3.4.4.3",
        })
    }

    fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.oid() == oid)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Any malformed, non-canonical or unsupported key encoding.
    InvalidKey,
    SeedLength {
        expected: usize,
        got: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKey => write!(f, "keys: invalid key encoding"),
            Error::SeedLength { expected, got } => {
                write!(f, "keys: seed must be {expected} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// A private seed and the public key derived from it. The seed is wiped
/// from memory when the key pair is dropped.
pub struct KeyPair {
    pub algorithm: Algorithm,
    seed: Zeroizing<Vec<u8>>,
    pub public_key: Vec<u8>,
}

impl KeyPair {
    /// Creates a new key pair from the system CSPRNG.
    pub fn generate(algorithm: Algorithm) -> Self {
        let mut seed = Zeroizing::new(vec![0u8; algorithm.seed_size()]);
        getrandom::fill(&mut seed).expect("system RNG failed");
        Self::from_seed(algorithm, &seed).expect("seed has the right length")
    }

    /// Rebuilds a key pair from its seed.
    pub fn from_seed(algorithm: Algorithm, seed: &[u8]) -> Result<Self, Error> {
        if seed.len() != algorithm.seed_size() {
            return Err(Error::SeedLength {
                expected: algorithm.seed_size(),
                got: seed.len(),
            });
        }
        let spki = public_key_der(algorithm, seed);
        let public_key = SubjectPublicKeyInfoRef::from_der(&spki)
            .expect("library output is valid SPKI")
            .subject_public_key
            .raw_bytes()
            .to_vec();
        Ok(KeyPair {
            algorithm,
            seed: Zeroizing::new(seed.to_vec()),
            public_key,
        })
    }

    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// The ML-DSA signing key. Panics if this is not an ML-DSA-65 key.
    pub fn ml_dsa_65(&self) -> SigningKey<MlDsa65> {
        assert_eq!(self.algorithm, Algorithm::MlDsa65);
        SigningKey::from_seed(self.seed[..].try_into().unwrap())
    }

    /// The ML-KEM decapsulation key. Panics if this is not an ML-KEM-768 key.
    pub fn ml_kem_768(&self) -> DecapsulationKey<MlKem768> {
        assert_eq!(self.algorithm, Algorithm::MlKem768);
        DecapsulationKey::from_seed(self.seed[..].try_into().unwrap())
    }

    /// Seed-only PKCS#8 in a `PRIVATE KEY` PEM block.
    pub fn private_key_pem(&self) -> Zeroizing<String> {
        let doc = private_key_der(self.algorithm, &self.seed);
        Zeroizing::new(
            doc.to_pem("PRIVATE KEY", LineEnding::LF)
                .expect("PEM encoding")
                .to_string(),
        )
    }

    /// SubjectPublicKeyInfo in a `PUBLIC KEY` PEM block.
    pub fn public_key_pem(&self) -> String {
        pkcs8::der::pem::encode_string("PUBLIC KEY", LineEnding::LF, &self.spki()).expect("PEM encoding")
    }

    /// Lowercase hex SHA-256 of the SubjectPublicKeyInfo DER: a stable name
    /// for the key in logs, key sets and rotation records.
    pub fn key_id(&self) -> String {
        digest(&SHA256, &self.spki())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn spki(&self) -> Vec<u8> {
        public_key_der(self.algorithm, &self.seed)
    }
}

fn private_key_der(algorithm: Algorithm, seed: &[u8]) -> SecretDocument {
    let doc = match algorithm {
        Algorithm::MlDsa65 => SigningKey::<MlDsa65>::from_seed(seed.try_into().unwrap()).to_pkcs8_der(),
        Algorithm::MlDsa87 => SigningKey::<MlDsa87>::from_seed(seed.try_into().unwrap()).to_pkcs8_der(),
        Algorithm::MlKem768 => {
            DecapsulationKey::<MlKem768>::from_seed(seed.try_into().unwrap()).to_pkcs8_der()
        }
        Algorithm::MlKem1024 => {
            DecapsulationKey::<MlKem1024>::from_seed(seed.try_into().unwrap()).to_pkcs8_der()
        }
    };
    doc.expect("PKCS#8 encoding")
}

fn public_key_der(algorithm: Algorithm, seed: &[u8]) -> Vec<u8> {
    let doc = match algorithm {
        Algorithm::MlDsa65 => SigningKey::<MlDsa65>::from_seed(seed.try_into().unwrap())
            .verifying_key()
            .to_public_key_der(),
        Algorithm::MlDsa87 => SigningKey::<MlDsa87>::from_seed(seed.try_into().unwrap())
            .verifying_key()
            .to_public_key_der(),
        Algorithm::MlKem768 => DecapsulationKey::<MlKem768>::from_seed(seed.try_into().unwrap())
            .encapsulation_key()
            .to_public_key_der(),
        Algorithm::MlKem1024 => DecapsulationKey::<MlKem1024>::from_seed(seed.try_into().unwrap())
            .encapsulation_key()
            .to_public_key_der(),
    };
    doc.expect("SPKI encoding").into_vec()
}

/// Reads a key written by [`KeyPair::private_key_pem`]. Expanded and "both"
/// private key forms, encrypted PEM and trailing data are rejected.
pub fn parse_private_key_pem(pem: &str) -> Result<KeyPair, Error> {
    let (label, doc) = SecretDocument::from_pem(pem).map_err(|_| Error::InvalidKey)?;
    if label != "PRIVATE KEY" {
        return Err(Error::InvalidKey);
    }
    let info = PrivateKeyInfoRef::try_from(doc.as_bytes()).map_err(|_| Error::InvalidKey)?;
    let algorithm = Algorithm::from_oid(info.algorithm.oid).ok_or(Error::InvalidKey)?;
    let der = doc.as_bytes();
    let seed: Zeroizing<Vec<u8>> = Zeroizing::new(
        match algorithm {
            Algorithm::MlDsa65 => SigningKey::<MlDsa65>::from_pkcs8_der(der).map(|k| k.to_seed().to_vec()),
            Algorithm::MlDsa87 => SigningKey::<MlDsa87>::from_pkcs8_der(der).map(|k| k.to_seed().to_vec()),
            Algorithm::MlKem768 => DecapsulationKey::<MlKem768>::from_pkcs8_der(der)
                .map(|k| k.to_seed().expect("decoded from a seed").to_vec()),
            Algorithm::MlKem1024 => DecapsulationKey::<MlKem1024>::from_pkcs8_der(der)
                .map(|k| k.to_seed().expect("decoded from a seed").to_vec()),
        }
        .map_err(|_| Error::InvalidKey)?,
    );
    if private_key_der(algorithm, &seed).as_bytes() != der {
        return Err(Error::InvalidKey);
    }
    KeyPair::from_seed(algorithm, &seed)
}

/// Reads a key written by [`KeyPair::public_key_pem`] and checks that it is
/// a valid key for its algorithm.
pub fn parse_public_key_pem(pem: &str) -> Result<(Algorithm, Vec<u8>), Error> {
    let (label, der) = pkcs8::der::pem::decode_vec(pem.as_bytes()).map_err(|_| Error::InvalidKey)?;
    if label != "PUBLIC KEY" {
        return Err(Error::InvalidKey);
    }
    let info = SubjectPublicKeyInfoRef::from_der(&der).map_err(|_| Error::InvalidKey)?;
    let algorithm = Algorithm::from_oid(info.algorithm.oid).ok_or(Error::InvalidKey)?;
    let again = match algorithm {
        Algorithm::MlDsa65 => {
            VerifyingKey::<MlDsa65>::from_public_key_der(&der).map(|k| k.to_public_key_der())
        }
        Algorithm::MlDsa87 => {
            VerifyingKey::<MlDsa87>::from_public_key_der(&der).map(|k| k.to_public_key_der())
        }
        Algorithm::MlKem768 => {
            EncapsulationKey::<MlKem768>::from_public_key_der(&der).map(|k| k.to_public_key_der())
        }
        Algorithm::MlKem1024 => {
            EncapsulationKey::<MlKem1024>::from_public_key_der(&der).map(|k| k.to_public_key_der())
        }
    };
    match again {
        Ok(Ok(doc)) if doc.as_bytes() == der.as_slice() => {
            Ok((algorithm, info.subject_public_key.raw_bytes().to_vec()))
        }
        _ => Err(Error::InvalidKey),
    }
}

/// Writes the private key PEM to a new file readable only by its owner. It
/// refuses to overwrite an existing file.
pub fn write_private_key_file(path: impl AsRef<Path>, key: &KeyPair) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut f = options.open(path)?;
    f.write_all(key.private_key_pem().as_bytes())?;
    f.sync_all()
}

/// Reads a private key file, refusing files that other users can read or
/// write (as OpenSSH does).
pub fn read_private_key_file(path: impl AsRef<Path>) -> io::Result<KeyPair> {
    let mut f = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if f.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private key is accessible by other users",
            ));
        }
    }
    let mut pem = Zeroizing::new(String::new());
    f.read_to_string(&mut pem)?;
    parse_private_key_pem(&pem).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
