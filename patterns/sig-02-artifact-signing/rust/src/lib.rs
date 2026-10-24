//! Pattern SIG-02: signing release artifacts, such as binaries, archives and
//! firmware images, with detached ML-DSA-87 signatures.
//!
//! A signature file is text with exactly these lines, in this order:
//!
//! ```text
//! pqc-patterns-signature-v1
//! algorithm: ML-DSA-87
//! key: <hex SHA-256 of the signer's SubjectPublicKeyInfo DER>
//! name: <artifact name, printable ASCII without spaces>
//! size: <artifact length in bytes>
//! sha512: <hex SHA-512 of the artifact>
//! signed: <RFC 3339 UTC time, whole seconds>
//! signature: <base64 ML-DSA-87 signature>
//! ```
//!
//! The signature covers the first seven lines exactly as written, including
//! their line feeds, under the ML-DSA context string [`CONTEXT`]. Verifiers
//! check the signature before they read the artifact, and check the name
//! they expected rather than trusting the file's.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest::{Context, SHA256, SHA512, digest};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use getrandom::SysRng;
use ml_dsa::pkcs8::EncodePublicKey;
use ml_dsa::signature::Keypair;
use ml_dsa::{MlDsa87, Seed, Signature, SigningKey, VerifyingKey};

/// Domain-separates artifact signatures from every other use of the same
/// key (FIPS 204, section 5.2).
pub const CONTEXT: &[u8] = b"pqc-patterns/sig-02/artifact/v1";
pub const ALGORITHM: &str = "ML-DSA-87";
/// Bounds what [`Verifier::verify`] will parse.
pub const MAX_SIGNATURE_FILE: usize = 16 * 1024;
const MAGIC: &str = "pqc-patterns-signature-v1";
const MAX_NAME_LEN: usize = 255;
const FIELDS: [&str; 7] = [
    "algorithm",
    "key",
    "name",
    "size",
    "sha512",
    "signed",
    "signature",
];

/// Artifact signing keys live for years and signature size rarely matters,
/// so this pattern uses the CNSA 2.0 level.
pub type Params = MlDsa87;

#[derive(Debug)]
pub enum VerifyError {
    Malformed,
    UnknownKey,
    Signature,
    WrongArtifact,
    Io(io::Error),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Malformed => write!(f, "artifacts: malformed signature file"),
            VerifyError::UnknownKey => write!(f, "artifacts: signed by an untrusted key"),
            VerifyError::Signature => write!(f, "artifacts: signature does not verify"),
            VerifyError::WrongArtifact => write!(f, "artifacts: signature is for a different artifact"),
            VerifyError::Io(e) => write!(f, "artifacts: {e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// What a signature file asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub key_id: String,
    pub name: String,
    pub size: u64,
    pub sha512: Vec<u8>,
    /// Unix seconds.
    pub signed: i64,
}

impl Statement {
    fn encode(&self) -> String {
        format!(
            "{MAGIC}\nalgorithm: {ALGORITHM}\nkey: {}\nname: {}\nsize: {}\nsha512: {}\nsigned: {}\n",
            self.key_id,
            self.name,
            self.size,
            to_hex(&self.sha512),
            format_time(self.signed)
        )
    }
}

/// Hex SHA-256 of the key's SubjectPublicKeyInfo DER, the same key ID as
/// pattern KEY-01.
pub fn key_id(pk: &VerifyingKey<Params>) -> String {
    let der = pk.to_public_key_der().expect("SPKI encoding");
    to_hex(digest(&SHA256, der.as_bytes()).as_ref())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_LEN && name.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Signs artifacts with one key.
pub struct Signer {
    key: SigningKey<Params>,
}

impl Signer {
    /// Loads a signing key from its 32-byte seed (see KEY-01 for storing it).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Signer {
            key: SigningKey::from_seed(&Seed::from(*seed)),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey<Params> {
        self.key.verifying_key()
    }

    /// Reads the artifact to the end and returns the signature file. `name`
    /// is how verifiers will refer to the artifact.
    pub fn sign(&self, name: &str, artifact: impl Read) -> io::Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before 1970")
            .as_secs() as i64;
        self.sign_at(name, artifact, now)
    }

    /// Like [`Signer::sign`] with an explicit signing time in Unix seconds.
    pub fn sign_at(&self, name: &str, artifact: impl Read, signed: i64) -> io::Result<String> {
        if !valid_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid artifact name {name:?}"),
            ));
        }
        let (size, sha512) = hash(artifact, u64::MAX)?;
        let st = Statement {
            key_id: key_id(&self.verifying_key()),
            name: name.to_owned(),
            size,
            sha512,
            signed,
        };
        let msg = st.encode();
        let sig = self
            .key
            .expanded_key()
            .sign_randomized(msg.as_bytes(), CONTEXT, &mut SysRng)
            .expect("context is under 255 bytes and the system RNG works");
        Ok(format!("{msg}signature: {}\n", STANDARD.encode(sig.encode())))
    }
}

/// Checks signature files against a set of trusted keys.
#[derive(Default)]
pub struct Verifier {
    keys: HashMap<String, VerifyingKey<Params>>,
}

impl Verifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trusts `pk`, keyed by its key ID.
    pub fn add(&mut self, pk: VerifyingKey<Params>) {
        self.keys.insert(key_id(&pk), pk);
    }

    /// Checks `sig_file` and then that `artifact` is the one it signs, under
    /// the name the caller expects.
    pub fn verify(&self, sig_file: &str, name: &str, artifact: impl Read) -> Result<Statement, VerifyError> {
        let (st, msg, sig) = parse(sig_file).ok_or(VerifyError::Malformed)?;
        let pk = self.keys.get(&st.key_id).ok_or(VerifyError::UnknownKey)?;
        if !pk.verify_with_context(msg.as_bytes(), CONTEXT, &sig) {
            return Err(VerifyError::Signature);
        }
        if st.name != name {
            return Err(VerifyError::WrongArtifact);
        }
        // Read at most one byte more than the signed size.
        let (size, sha512) = hash(artifact, st.size.saturating_add(1)).map_err(VerifyError::Io)?;
        if size != st.size || sha512 != st.sha512 {
            return Err(VerifyError::WrongArtifact);
        }
        Ok(st)
    }
}

fn hash(artifact: impl Read, limit: u64) -> io::Result<(u64, Vec<u8>)> {
    let mut ctx = Context::new(&SHA512);
    let mut reader = artifact.take(limit);
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        ctx.update(&buf[..n]);
        size += n as u64;
    }
    Ok((size, ctx.finish().as_ref().to_vec()))
}

/// Splits a signature file strictly. Every field must be in its one
/// canonical spelling, so the signed bytes are exactly what `sign` writes.
fn parse(file: &str) -> Option<(Statement, &str, Signature<Params>)> {
    if file.len() > MAX_SIGNATURE_FILE {
        return None;
    }
    let body = file.strip_suffix('\n')?;
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() != 8 || lines[0] != MAGIC {
        return None;
    }
    let mut fields = Vec::with_capacity(7);
    for (line, key) in lines[1..].iter().zip(FIELDS) {
        fields.push(line.strip_prefix(key)?.strip_prefix(": ")?);
    }
    let key_id = from_hex(fields[1]).filter(|k| k.len() == 32)?;
    let st = Statement {
        key_id: to_hex(&key_id),
        name: fields[2].to_owned(),
        size: fields[3].parse().ok()?,
        sha512: from_hex(fields[4]).filter(|d| d.len() == 64)?,
        signed: parse_time(fields[5])?,
    };
    if fields[0] != ALGORITHM || !valid_name(&st.name) {
        return None;
    }
    let sig = STANDARD.decode(fields[6]).ok()?;
    let sig = Signature::<Params>::try_from(sig.as_slice()).ok()?;
    let msg = &file[..file.len() - lines[7].len() - 1];
    // Reject any field whose spelling is not canonical (leading zeros,
    // upper-case hex, other time zones), so one statement has one encoding.
    (st.encode() == msg).then_some((st, msg, sig))
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// `YYYY-MM-DDTHH:MM:SSZ` for Unix seconds (proleptic Gregorian, UTC).
fn format_time(t: i64) -> String {
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// Parses the form [`format_time`] writes; the caller's round-trip check
/// rejects anything else.
fn parse_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

// Howard Hinnant's civil calendar algorithms.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_round_trip() {
        for t in [0, 1_792_756_800, 951_782_400, 4_102_444_799] {
            assert_eq!(parse_time(&format_time(t)), Some(t), "{}", format_time(t));
        }
        assert_eq!(format_time(1_792_756_800), "2026-10-23T12:00:00Z");
        assert_eq!(format_time(951_782_400), "2000-02-29T00:00:00Z");
    }
}
