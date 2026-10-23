//! Pattern HASH-03: storing passwords with Argon2id (RFC 9106) in the PHC
//! string format `$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>`,
//! with a fresh 16-byte salt per password, a constant-time comparison, and a
//! signal to re-hash when the stored parameters are older than the current
//! ones.

use argon2::{Algorithm, Argon2, Version};
use base64ct::{Base64Unpadded, Encoding};
use subtle::ConstantTimeEq;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub memory_kib: u32,
    pub time: u32,
    pub threads: u32,
}

/// RFC 9106's second recommended option: 64 MiB, 3 passes, 4 lanes. Tune
/// `time` upwards until hashing takes about 0.5 s on your servers, but never
/// go below OWASP's floor of 19 MiB and 2 passes.
pub const DEFAULT: Params = Params {
    memory_kib: 64 * 1024,
    time: 3,
    threads: 4,
};

const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
// Bounds for stored parameters, so a corrupt or hostile database row cannot
// make verify allocate gigabytes.
const MAX_MEMORY_KIB: u32 = 1 << 20;
const MAX_TIME: u32 = 16;
const MAX_THREADS: u32 = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Mismatch,
    Format,
}

impl Params {
    fn valid(&self) -> bool {
        (1..=MAX_THREADS).contains(&self.threads)
            && (1..=MAX_TIME).contains(&self.time)
            && self.memory_kib >= 8 * self.threads
            && self.memory_kib <= MAX_MEMORY_KIB
    }

    fn argon2(&self) -> Result<Argon2<'static>, Error> {
        let p = argon2::Params::new(self.memory_kib, self.time, self.threads, Some(HASH_LEN))
            .map_err(|_| Error::Format)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, p))
    }
}

/// Returns a PHC string for `password` under `p`.
pub fn hash(password: &[u8], p: Params) -> Result<String, Error> {
    if !p.valid() {
        return Err(Error::Format);
    }
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).expect("system RNG failed");
    let mut out = [0u8; HASH_LEN];
    p.argon2()?
        .hash_password_into(password, &salt, &mut out)
        .map_err(|_| Error::Format)?;
    Ok(format!(
        "$argon2id$v=19$m={},t={},p={}${}${}",
        p.memory_kib,
        p.time,
        p.threads,
        Base64Unpadded::encode_string(&salt),
        Base64Unpadded::encode_string(&out)
    ))
}

/// Checks `password` against a stored PHC string. On success, returns
/// whether the hash should be replaced because its parameters differ from
/// `current`; re-hash and store the new value while you have the plaintext.
pub fn verify(password: &[u8], stored: &str, current: Params) -> Result<bool, Error> {
    let (p, salt, want) = parse(stored)?;
    let mut got = [0u8; HASH_LEN];
    p.argon2()?
        .hash_password_into(password, &salt, &mut got)
        .map_err(|_| Error::Format)?;
    if bool::from(got.ct_eq(&want[..])) {
        Ok(p != current)
    } else {
        Err(Error::Mismatch)
    }
}

/// Accepts only the canonical form `hash` writes: argon2id, version 19,
/// parameters in m,t,p order without leading zeros, unpadded base64, a salt
/// of at least 16 bytes and a 32-byte hash.
fn parse(s: &str) -> Result<(Params, Vec<u8>, Vec<u8>), Error> {
    let f: Vec<&str> = s.split('$').collect();
    let ["", "argon2id", "v=19", params, salt, hash] = f[..] else {
        return Err(Error::Format);
    };
    let kv: Vec<&str> = params.split(',').collect();
    let [m, t, p] = kv[..] else {
        return Err(Error::Format);
    };
    let num = |field: &str, name: &str| -> Result<u32, Error> {
        let n = field.strip_prefix(name).ok_or(Error::Format)?;
        let v: u32 = n.parse().map_err(|_| Error::Format)?;
        if v.to_string() != n {
            return Err(Error::Format);
        }
        Ok(v)
    };
    let p = Params {
        memory_kib: num(m, "m=")?,
        time: num(t, "t=")?,
        threads: num(p, "p=")?,
    };
    let salt = Base64Unpadded::decode_vec(salt).map_err(|_| Error::Format)?;
    let hash = Base64Unpadded::decode_vec(hash).map_err(|_| Error::Format)?;
    if !p.valid() || salt.len() < SALT_LEN || hash.len() != HASH_LEN {
        return Err(Error::Format);
    }
    Ok((p, salt, hash))
}
