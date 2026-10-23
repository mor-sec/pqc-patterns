use std::collections::HashSet;
use std::io::{self, Read, Write};

use sym_03_streaming_encryption::{Error, HEADER_SIZE, SEGMENT_SIZE, TAG_SIZE, decrypt, encrypt, new_key};

const SEG: usize = SEGMENT_SIZE;

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn seal(key: &[u8], pt: &[u8], ad: &[u8]) -> Vec<u8> {
    let mut ct = Vec::new();
    encrypt(pt, &mut ct, key, ad).unwrap();
    ct
}

fn open(ct: &[u8], key: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
    let mut pt = Vec::new();
    decrypt(ct, &mut pt, key, ad).map(|_| pt)
}

fn rejected(r: Result<Vec<u8>, Error>) -> bool {
    matches!(r, Err(Error::Decrypt))
}

#[test]
fn round_trip() {
    let key = new_key();
    let ad = b"backups/2026-10-23.tar";
    for n in [0, 1, SEG - 1, SEG, SEG + 1, 3 * SEG, 3 * SEG + 7] {
        let pt = pattern(n);
        let ct = seal(&key, &pt, ad);
        let segments = n.div_ceil(SEG).max(1);
        assert_eq!(ct.len(), HEADER_SIZE + n + segments * TAG_SIZE, "size {n}");
        assert_eq!(open(&ct, &key, ad).unwrap(), pt, "size {n}");
    }
}

/// Returns at most one byte per read, like a slow network peer.
struct OneByte<R>(R);

impl<R: Read> Read for OneByte<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let end = buf.len().min(1);
        self.0.read(&mut buf[..end])
    }
}

#[test]
fn short_reads() {
    let key = new_key();
    let pt = pattern(2 * SEG + 3);
    let mut ct = Vec::new();
    encrypt(OneByte(&pt[..]), &mut ct, &key, b"").unwrap();
    let mut out = Vec::new();
    decrypt(OneByte(&ct[..]), &mut out, &key, b"").unwrap();
    assert_eq!(out, pt);
}

#[test]
fn rejects_truncation() {
    let key = new_key();
    for n in [SEG, 2 * SEG, 2 * SEG + 5] {
        let ct = seal(&key, &pattern(n), b"");
        let final_len = (n - 1) % SEG + 1 + TAG_SIZE;
        for cut in [final_len, 1, SEG + TAG_SIZE, ct.len() - HEADER_SIZE + 1, ct.len()] {
            if cut > ct.len() {
                continue;
            }
            assert!(
                rejected(open(&ct[..ct.len() - cut], &key, b"")),
                "size {n}: removing {cut} bytes not detected"
            );
        }
    }
}

#[test]
fn rejects_appended_data() {
    let key = new_key();
    for n in [0, 5, SEG] {
        let ct = seal(&key, &pattern(n), b"");
        for extra in [1, TAG_SIZE, SEG + TAG_SIZE] {
            let mut bad = ct.clone();
            bad.extend(vec![0u8; extra]);
            assert!(
                rejected(open(&bad, &key, b"")),
                "size {n}: {extra} appended bytes not detected"
            );
        }
    }
    let mut joined = seal(&key, &pattern(SEG), b"");
    joined.extend_from_slice(&seal(&key, &pattern(SEG), b"")[HEADER_SIZE..]);
    assert!(
        rejected(open(&joined, &key, b"")),
        "concatenated streams accepted"
    );
}

#[test]
fn rejects_reordered_segments() {
    let key = new_key();
    let ct = seal(&key, &pattern(3 * SEG), b"");
    let s = SEG + TAG_SIZE;
    let mut swapped = ct.clone();
    swapped[HEADER_SIZE..HEADER_SIZE + s].copy_from_slice(&ct[HEADER_SIZE + s..HEADER_SIZE + 2 * s]);
    swapped[HEADER_SIZE + s..HEADER_SIZE + 2 * s].copy_from_slice(&ct[HEADER_SIZE..HEADER_SIZE + s]);
    assert!(rejected(open(&swapped, &key, b"")));
}

#[test]
fn rejects_tampering() {
    let key = new_key();
    let ad = b"uploads/42";
    let ct = seal(&key, &pattern(100), ad);
    for i in 0..ct.len() {
        let mut bad = ct.clone();
        bad[i] ^= 1;
        assert!(rejected(open(&bad, &key, ad)), "flipping byte {i} not detected");
    }
    assert!(rejected(open(&ct, &key, b"uploads/43")));
    assert!(rejected(open(&ct, &new_key(), ad)));
    assert!(rejected(open(&[], &key, ad)));
}

#[test]
fn rejects_short_key() {
    let r = encrypt(&b""[..], io::sink(), &[0u8; 16], b"");
    assert!(matches!(r, Err(Error::KeyLength(16))));
}

#[test]
fn headers_are_unique() {
    let key = new_key();
    let mut seen = HashSet::new();
    for _ in 0..1000 {
        assert!(
            seen.insert(seal(&key, b"", b"")[..HEADER_SIZE].to_vec()),
            "header reused"
        );
    }
}

struct DiskFull;

impl Write for DiskFull {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("disk full"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn passes_through_io_errors() {
    let key = new_key();
    let ct = seal(&key, b"x", b"");
    assert!(matches!(decrypt(&ct[..], DiskFull, &key, b""), Err(Error::Io(_))));
}
