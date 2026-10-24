fn kx(pk: &RsaPublicKey, secret: EphemeralSecret, peer: &PublicKey) {
    // ruleid: pqc-kx-rsa-encrypt
    pk.encrypt(&mut rng, Oaep::new::<Sha256>(), b"k");
    // ruleid: pqc-kx-classical-ecdh
    let shared = secret.diffie_hellman(peer);
    // ruleid: pqc-kx-classical-ecdh
    let h = Hpke::<HpkeLibcrux>::new(Mode::Base, KemAlgorithm::DhKem25519, KdfAlgorithm::HkdfSha256, AeadAlgorithm::Aes256Gcm);
    // ok: pqc-kx-classical-ecdh
    let h = Hpke::<HpkeLibcrux>::new(Mode::Base, KemAlgorithm::XWingDraft06, KdfAlgorithm::HkdfSha256, AeadAlgorithm::Aes256Gcm);
}

fn sigs(sk: &SigningKey<MlDsa65>, vk: &VerifyingKey<MlDsa65>, msg: &[u8], sig: &Signature<MlDsa65>) {
    // ruleid: pqc-sig-classical-keygen
    let k = RsaPrivateKey::new(&mut rng, 3072);
    // ruleid: pqc-sig-classical-keygen
    let k = Ed25519KeyPair::generate_pkcs8(&rng);
    // ruleid: pqc-sig-classical-keygen
    let k = p256::ecdsa::SigningKey::random(&mut rng);
    // ok: pqc-sig-classical-keygen
    let k = SigningKey::<MlDsa65>::from_seed(&seed);

    // ruleid: pqc-sig-mldsa-no-context
    sk.sign_deterministic(msg, b"");
    // ruleid: pqc-sig-mldsa-no-context
    vk.verify_with_context(msg, b"", sig);
    // ok: pqc-sig-mldsa-no-context
    sk.sign_deterministic(msg, b"app/v1");
}

fn sym() {
    // ruleid: pqc-sym-unauthenticated-mode
    let c = cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into());
    // ruleid: pqc-sym-unauthenticated-mode
    let c = EncryptingKey::ctr(key);
    // ruleid: pqc-sym-aes-128
    let k = UnboundKey::new(&AES_128_GCM, &key);
    // ok: pqc-sym-aes-128
    let k = UnboundKey::new(&AES_256_GCM, &key);
    // ruleid: pqc-sym-static-nonce
    let n = Nonce::assume_unique_for_key([0u8; 12]);
    // ok: pqc-sym-static-nonce
    let n = Nonce::assume_unique_for_key(nonce);
    // ruleid: pqc-sym-static-nonce
    let n = aws_lc_rs::aead::Nonce::assume_unique_for_key([0u8; 12]);
    let zero = [0u8; 12];
    // ruleid: pqc-sym-static-nonce
    let n = Nonce::assume_unique_for_key(zero);
    let mut fresh = [0u8; 12];
    rng.fill(&mut fresh).unwrap();
    // ok: pqc-sym-static-nonce
    let n = Nonce::assume_unique_for_key(fresh);
    let mut counter = [0u8; 12];
    counter[..7].copy_from_slice(&prefix);
    counter[11] = last as u8;
    // ok: pqc-sym-static-nonce
    let n = Nonce::assume_unique_for_key(counter);
    let mut indexed = [0u8; 12];
    indexed[11] = 1;
    // ok: pqc-sym-static-nonce
    let n = Nonce::assume_unique_for_key(indexed);
}

fn tls() {
    // ruleid: pqc-tls-classical-groups
    let p = CryptoProvider { kx_groups: vec![kx_group::X25519, kx_group::SECP256R1], ..aws_lc_rs::default_provider() };
    // ok: pqc-tls-classical-groups
    let p = CryptoProvider { kx_groups: vec![kx_group::X25519MLKEM768, kx_group::X25519], ..aws_lc_rs::default_provider() };
    // ruleid: pqc-tls-min-version
    let b = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13]);
    // ok: pqc-tls-min-version
    let b = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    // ruleid: pqc-tls-no-verify
    cfg.dangerous().set_certificate_verifier(Arc::new(NoVerifier));
    // ruleid: pqc-tls-no-verify
    let c = reqwest::Client::builder().danger_accept_invalid_certs(true);
}

fn hashes(data: &[u8]) {
    // ruleid: pqc-hash-weak
    let d = md5::compute(data);
    // ruleid: pqc-hash-weak
    let h = Sha1::new();
    // ok: pqc-hash-weak
    let h = Sha256::new();
}
