// A per-run CA, the API host's leaf certificate, and the tiny CRL server.
//
// The Windows tool installs its CA in LocalMachine\Root and serves a CRL because Schannel
// checks revocation. The Linux equivalent is a system trust anchor
// (update-ca-certificates / update-ca-trust / trust), and the CRL is kept because the game may
// still be a Windows binary under Wine/Proton with a Schannel-shaped TLS stack.
//
// A CA and leaf use RSA-2048/SHA-256, like the original, so the handshake looks unremarkable.

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use rand::RngCore;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    CrlDistributionPoint, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod,
    KeyPair, KeyUsagePurpose, SerialNumber,
};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

use crate::log::ca_name;

pub struct Material {
    /// Present only when this run manages a CA (the `--no-ca` test mode has a self-signed leaf).
    pub ca_pem: Option<String>,
    /// Leaf first, then its issuer.
    pub chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
    pub crl: Option<Vec<u8>>,
}

fn rsa_key() -> Result<KeyPair> {
    let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
        .context("could not generate an RSA key")?;
    let der = key.to_pkcs8_der()?;
    let pkcs8 = PrivatePkcs8KeyDer::from(der.as_bytes().to_vec());
    KeyPair::try_from(&PrivateKeyDer::Pkcs8(pkcs8)).context("could not load the RSA key")
}

fn ca_certificate(host_url: &str) -> Result<(Certificate, KeyPair)> {
    let key = rsa_key()?;
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, ca_name());
    params
        .distinguished_name
        .push(DnType::OrganizationName, "HellForge");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(1);
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![host_url.to_string()],
    }];
    let certificate = params
        .self_signed(&key)
        .context("could not sign the capture CA")?;
    Ok((certificate, key))
}

fn leaf_certificate(
    host: &str,
    cdp: Option<&str>,
    issuer: Option<(&Certificate, &KeyPair)>,
) -> Result<(Certificate, KeyPair)> {
    let key = rsa_key()?;
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::new(vec![host.to_string()])
        .context("the API host is not a valid certificate name")?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, host.to_string());
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(1);
    // Never past the CA's own end, which was made a moment earlier.
    if let Some((issuer, _)) = issuer {
        if params.not_after > issuer.params().not_after {
            params.not_after = issuer.params().not_after;
        }
    }
    if let Some(url) = cdp {
        params.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![url.to_string()],
        }];
    }
    params.serial_number = Some(SerialNumber::from(rand::random::<u64>()));
    let certificate = match issuer {
        Some((issuer, issuer_key)) => params
            .signed_by(&key, issuer, issuer_key)
            .context("could not sign the API host certificate")?,
        None => params
            .self_signed(&key)
            .context("could not sign the API host certificate")?,
    };
    Ok((certificate, key))
}

fn revocation_list(ca: &Certificate, ca_key: &KeyPair) -> Result<Vec<u8>> {
    let now = OffsetDateTime::now_utc();
    let params = CertificateRevocationListParams {
        this_update: now - Duration::days(1),
        next_update: ca.params().not_after,
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = params
        .signed_by(ca, ca_key)
        .context("could not sign the CRL")?;
    Ok(crl.der().to_vec())
}

/// Builds the certificates. `crl_url` is present exactly when a managed CA was made.
pub fn generate(host: &str, crl_url: Option<&str>) -> Result<Material> {
    if let Some(url) = crl_url {
        let (ca, ca_key) = ca_certificate(url)?;
        let (leaf, leaf_key) = leaf_certificate(host, Some(url), Some((&ca, &ca_key)))?;
        let crl = revocation_list(&ca, &ca_key)?;
        Ok(Material {
            ca_pem: Some(ca.pem()),
            chain: vec![leaf.der().clone(), ca.der().clone()],
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            crl: Some(crl),
        })
    } else {
        let (leaf, leaf_key) = leaf_certificate(host, None, None)?;
        Ok(Material {
            ca_pem: None,
            chain: vec![leaf.der().clone()],
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            crl: None,
        })
    }
}

/// A fresh view of the CA before it is installed: useful for a manual `--ca-out` import.
pub fn write_pem(path: &Path, pem: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    use std::io::Write;
    file.write_all(pem.as_bytes())?;
    Ok(())
}

/// A random path component, so a stale CRL URL from a killed run cannot be confused with this one.
pub fn crl_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The CA's subject CN, for diagnostics.
pub fn describe_material(material: &Material) -> String {
    format!(
        "{} certificate(s) in the chain, CRL {}",
        material.chain.len(),
        if material.crl.is_some() { "yes" } else { "no" }
    )
}
