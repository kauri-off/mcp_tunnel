use md5::compute;
use rsa::{pkcs1::EncodeRsaPublicKey, RsaPublicKey};

pub fn fingerprint_md5(public_key: &RsaPublicKey) -> anyhow::Result<String> {
    let binding = public_key.to_pkcs1_der()?;
    let der = binding.as_bytes();

    let hash = compute(der);

    let fingerprint = hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");

    Ok(fingerprint)
}
