use bytes::Bytes;
use xirtam_crypt::aead::AeadKey;
use xirtam_crypt::dh::{DhPublic, DhSecret};

pub fn envelope_encrypt(to: &DhPublic, msg: &[u8]) -> Bytes {
    let eph_sk = DhSecret::random();
    let ss = eph_sk.diffie_hellman(to);
    bcs::to_bytes(&(
        eph_sk.public_key(),
        AeadKey::from_bytes(ss)
            .encrypt(Default::default(), msg, &[])
            .unwrap(),
    ))
    .unwrap()
    .into()
}

pub fn envelope_decrypt(my_sk: &DhSecret, envelope: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (eph_pk, ct): (DhPublic, Vec<u8>) = bcs::from_bytes(envelope)?;
    let ss = my_sk.diffie_hellman(&eph_pk);
    // Decrypt with the same AEAD parameters used in encrypt()
    let pt = AeadKey::from_bytes(ss).decrypt(Default::default(), &ct, &[])?;
    Ok(pt)
}
