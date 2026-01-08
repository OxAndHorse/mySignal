use libcrux_ml_tkem::mlkem1024::{
    MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey,
};
use libcrux_ml_tkem::{kyber1024_with_tag, MlKemCiphertext, SHARED_SECRET_SIZE};
use rand::{CryptoRng, Rng as _};


use super::{
    BadKEMKeyLength, ConstantLength as _, DecapsulateError, KeyMaterial,TagKeyType, Public, Secret,
};
pub(crate) struct TagParameters;

impl super::TagParameters for TagParameters {
    const KEY_TYPE: TagKeyType = TagKeyType::TKyber1024;
    const PUBLIC_KEY_LENGTH: usize = MlKem1024Ciphertext::LENGTH;
    const SECRET_KEY_LENGTH: usize = MlKem1024PrivateKey::LENGTH;
    const CIPHERTEXT_LENGTH: usize = MlKem1024PublicKey::LENGTH;
    const SHARED_SECRET_LENGTH: usize = SHARED_SECRET_SIZE;


    fn generate<R: CryptoRng + ?Sized>(
        csprng: &mut R,
    ) -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        let (sk, pk) = kyber1024_with_tag::generate_key_pair1(csprng.random()).into_parts();
        (KeyMaterial::from(pk), KeyMaterial::from(sk))
    }

    fn encapsulate_with_tag<R: CryptoRng + ?Sized>(
            pub_key: &KeyMaterial<Public>,
            csprng: &mut R,
            tag:&[u8],
        ) -> std::result::Result<(super::SharedSecret, super::RawCiphertext), BadKEMKeyLength> {
        let kyber_pk =
        MlKem1024PublicKey::try_from(pub_key.as_ref()).map_err(|_| BadKEMKeyLength)?;
        let (kyber_ct, kyber_ss) = kyber1024_with_tag::encapsulate_with_tag(&kyber_pk, csprng.random(),tag);
        Ok((kyber_ss.as_ref().into(), kyber_ct.as_ref().into()))
    }

    fn decapsulate_with_tag(
            secret_key: &KeyMaterial<Secret>,
            ciphertext: &[u8],
            tag:&[u8],
        ) -> std::result::Result<super::SharedSecret, DecapsulateError> {
        let kyber_sk = MlKem1024PrivateKey::try_from(secret_key.as_ref())
        .map_err(|_| DecapsulateError::BadKeyLength)?;
        let kyber_ct =
            MlKemCiphertext::try_from(ciphertext).map_err(|_| DecapsulateError::BadCiphertext)?;
        let kyber_ss = kyber1024_with_tag::decapsulate_with_tag(&kyber_sk, &kyber_ct,tag);

        Ok(kyber_ss.as_ref().into())
    }
}