//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::clone::Clone;

use crate::state::{PreKeyId, SignedPreKeyId};
use crate::{kem, DeviceId, IdentityKey, KyberPreKeyId, PublicKey, Result, SignalProtocolError};
#[cfg(feature = "tkem1024")]
use rand::TryRngCore as _;

#[derive(Clone)]
struct SignedPreKey {
    id: SignedPreKeyId,
    public_key: PublicKey,
    signature: Vec<u8>,
}

impl SignedPreKey {
    fn new(id: SignedPreKeyId, public_key: PublicKey, signature: Vec<u8>) -> Self {
        Self {
            id,
            public_key,
            signature,
        }
    }
}

#[derive(Clone)]
struct KyberPreKey {
    id: KyberPreKeyId,
    public_key: kem::PublicKey,
    signature: Vec<u8>,
}

impl KyberPreKey {
    fn new(id: KyberPreKeyId, public_key: kem::PublicKey, signature: Vec<u8>) -> Self {
        Self {
            id,
            public_key,
            signature,
        }
    }
}

#[cfg(feature = "tkem1024")]
#[derive(Clone)]
pub struct TkemMasterKey {
    id: u32,
    public_key: kem::TagPublicKey,
    signature: Vec<u8>,
}

#[cfg(feature = "tkem1024")]
impl TkemMasterKey {
    fn new(id: u32, public_key: kem::TagPublicKey, signature: Vec<u8>) -> Self {
        Self {
            id,
            public_key,
            signature,
        }
    }
}

// Represents the raw contents of the pre-key bundle without any notion of required/optional
// fields.
// Can be used as a "builder" for PreKeyBundle, in which case all the validation will happen in
// PreKeyBundle::new.
pub struct PreKeyBundleContent {
    pub registration_id: Option<u32>,
    pub device_id: Option<DeviceId>,
    pub pre_key_id: Option<PreKeyId>,
    pub pre_key_public: Option<PublicKey>,
    pub signed_pre_key_id: Option<SignedPreKeyId>,
    pub signed_pre_key_public: Option<PublicKey>,
    pub signed_pre_key_signature: Option<Vec<u8>>,
    pub identity_key: Option<IdentityKey>,
    pub kyber_pre_key_id: Option<KyberPreKeyId>,
    pub kyber_pre_key_public: Option<kem::PublicKey>,
    pub kyber_pre_key_signature: Option<Vec<u8>>,
    #[cfg(feature = "tkem1024")]
    pub tkem_master_key_id: Option<u32>,
    #[cfg(feature = "tkem1024")]
    pub tkem_master_key_public: Option<kem::TagPublicKey>,
    #[cfg(feature = "tkem1024")]
    pub tkem_master_key_signature: Option<Vec<u8>>,
}

impl From<PreKeyBundle> for PreKeyBundleContent {
    fn from(bundle: PreKeyBundle) -> Self {
        Self {
            registration_id: Some(bundle.registration_id),
            device_id: Some(bundle.device_id),
            pre_key_id: bundle.pre_key_id,
            pre_key_public: bundle.pre_key_public,
            signed_pre_key_id: Some(bundle.ec_signed_pre_key.id),
            signed_pre_key_public: Some(bundle.ec_signed_pre_key.public_key),
            signed_pre_key_signature: Some(bundle.ec_signed_pre_key.signature),
            identity_key: Some(bundle.identity_key),
            kyber_pre_key_id: Some(bundle.kyber_pre_key.id),
            kyber_pre_key_public: Some(bundle.kyber_pre_key.public_key),
            kyber_pre_key_signature: Some(bundle.kyber_pre_key.signature),
            #[cfg(feature = "tkem1024")]
            tkem_master_key_id: bundle.tkem_master_key.as_ref().map(|k| k.id),
            #[cfg(feature = "tkem1024")]
            tkem_master_key_public: bundle.tkem_master_key.as_ref().map(|k| k.public_key.clone()),
            #[cfg(feature = "tkem1024")]
            tkem_master_key_signature: bundle.tkem_master_key.as_ref().map(|k| k.signature.clone()),
        }
    }
}

impl TryFrom<PreKeyBundleContent> for PreKeyBundle {
    type Error = SignalProtocolError;

    fn try_from(content: PreKeyBundleContent) -> Result<Self> {
        PreKeyBundle::new(
            content.registration_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("registration_id is required".to_string())
            })?,
            content.device_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("device_id is required".to_string())
            })?,
            content
                .pre_key_id
                .and_then(|id| content.pre_key_public.map(|public| (id, public))),
            content.signed_pre_key_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("signed_pre_key_id is required".to_string())
            })?,
            content.signed_pre_key_public.ok_or_else(|| {
                SignalProtocolError::InvalidArgument(
                    "signed_pre_key_public is required".to_string(),
                )
            })?,
            content.signed_pre_key_signature.ok_or_else(|| {
                SignalProtocolError::InvalidArgument(
                    "signed_pre_key_signature is required".to_string(),
                )
            })?,
            content.kyber_pre_key_id.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("kyber_pre_key_id is required".to_string())
            })?,
            content.kyber_pre_key_public.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("kyber_pre_key_public is required".to_string())
            })?,
            content.kyber_pre_key_signature.ok_or_else(|| {
                SignalProtocolError::InvalidArgument(
                    "kyber_pre_key_signature is required".to_string(),
                )
            })?,
            content.identity_key.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("identity_key is required".to_string())
            })?,
        )
    }
}

#[derive(Clone)]
pub struct PreKeyBundle {
    registration_id: u32,
    device_id: DeviceId,
    pre_key_id: Option<PreKeyId>,
    pre_key_public: Option<PublicKey>,
    ec_signed_pre_key: SignedPreKey,
    identity_key: IdentityKey,
    kyber_pre_key: KyberPreKey,
    #[cfg(feature = "tkem1024")]
    tkem_master_key: Option<TkemMasterKey>,
}

impl PreKeyBundle {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        registration_id: u32,
        device_id: DeviceId,
        pre_key: Option<(PreKeyId, PublicKey)>,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: Vec<u8>,
        kyber_pre_key_id: KyberPreKeyId,
        kyber_pre_key_public: kem::PublicKey,
        kyber_pre_key_signature: Vec<u8>,
        identity_key: IdentityKey,
    ) -> Result<Self> {
        let (pre_key_id, pre_key_public) = match pre_key {
            None => (None, None),
            Some((id, key)) => (Some(id), Some(key)),
        };

        let ec_signed_pre_key = SignedPreKey::new(
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
        );

        let kyber_pre_key = KyberPreKey::new(
            kyber_pre_key_id,
            kyber_pre_key_public,
            kyber_pre_key_signature,
        );

        Ok(Self {
            registration_id,
            device_id,
            pre_key_id,
            pre_key_public,
            ec_signed_pre_key,
            identity_key,
            kyber_pre_key,
            #[cfg(feature = "tkem1024")]
            tkem_master_key: None,
        })
    }

    #[cfg(feature = "tkem1024")]
    #[expect(clippy::too_many_arguments)]
    pub fn new_with_tkem(
        registration_id: u32,
        device_id: DeviceId,
        pre_key: Option<(PreKeyId, PublicKey)>,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: Vec<u8>,
        tkem_master_key_id: u32,
        tkem_master_key_public: kem::TagPublicKey,
        tkem_master_key_signature: Vec<u8>,
        identity_key: IdentityKey,
    ) -> Result<Self> {
        let (pre_key_id, pre_key_public) = match pre_key {
            None => (None, None),
            Some((id, key)) => (Some(id), Some(key)),
        };

        let ec_signed_pre_key = SignedPreKey::new(
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
        );

        // Dummy kyber pre key to satisfy the struct
        let dummy_kyber_id = 0.into();
        let mut csprng = rand::rngs::OsRng.unwrap_err();
        let dummy_kyber_public =
            kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng).public_key;
        let kyber_pre_key = KyberPreKey::new(dummy_kyber_id, dummy_kyber_public, vec![]);

        let tkem_master_key = TkemMasterKey::new(
            tkem_master_key_id,
            tkem_master_key_public,
            tkem_master_key_signature,
        );

        Ok(Self {
            registration_id,
            device_id,
            pre_key_id,
            pre_key_public,
            ec_signed_pre_key,
            identity_key,
            kyber_pre_key,
            tkem_master_key: Some(tkem_master_key),
        })
    }

    pub fn registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    pub fn device_id(&self) -> Result<DeviceId> {
        Ok(self.device_id)
    }

    pub fn pre_key_id(&self) -> Result<Option<PreKeyId>> {
        Ok(self.pre_key_id)
    }

    pub fn pre_key_public(&self) -> Result<Option<PublicKey>> {
        Ok(self.pre_key_public)
    }

    pub fn signed_pre_key_id(&self) -> Result<SignedPreKeyId> {
        Ok(self.ec_signed_pre_key.id)
    }

    pub fn signed_pre_key_public(&self) -> Result<PublicKey> {
        Ok(self.ec_signed_pre_key.public_key)
    }

    pub fn signed_pre_key_signature(&self) -> Result<&[u8]> {
        Ok(self.ec_signed_pre_key.signature.as_ref())
    }

    pub fn identity_key(&self) -> Result<&IdentityKey> {
        Ok(&self.identity_key)
    }

    pub fn kyber_pre_key_id(&self) -> Result<KyberPreKeyId> {
        Ok(self.kyber_pre_key.id)
    }

    pub fn kyber_pre_key_public(&self) -> Result<&kem::PublicKey> {
        Ok(&self.kyber_pre_key.public_key)
    }

    pub fn kyber_pre_key_signature(&self) -> Result<&[u8]> {
        Ok(&self.kyber_pre_key.signature)
    }

    #[cfg(feature = "tkem1024")]
    pub fn tkem_master_key_id(&self) -> Result<Option<u32>> {
        Ok(self.tkem_master_key.as_ref().map(|k| k.id))
    }

    #[cfg(feature = "tkem1024")]
    pub fn tkem_master_key_public(&self) -> Result<Option<&kem::TagPublicKey>> {
        Ok(self.tkem_master_key.as_ref().map(|k| &k.public_key))
    }

    #[cfg(feature = "tkem1024")]
    pub fn tkem_master_key_signature(&self) -> Result<Option<&[u8]>> {
        Ok(self.tkem_master_key.as_ref().map(|k| k.signature.as_ref()))
    }

    pub fn modify<F>(self, modify: F) -> Result<Self>
    where
        F: FnOnce(&mut PreKeyBundleContent),
    {
        let mut content = self.into();
        modify(&mut content);
        content.try_into()
    }
}
