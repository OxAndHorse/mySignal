//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Interfaces in [traits] and reference implementations in [inmem] for various mutable stores.

#![warn(missing_docs)]

mod inmem;
mod traits;

pub use inmem::{
    InMemIdentityKeyStore, InMemKyberPreKeyStore, InMemPreKeyStore, InMemSenderKeyStore,
    InMemSessionStore, InMemSignalProtocolStore, InMemSignedPreKeyStore,
};
#[cfg(feature = "tkem1024")]
pub use inmem::InMemTkemStore;
pub use traits::{
    Direction, IdentityChange, IdentityKeyStore, KyberPreKeyStore, PreKeyStore, ProtocolStore,
    SenderKeyStore, SessionStore, SignedPreKeyStore,
};
#[cfg(feature = "tkem1024")]
pub use traits::TkemStore;
