// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

#[cfg(feature = "device")]
pub mod device;

#[cfg(feature = "ffi-bindings")]
pub mod ffi;
#[cfg(feature = "jni-bindings")]
pub mod jni;
pub mod noise;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

pub(crate) mod serialization;

pub mod x25519 {
    use wolfssl_wolfcrypt::curve25519::Curve25519Key;
    use wolfssl_wolfcrypt::random::RNG;

    pub use x25519_dalek::{
        PublicKey, StaticSecret,
    };

    pub fn dh_generate() -> [u8; 32] {
        let mut rng = RNG::new().unwrap();
        let mut curve25519key = Curve25519Key::generate(&mut rng).unwrap();
        let mut bytes = [0u8; 32];
        curve25519key.export_private_raw_ex(&mut bytes, false).unwrap();
        bytes
    }

    pub fn dh_make_pub(private: &[u8]) -> [u8; 32] {
        let mut public = [0u8; 32];
        Curve25519Key::make_pub(private, &mut public).unwrap();
        public
    }
}
