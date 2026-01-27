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
    use wolfssl_wolfcrypt::ecc::ECC;
    use wolfssl_wolfcrypt::random::RNG;

    pub fn dh_generate() -> [u8; 32] {
        let mut rng = RNG::new().unwrap();
        let mut ecc = ECC::generate(32, &mut rng, None, None).unwrap();
        let mut bytes = [0u8; 32];
        ecc.export_private(&mut bytes).unwrap();
        bytes
    }

    pub fn dh_make_pub(private: &[u8]) -> [u8; 65] {
        let mut ecc_private = ECC::import_private_key_ex(private, &[], ECC::SECP256R1, None, None).unwrap();
        let mut rng = RNG::new().unwrap();
        ecc_private.make_pub(Some(&mut rng)).unwrap();
        let mut public = [0u8; 65];
        let size = ecc_private.export_x963(&mut public).unwrap();
        assert_eq!(size, 65);
        public
    }
}
