// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{HandshakeInit, HandshakeResponse, PacketCookieReply};
use crate::noise::errors::WireGuardError;
use crate::noise::session::Session;
#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;
use crate::x25519;
use std::convert::TryInto;
use std::time::{Duration, SystemTime};
use wolfssl_wolfcrypt::aes::GCM;
use wolfssl_wolfcrypt::ecc::ECC;
use wolfssl_wolfcrypt::hmac::HMAC;
use wolfssl_wolfcrypt::sha::SHA256;

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;

pub(crate) const LABEL_MAC1: &[u8; 8] = b"mac1----";
pub(crate) const LABEL_COOKIE: &[u8; 8] = b"cookie--";
pub(crate) const PRIVATE_KEY_LEN: usize = 32;
pub(crate) const PUBLIC_KEY_LEN: usize = 65;
pub(crate) const TIMESTAMP_LEN: usize = 12;
pub(crate) const HASH_LEN: usize = SHA256::DIGEST_SIZE;
pub(crate) const SHARED_SECRET_KEY_LEN: usize = 32;

// CONSTRUCTION = "Noise_IKpsk2_SECP256R1_AesGcm_SHA256"
// initiator.chaining_key = HASH(CONSTRUCTION)
const INITIAL_CHAIN_KEY: [u8; HASH_LEN] = [
    0x08, 0x2D, 0xAF, 0xE0, 0xB1, 0x9F, 0xEE, 0x70,
    0x6A, 0x69, 0xF2, 0xB9, 0x5C, 0xA6, 0xE1, 0x36,
    0x9F, 0xAB, 0xD5, 0x36, 0x5F, 0x0E, 0x91, 0x62,
    0x25, 0x74, 0x73, 0x5B, 0x7F, 0x24, 0xBE, 0x48,
];

// IDENTIFIER = "WolfGuard v1 info@wolfssl.com"
// initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER)
const INITIAL_CHAIN_HASH: [u8; HASH_LEN] = [
    0x05, 0xB6, 0x88, 0xC3, 0xB9, 0x6E, 0xC7, 0x79,
    0x40, 0x77, 0x80, 0xBA, 0xEC, 0xBF, 0x19, 0x8E,
    0x39, 0xA1, 0x3D, 0x2C, 0x42, 0x74, 0x45, 0xEF,
    0x28, 0x39, 0xCB, 0x5E, 0x21, 0x1B, 0x6A, 0x00,
];

#[inline]
pub(crate) fn sha256_hash(data1: &[u8], data2: &[u8]) -> [u8; 32] {
    let mut hash = SHA256::new().unwrap();
    hash.update(data1).unwrap();
    hash.update(data2).unwrap();
    let mut output = [0u8; 32];
    hash.finalize(&mut output).unwrap();
    output
}

#[inline]
/// HMAC-SHA256
fn sha256_hmac(key: &[u8], data1: &[u8]) -> [u8; 32] {
    let mut mac = [0u8; 32];
    let mut hmac = HMAC::new(HMAC::TYPE_SHA256, key).unwrap();
    hmac.update(data1).unwrap();
    hmac.finalize(&mut mac).unwrap();
    mac
}

#[inline]
/// Like sha256_hmac, but chain data1 and data2 together
fn sha256_hmac2(key: &[u8], data1: &[u8], data2: &[u8]) -> [u8; 32] {
    let mut mac = [0u8; 32];
    let mut hmac = HMAC::new(HMAC::TYPE_SHA256, key).unwrap();
    hmac.update(data1).unwrap();
    hmac.update(data2).unwrap();
    hmac.finalize(&mut mac).unwrap();
    mac
}

#[inline]
/// 32-byte MAC using HMAC-SHA256
pub(crate) fn hmac_sha256_mac_32(key: &[u8], data1: &[u8]) -> [u8; 32] {
    let mut mac = [0u8; 32];
    let mut hmac = HMAC::new(HMAC::TYPE_SHA256, key).unwrap();
    hmac.update(data1).unwrap();
    hmac.finalize(&mut mac).unwrap();
    mac
}

#[inline]
/// 32-byte MAC using HMAC-SHA256 with two data inputs chained
pub(crate) fn hmac_sha256_mac_32_2(key: &[u8], data1: &[u8], data2: &[u8]) -> [u8; 32] {
    let mut mac = [0u8; 32];
    let mut hmac = HMAC::new(HMAC::TYPE_SHA256, key).unwrap();
    hmac.update(data1).unwrap();
    hmac.update(data2).unwrap();
    hmac.finalize(&mut mac).unwrap();
    mac
}

/// 16-byte MAC using HMAC-SHA256 (truncated)
pub(crate) fn hmac_sha256_mac_16(key: &[u8], data1: &[u8]) -> [u8; 16] {
    let mut full_mac = [0u8; 32];
    let mut hmac = HMAC::new(HMAC::TYPE_SHA256, key).unwrap();
    hmac.update(data1).unwrap();
    hmac.finalize(&mut full_mac).unwrap();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&full_mac[..16]);
    hash
}

#[inline]
/// This wrapper involves an extra copy and MAY BE SLOWER
fn aead_aes_gcm_seal(ciphertext: &mut [u8], key: &[u8], counter: u64, data: &[u8], aad: &[u8]) {
    let mut nonce: [u8; 16] = [0; 16];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());

    aead_aes_gcm_seal_inner(ciphertext, key, nonce, data, aad)
}

#[inline]
fn aead_aes_gcm_seal_inner(
    ciphertext: &mut [u8],
    key: &[u8],
    nonce: [u8; 16],
    data: &[u8],
    aad: &[u8],
) {
    let (cipher_out, tag_out) = ciphertext.split_at_mut(data.len());
    let mut gcm = GCM::new().unwrap();
    gcm.init(key).unwrap();
    gcm.encrypt(data, cipher_out, &nonce, aad, tag_out).unwrap();
}

#[inline]
/// This wrapper involves an extra copy and MAY BE SLOWER
fn aead_aes_gcm_open(
    buffer: &mut [u8],
    key: &[u8],
    counter: u64,
    data: &[u8],
    aad: &[u8],
) -> Result<(), WireGuardError> {
    let mut nonce: [u8; 16] = [0; 16];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());

    let mut gcm = GCM::new().map_err(|_| WireGuardError::InvalidAeadTag)?;
    gcm.init(key).map_err(|_| WireGuardError::InvalidAeadTag)?;
    gcm.decrypt(&data[..data.len()-16], buffer, &nonce, aad, &data[data.len()-16..])
        .map_err(|_| WireGuardError::InvalidAeadTag)?;
    Ok(())
}

#[derive(Debug)]
/// This struct represents a 12 byte [Tai64N](https://cr.yp.to/libtai/tai64.html) timestamp
struct Tai64N {
    secs: u64,
    nano: u32,
}

#[derive(Debug)]
/// This struct computes a [Tai64N](https://cr.yp.to/libtai/tai64.html) timestamp from current system time
struct TimeStamper {
    duration_at_start: Duration,
    instant_at_start: Instant,
}

impl TimeStamper {
    /// Create a new TimeStamper
    pub fn new() -> TimeStamper {
        TimeStamper {
            duration_at_start: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
            instant_at_start: Instant::now(),
        }
    }

    /// Take time reading and generate a 12 byte timestamp
    pub fn stamp(&self) -> [u8; 12] {
        const TAI64_BASE: u64 = (1u64 << 62) + 37;
        let mut ext_stamp = [0u8; 12];
        let stamp = Instant::now().duration_since(self.instant_at_start) + self.duration_at_start;
        ext_stamp[0..8].copy_from_slice(&(stamp.as_secs() + TAI64_BASE).to_be_bytes());
        ext_stamp[8..12].copy_from_slice(&stamp.subsec_nanos().to_be_bytes());
        ext_stamp
    }
}

impl Tai64N {
    /// A zeroed out timestamp
    fn zero() -> Tai64N {
        Tai64N { secs: 0, nano: 0 }
    }

    /// Parse a timestamp from a 12 byte u8 slice
    fn parse(buf: &[u8; 12]) -> Result<Tai64N, WireGuardError> {
        if buf.len() < 12 {
            return Err(WireGuardError::InvalidTai64nTimestamp);
        }

        let (sec_bytes, nano_bytes) = buf.split_at(std::mem::size_of::<u64>());
        let secs = u64::from_be_bytes(sec_bytes.try_into().unwrap());
        let nano = u32::from_be_bytes(nano_bytes.try_into().unwrap());

        // WireGuard does not actually expect tai64n timestamp, just monotonically increasing one
        //if secs < (1u64 << 62) || secs >= (1u64 << 63) {
        //    return Err(WireGuardError::InvalidTai64nTimestamp);
        //};
        //if nano >= 1_000_000_000 {
        //   return Err(WireGuardError::InvalidTai64nTimestamp);
        //}

        Ok(Tai64N { secs, nano })
    }

    /// Check if this timestamp represents a time that is chronologically after the time represented
    /// by the other timestamp
    pub fn after(&self, other: &Tai64N) -> bool {
        (self.secs > other.secs) || ((self.secs == other.secs) && (self.nano > other.nano))
    }
}

/// Parameters used by the noise protocol
struct NoiseParams {
    /// Our static public key
    static_public: [u8; PUBLIC_KEY_LEN],
    /// Our static private key
    static_private: [u8; PRIVATE_KEY_LEN],
    /// Static public key of the other party
    peer_static_public: [u8; PUBLIC_KEY_LEN],
    /// A shared key = DH(static_private, peer_static_public)
    static_shared: [u8; SHARED_SECRET_KEY_LEN],
    /// A pre-computation of HASH("mac1----", peer_static_public) for this peer
    sending_mac1_key: [u8; HASH_LEN],
    /// An optional preshared key
    preshared_key: Option<[u8; SHARED_SECRET_KEY_LEN]>,
}

impl std::fmt::Debug for NoiseParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseParams")
            .field("static_public", &self.static_public)
            .field("static_private", &"<redacted>")
            .field("peer_static_public", &self.peer_static_public)
            .field("static_shared", &"<redacted>")
            .field("sending_mac1_key", &self.sending_mac1_key)
            .field("preshared_key", &self.preshared_key)
            .finish()
    }
}

struct HandshakeInitSentState {
    local_index: u32,
    hash: [u8; HASH_LEN],
    chaining_key: [u8; HASH_LEN],
    ephemeral_private: [u8; PRIVATE_KEY_LEN],
    time_sent: Instant,
}

impl std::fmt::Debug for HandshakeInitSentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitSentState")
            .field("local_index", &self.local_index)
            .field("hash", &self.hash)
            .field("chaining_key", &self.chaining_key)
            .field("ephemeral_private", &"<redacted>")
            .field("time_sent", &self.time_sent)
            .finish()
    }
}

#[derive(Debug)]
enum HandshakeState {
    /// No handshake in process
    None,
    /// We initiated the handshake
    InitSent(HandshakeInitSentState),
    /// Handshake initiated by peer
    InitReceived {
        hash: [u8; HASH_LEN],
        chaining_key: [u8; HASH_LEN],
        peer_ephemeral_public: [u8; PUBLIC_KEY_LEN],
        peer_index: u32,
    },
    /// Handshake was established too long ago (implies no handshake is in progress)
    Expired,
}

pub struct Handshake {
    params: NoiseParams,
    /// Index of the next session
    next_index: u32,
    /// Allow to have two outgoing handshakes in flight, because sometimes we may receive a delayed response to a handshake with bad networks
    previous: HandshakeState,
    /// Current handshake state
    state: HandshakeState,
    cookies: Cookies,
    /// The timestamp of the last handshake we received
    last_handshake_timestamp: Tai64N,
    // TODO: make TimeStamper a singleton
    stamper: TimeStamper,
    pub(super) last_rtt: Option<u32>,
}

#[derive(Default)]
struct Cookies {
    last_mac1: Option<[u8; 32]>,
    index: u32,
    write_cookie: Option<[u8; 32]>,
}

#[derive(Debug)]
pub struct HalfHandshake {
    pub peer_index: u32,
    pub peer_static_public: [u8; PUBLIC_KEY_LEN],
}

pub fn parse_handshake_anon(
    static_private: &[u8],
    static_public: &[u8],
    packet: &HandshakeInit,
) -> Result<HalfHandshake, WireGuardError> {
    let peer_index = packet.sender_idx;
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = INITIAL_CHAIN_KEY;
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = INITIAL_CHAIN_HASH;
    hash = sha256_hash(&hash, static_public);
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    let peer_ephemeral_public = *packet.unencrypted_ephemeral;
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = sha256_hash(&hash, &peer_ephemeral_public);
    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = sha256_hmac(
        &sha256_hmac(&chaining_key, &peer_ephemeral_public),
        &[0x01],
    );
    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let ephemeral_shared = diffie_hellman(static_private, &peer_ephemeral_public);
    let temp = sha256_hmac(&chaining_key, &ephemeral_shared);
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = sha256_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = sha256_hmac2(&temp, &chaining_key, &[0x02]);

    let mut peer_static_public = [0u8; PUBLIC_KEY_LEN];
    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    aead_aes_gcm_open(
        &mut peer_static_public,
        &key,
        0,
        packet.encrypted_static,
        &hash,
    )?;

    Ok(HalfHandshake {
        peer_index,
        peer_static_public,
    })
}

impl NoiseParams {
    /// New noise params struct from our secret key, peers public key, and optional preshared key
    fn new(
        static_private: [u8; PRIVATE_KEY_LEN],
        static_public: [u8; PUBLIC_KEY_LEN],
        peer_static_public: [u8; PUBLIC_KEY_LEN],
        preshared_key: Option<[u8; SHARED_SECRET_KEY_LEN]>,
    ) -> NoiseParams {
        let static_shared = diffie_hellman(&static_private, &peer_static_public);

        let initial_sending_mac_key = sha256_hash(LABEL_MAC1, &peer_static_public);

        NoiseParams {
            static_public,
            static_private,
            peer_static_public,
            static_shared,
            sending_mac1_key: initial_sending_mac_key,
            preshared_key,
        }
    }

    /// Set a new private key
    fn set_static_private(
        &mut self,
        static_private: [u8; PRIVATE_KEY_LEN],
        static_public: [u8; PUBLIC_KEY_LEN],
    ) {
        // Check that the public key indeed matches the private key
        let check_key = x25519::dh_make_pub(&static_private);
        assert_eq!(check_key, static_public);

        self.static_private = static_private;
        self.static_public = static_public;

        self.static_shared = diffie_hellman(&self.static_private, &self.peer_static_public);
    }
}

impl Handshake {
    pub(crate) fn new(
        static_private: [u8; PRIVATE_KEY_LEN],
        static_public: [u8; PUBLIC_KEY_LEN],
        peer_static_public: [u8; PUBLIC_KEY_LEN],
        global_idx: u32,
        preshared_key: Option<[u8; 32]>,
    ) -> Handshake {
        let params = NoiseParams::new(
            static_private,
            static_public,
            peer_static_public,
            preshared_key,
        );

        Handshake {
            params,
            next_index: global_idx,
            previous: HandshakeState::None,
            state: HandshakeState::None,
            last_handshake_timestamp: Tai64N::zero(),
            stamper: TimeStamper::new(),
            cookies: Default::default(),
            last_rtt: None,
        }
    }

    pub(crate) fn is_in_progress(&self) -> bool {
        !matches!(self.state, HandshakeState::None | HandshakeState::Expired)
    }

    pub(crate) fn timer(&self) -> Option<Instant> {
        match self.state {
            HandshakeState::InitSent(HandshakeInitSentState { time_sent, .. }) => Some(time_sent),
            _ => None,
        }
    }

    pub(crate) fn set_expired(&mut self) {
        self.previous = HandshakeState::Expired;
        self.state = HandshakeState::Expired;
    }

    pub(crate) fn is_expired(&self) -> bool {
        matches!(self.state, HandshakeState::Expired)
    }

    pub(crate) fn has_cookie(&self) -> bool {
        self.cookies.write_cookie.is_some()
    }

    pub(crate) fn clear_cookie(&mut self) {
        self.cookies.write_cookie = None;
    }

    // The index used is 24 bits for peer index, allowing for 16M active peers per server and 8 bits for cyclic session index
    fn inc_index(&mut self) -> u32 {
        let index = self.next_index;
        let idx8 = index as u8;
        self.next_index = (index & !0xff) | u32::from(idx8.wrapping_add(1));
        self.next_index
    }

    pub(crate) fn set_static_private(
        &mut self,
        private_key: [u8; PRIVATE_KEY_LEN],
        public_key: [u8; PUBLIC_KEY_LEN],
    ) {
        self.params.set_static_private(private_key, public_key)
    }

    pub(super) fn receive_handshake_initialization<'a>(
        &mut self,
        packet: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session), WireGuardError> {
        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = sha256_hash(&hash, &self.params.static_public);
        // msg.sender_index = little_endian(initiator.sender_index)
        let peer_index = packet.sender_idx;
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        let peer_ephemeral_public = *packet.unencrypted_ephemeral;
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = sha256_hash(&hash, &peer_ephemeral_public);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(
            &sha256_hmac(&chaining_key, &peer_ephemeral_public),
            &[0x01],
        );
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let ephemeral_shared = diffie_hellman(&self.params.static_private, &peer_ephemeral_public);
        let temp = sha256_hmac(&chaining_key, &ephemeral_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = sha256_hmac2(&temp, &chaining_key, &[0x02]);

        let mut peer_static_public_decrypted = [0u8; PUBLIC_KEY_LEN];
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        aead_aes_gcm_open(
            &mut peer_static_public_decrypted,
            &key,
            0,
            packet.encrypted_static,
            &hash,
        )?;

        ring::constant_time::verify_slices_are_equal(
            &self.params.peer_static_public,
            &peer_static_public_decrypted,
        )
        .map_err(|_| WireGuardError::WrongKey)?;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = sha256_hash(&hash, packet.encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = sha256_hmac(&chaining_key, &self.params.static_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = sha256_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        aead_aes_gcm_open(&mut timestamp, &key, 0, packet.encrypted_timestamp, &hash)?;

        let timestamp = Tai64N::parse(&timestamp)?;
        if !timestamp.after(&self.last_handshake_timestamp) {
            // Possibly a replay
            return Err(WireGuardError::WrongTai64nTimestamp);
        }
        self.last_handshake_timestamp = timestamp;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = sha256_hash(&hash, packet.encrypted_timestamp);

        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitReceived {
                chaining_key,
                hash,
                peer_ephemeral_public,
                peer_index,
            },
        );

        self.format_handshake_response(dst)
    }

    pub(super) fn receive_handshake_response(
        &mut self,
        packet: HandshakeResponse,
    ) -> Result<Session, WireGuardError> {
        // Check if there is a handshake awaiting a response and return the correct one
        let (state, is_previous) = match (&self.state, &self.previous) {
            (HandshakeState::InitSent(s), _) if s.local_index == packet.receiver_idx => (s, false),
            (_, HandshakeState::InitSent(s)) if s.local_index == packet.receiver_idx => (s, true),
            _ => return Err(WireGuardError::UnexpectedPacket),
        };

        let peer_index = packet.sender_idx;
        let local_index = state.local_index;

        let unencrypted_ephemeral = *packet.unencrypted_ephemeral;
        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        let mut hash = sha256_hash(&state.hash, &unencrypted_ephemeral);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = sha256_hmac(&state.chaining_key, &unencrypted_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        let mut chaining_key = sha256_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = diffie_hellman(&state.ephemeral_private, &unencrypted_ephemeral);
        let temp = sha256_hmac(&chaining_key, &ephemeral_shared);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let temp = sha256_hmac(
            &chaining_key,
            &diffie_hellman(&self.params.static_private, &unencrypted_ephemeral)
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = sha256_hmac(
            &chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; 32])[..],
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = sha256_hmac2(&temp, &chaining_key, &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = sha256_hmac2(&temp, &temp2, &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = sha256_hash(&hash, &temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        aead_aes_gcm_open(&mut [], &key, 0, packet.encrypted_nothing, &hash)?;

        // responder.hash = HASH(responder.hash || msg.encrypted_nothing)
        // hash = sha256_hash(hash, buf[ENC_NOTHING_OFF..ENC_NOTHING_OFF + ENC_NOTHING_SZ]);

        // Derive keys
        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        // initiator.sending_key_counter = 0
        // initiator.receiving_key_counter = 0
        let temp1 = sha256_hmac(&chaining_key, &[]);
        let temp2 = sha256_hmac(&temp1, &[0x01]);
        let temp3 = sha256_hmac2(&temp1, &temp2, &[0x02]);

        let rtt_time = Instant::now().duration_since(state.time_sent);
        self.last_rtt = Some(rtt_time.as_millis() as u32);

        if is_previous {
            self.previous = HandshakeState::None;
        } else {
            self.state = HandshakeState::None;
        }
        Ok(Session::new(local_index, peer_index, temp3, temp2))
    }

    pub(super) fn receive_cookie_reply(
        &mut self,
        packet: PacketCookieReply,
    ) -> Result<(), WireGuardError> {
        let mac1 = match self.cookies.last_mac1 {
            Some(mac) => mac,
            None => {
                return Err(WireGuardError::UnexpectedPacket);
            }
        };

        let local_index = self.cookies.index;
        if packet.receiver_idx != local_index {
            return Err(WireGuardError::WrongIndex);
        }
        // msg.encrypted_cookie = AEAD(HASH(LABEL_COOKIE || responder.static_public), msg.nonce, cookie, last_received_msg.mac1)
        let key = sha256_hash(LABEL_COOKIE, &self.params.peer_static_public); // TODO: pre-compute

        let aad = &mac1[..];
        let msg = packet.encrypted_cookie;
        let (ciphertext, tag) = msg.split_at(msg.len() - 16);
        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut gcm = GCM::new().map_err(|_| WireGuardError::InvalidAeadTag)?;
        gcm.init(&key).map_err(|_| WireGuardError::InvalidAeadTag)?;
        gcm.decrypt(ciphertext, &mut plaintext, packet.nonce, aad, tag)
            .map_err(|_| WireGuardError::InvalidAeadTag)?;

        let cookie = plaintext
            .try_into()
            .map_err(|_| WireGuardError::InvalidPacket)?;
        self.cookies.write_cookie = Some(cookie);
        Ok(())
    }

    // Compute and append mac1 and mac2 to a handshake message
    fn append_mac1_and_mac2<'a>(
        &mut self,
        local_index: u32,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let mac1_off = dst.len() - 64;
        let mac2_off = dst.len() - 32;

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let msg_mac1 = hmac_sha256_mac_32(&self.params.sending_mac1_key, &dst[..mac1_off]);

        dst[mac1_off..mac2_off].copy_from_slice(&msg_mac1[..]);

        //msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        let msg_mac2: [u8; 32] = if let Some(cookie) = self.cookies.write_cookie {
            hmac_sha256_mac_32(&cookie, &dst[..mac2_off])
        } else {
            [0u8; 32]
        };

        dst[mac2_off..].copy_from_slice(&msg_mac2[..]);

        self.cookies.index = local_index;
        self.cookies.last_mac1 = Some(msg_mac1);
        Ok(dst)
    }

    pub(super) fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if dst.len() < super::HANDSHAKE_INIT_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(65);
        let (encrypted_static, rest) = rest.split_at_mut(65 + 16);
        let (encrypted_timestamp, _) = rest.split_at_mut(12 + 16);

        let local_index = self.inc_index();

        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = sha256_hash(&hash, &self.params.peer_static_public);
        // initiator.ephemeral_private = DH_GENERATE()
        let ephemeral_private = x25519::dh_generate();
        // msg.message_type = 1
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::HANDSHAKE_INIT.to_le_bytes());
        // msg.sender_index = little_endian(initiator.sender_index)
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral.copy_from_slice(&x25519::dh_make_pub(&ephemeral_private));
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = sha256_hash(&hash, unencrypted_ephemeral);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&sha256_hmac(&chaining_key, unencrypted_ephemeral), &[0x01]);
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let ephemeral_shared = diffie_hellman(&ephemeral_private, &self.params.peer_static_public);
        let temp = sha256_hmac(&chaining_key, &ephemeral_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = sha256_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        aead_aes_gcm_seal(
            encrypted_static,
            &key,
            0,
            &self.params.static_public,
            &hash,
        );
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = sha256_hash(&hash, encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = sha256_hmac(&chaining_key, &self.params.static_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = sha256_hmac2(&temp, &chaining_key, &[0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let timestamp = self.stamper.stamp();
        aead_aes_gcm_seal(encrypted_timestamp, &key, 0, &timestamp, &hash);
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = sha256_hash(&hash, encrypted_timestamp);

        let time_now = Instant::now();
        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitSent(HandshakeInitSentState {
                local_index,
                chaining_key,
                hash,
                ephemeral_private,
                time_sent: time_now,
            }),
        );

        self.append_mac1_and_mac2(local_index, &mut dst[..super::HANDSHAKE_INIT_SZ])
    }

    fn format_handshake_response<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session), WireGuardError> {
        if dst.len() < super::HANDSHAKE_RESP_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let state = std::mem::replace(&mut self.state, HandshakeState::None);
        let (mut chaining_key, mut hash, peer_ephemeral_public, peer_index) = match state {
            HandshakeState::InitReceived {
                chaining_key,
                hash,
                peer_ephemeral_public,
                peer_index,
            } => (chaining_key, hash, peer_ephemeral_public, peer_index),
            _ => {
                panic!("Unexpected attempt to call send_handshake_response");
            }
        };

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(65);
        let (encrypted_nothing, _) = rest.split_at_mut(16);

        // responder.ephemeral_private = DH_GENERATE()
        let ephemeral_private = x25519::dh_generate();
        let local_index = self.inc_index();
        // msg.message_type = 2
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::HANDSHAKE_RESP.to_le_bytes());
        // msg.sender_index = little_endian(responder.sender_index)
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&peer_index.to_le_bytes());
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral.copy_from_slice(&x25519::dh_make_pub(&ephemeral_private));
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        hash = sha256_hash(&hash, unencrypted_ephemeral);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = sha256_hmac(&chaining_key, unencrypted_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = diffie_hellman(&ephemeral_private, &peer_ephemeral_public);
        let temp = sha256_hmac(&chaining_key, &ephemeral_shared);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let temp = sha256_hmac(
            &chaining_key,
            &diffie_hellman(&ephemeral_private, &self.params.peer_static_public)
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = sha256_hmac(
            &chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; 32])[..],
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = sha256_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = sha256_hmac2(&temp, &chaining_key, &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = sha256_hmac2(&temp, &temp2, &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = sha256_hash(&hash, &temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        aead_aes_gcm_seal(encrypted_nothing, &key, 0, &[], &hash);

        // Derive keys
        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        // initiator.sending_key_counter = 0
        // initiator.receiving_key_counter = 0
        let temp1 = sha256_hmac(&chaining_key, &[]);
        let temp2 = sha256_hmac(&temp1, &[0x01]);
        let temp3 = sha256_hmac2(&temp1, &temp2, &[0x02]);

        let dst = self.append_mac1_and_mac2(local_index, &mut dst[..super::HANDSHAKE_RESP_SZ])?;

        Ok((dst, Session::new(local_index, peer_index, temp2, temp3)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_seal_rfc7530_test_vector() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let mut buffer = vec![0; plaintext.len() + 16];

        aead_aes_gcm_seal_inner(&mut buffer, &key, nonce, plaintext, &aad);

        const EXPECTED_CIPHERTEXT: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        const EXPECTED_TAG: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        assert_eq!(buffer[..plaintext.len()], EXPECTED_CIPHERTEXT);
        assert_eq!(buffer[plaintext.len()..], EXPECTED_TAG);
    }

    #[test]
    fn symmetric_chacha20_seal_open() {
        let aad: [u8; 32] = Default::default();
        let key: [u8; 32] = Default::default();
        let counter = 0;

        let mut encrypted_nothing: [u8; 16] = Default::default();

        aead_aes_gcm_seal(&mut encrypted_nothing, &key, counter, &[], &aad);

        eprintln!("encrypted_nothing: {:?}", encrypted_nothing);

        aead_aes_gcm_open(&mut [], &key, counter, &encrypted_nothing, &aad)
            .expect("Should open what we just sealed");
    }
}

fn diffie_hellman(private: &[u8], public: &[u8]) -> [u8; 32] {
    let mut shared_secret = [0u8; 32];
    let mut ecc_private = ECC::import_private_key_ex(private, &[], ECC::SECP256R1, None, None).unwrap();
    let mut ecc_public = ECC::import_x963_ex(public, ECC::SECP256R1, None, None).unwrap();
    let size = ecc_private.shared_secret(&mut ecc_public, &mut shared_secret).unwrap();
    assert_eq!(size, shared_secret.len());
    shared_secret
}
