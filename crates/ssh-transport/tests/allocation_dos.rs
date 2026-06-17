//! Protocol-level over-allocation / size-attack guards.
//!
//! An SSH peer is untrusted: every length field on the wire is attacker-controlled. A
//! naive parser that allocates (or buffers) based on a claimed length before validating
//! it lets a single small packet trigger a multi-gigabyte allocation — a memory-
//! exhaustion DoS. These tests drive a real [`Transport`] and assert each such vector is
//! rejected *at the framing/parse layer, before the claimed size is ever buffered*.
//!
//! The defended invariants:
//! * A binary packet whose `packet_length` exceeds [`MAX_PACKET_LENGTH`] is refused from
//!   the 4-byte header alone — we never wait for, or allocate, the claimed payload.
//! * A `name-list` with more entries than [`wire::MAX_NAME_LIST_ENTRIES`] is refused
//!   before the per-name `Box<str>` allocations run.
//! * The pre-identification banner buffer is bounded, so a peer that never sends a
//!   newline cannot grow our receive buffer without limit.

use rand_chacha::ChaCha8Rng;
use ssh_transport::packet::{MAX_PACKET_LENGTH, encode_plain_into};
use ssh_transport::rand_core::SeedableRng;
use ssh_transport::wire::{MAX_NAME_LIST_ENTRIES, Writer};
use ssh_transport::{HostKey, SshError, Transport, msg};

fn rng() -> ChaCha8Rng {
    ChaCha8Rng::seed_from_u64(0xDEAD_BEEF)
}

/// A fresh server transport advanced past the version exchange, so the next bytes it
/// reads are parsed as binary packets (the `Cipher::None` plaintext framing used before
/// `NEWKEYS`). This is the pre-auth surface an unauthenticated peer can reach.
fn server_after_version() -> Transport<ChaCha8Rng> {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(7));
    let mut server = Transport::new_server(ChaCha8Rng::seed_from_u64(2), host_key);
    server
        .on_input(b"SSH-2.0-attacker\r\n")
        .expect("a well-formed client identification is accepted");
    server
}

/// A `packet_length` field claiming far more than [`MAX_PACKET_LENGTH`] must be rejected
/// from the 4-byte header alone. The key anti-DoS property: rejection happens with *only
/// the header present*, proving we validate the length before buffering/allocating the
/// claimed payload. If the parser instead waited for the bytes, this would return
/// `Ok(())` (need more) rather than an error.
#[test]
fn oversized_packet_length_is_rejected_from_the_header_alone() {
    let mut server = server_after_version();

    // 4-byte big-endian length only — no payload follows.
    let claimed = (MAX_PACKET_LENGTH as u32) + 1;
    let header = claimed.to_be_bytes();

    let result = server.on_input(&header);
    assert!(
        matches!(result, Err(SshError::BadPacket(_))),
        "an oversized packet_length must be refused from the header, got {result:?}"
    );
}

/// A truly enormous claimed length (near `u32::MAX`, ~4 GiB) is the canonical memory-
/// exhaustion payload. It must be refused exactly like any other out-of-range length —
/// never used to size an allocation.
#[test]
fn four_gigabyte_packet_length_does_not_allocate() {
    let mut server = server_after_version();
    let header = u32::MAX.to_be_bytes();
    let result = server.on_input(&header);
    assert!(
        matches!(result, Err(SshError::BadPacket(_))),
        "a ~4 GiB packet_length must be refused, got {result:?}"
    );
}

/// A `packet_length` below the protocol minimum is malformed and must be rejected (the
/// lower bound of the same range check that guards the upper bound).
#[test]
fn undersized_packet_length_is_rejected() {
    let mut server = server_after_version();
    // packet_length = 1 is far below MIN_PACKET; the range check must reject it.
    let header = 1u32.to_be_bytes();
    let result = server.on_input(&header);
    assert!(
        matches!(result, Err(SshError::BadPacket(_))),
        "an undersized packet_length must be refused, got {result:?}"
    );
}

/// A `packet_length` *within* range but not yet fully arrived must NOT error — it is a
/// legitimately incomplete read, and the transport should simply wait for more bytes.
/// This is the contrast case that proves the oversized-length rejection above is a
/// deliberate range check, not just "any incomplete packet fails".
#[test]
fn in_range_incomplete_packet_waits_for_more_bytes() {
    let mut server = server_after_version();
    // Claim a modest, in-range length but send only the header.
    let header = 64u32.to_be_bytes();
    let result = server.on_input(&header);
    assert!(
        result.is_ok(),
        "an in-range but incomplete packet must wait for more bytes, got {result:?}"
    );
}

/// SSH is a byte stream: a peer can declare a valid packet length and then keep sending
/// well past it. The transport must consume exactly the declared length per packet and
/// re-parse the remainder as the next packet — never folding the excess into one packet's
/// size, and never buffering the whole stream as a single allocation. Here several valid
/// packets arrive coalesced in one read (far more data than the first packet declares);
/// all must be accepted at their true boundaries.
#[test]
fn valid_packet_followed_by_more_data_is_parsed_packet_by_packet() {
    let mut server = server_after_version();
    let mut r = rng();

    // Three back-to-back IGNORE packets (valid in any phase, no side effects).
    let mut stream = Vec::new();
    for _ in 0..3 {
        encode_plain_into(&[msg::IGNORE], &mut r, &mut stream);
    }

    assert!(
        server.on_input(&stream).is_ok(),
        "coalesced valid packets must each be consumed at their declared boundary"
    );
}

/// The bytes *trailing* a valid packet are themselves the start of the next packet, so
/// they are subject to the same length cap. A valid packet followed by an oversized-length
/// header must not be waved through just because a well-formed packet preceded it.
#[test]
fn excess_data_after_a_valid_packet_is_still_length_checked() {
    let mut server = server_after_version();
    let mut r = rng();

    let mut stream = Vec::new();
    encode_plain_into(&[msg::IGNORE], &mut r, &mut stream); // one valid packet ...
    stream.extend_from_slice(&((MAX_PACKET_LENGTH as u32) + 1).to_be_bytes()); // ... then a bomb header

    let result = server.on_input(&stream);
    assert!(
        matches!(result, Err(SshError::BadPacket(_))),
        "an oversized length following a valid packet must still be refused, got {result:?}"
    );
}

/// A KEXINIT carrying a `name-list` with more entries than [`MAX_NAME_LIST_ENTRIES`] is a
/// pre-auth amplification vector: each name would otherwise become its own `Box<str>`
/// allocation and feed an `O(client × server)` negotiation scan. It must be rejected
/// during parsing, before those allocations run.
#[test]
fn oversized_name_list_in_kexinit_is_rejected() {
    let mut server = server_after_version();

    // Build a KEXINIT whose first (kex) name-list is one past the cap. `parse` reads the
    // 16-byte cookie then this list first, so it errors before touching the rest.
    let mut w = Writer::new();
    w.u8(msg::KEXINIT);
    w.raw(&[0u8; 16]); // cookie
    let names: Vec<&str> = vec!["x"; MAX_NAME_LIST_ENTRIES + 1];
    w.name_list(&names);
    let payload = w.into_bytes();

    // Frame it as a valid plaintext binary packet so it reaches the KEXINIT handler.
    let mut frame = Vec::new();
    encode_plain_into(&payload, &mut rng(), &mut frame);

    let result = server.on_input(&frame);
    assert!(
        matches!(result, Err(SshError::Encoding(_))),
        "an over-long name-list must be refused during parsing, got {result:?}"
    );
}

/// A peer that opens the connection and then streams bytes without ever sending a
/// newline-terminated identification line must not be able to grow our pre-identification
/// receive buffer without bound. The banner buffer is capped, so the flood is refused.
#[test]
fn unterminated_version_banner_flood_is_rejected() {
    // A client tolerates server banner lines, so it is the side that buffers pre-id bytes
    // looking for the SSH identification — exactly the surface to bound.
    let mut client = Transport::new_client(ChaCha8Rng::seed_from_u64(3));

    // Well over the banner cap (MAX_LINE * 64 ≈ 16 KiB), with no newline anywhere.
    let flood = vec![b'A'; 64 * 1024];
    let result = client.on_input(&flood);
    assert!(
        matches!(result, Err(SshError::BadVersion(_))),
        "an unterminated banner flood must be refused, got {result:?}"
    );
}

/// A server (which does not tolerate banner lines) must reject a peer whose first line is
/// not an SSH identification, rather than buffering arbitrary junk.
#[test]
fn server_rejects_non_ssh_identification() {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(9));
    let mut server = Transport::new_server(ChaCha8Rng::seed_from_u64(2), host_key);
    let result = server.on_input(b"NOT-SSH garbage line\r\n");
    assert!(
        matches!(result, Err(SshError::BadVersion(_))),
        "a non-SSH identification must be refused, got {result:?}"
    );
}
