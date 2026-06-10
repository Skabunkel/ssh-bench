//! In-memory re-key test: after the initial handshake, trigger a key re-exchange and
//! confirm the session id is preserved, traffic queued mid-rekey is delivered, and new
//! traffic flows under the fresh keys.

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use ssh_transport::{Event, HostKey, Transport};

fn pump(client: &mut Transport<ChaCha8Rng>, server: &mut Transport<ChaCha8Rng>) -> bool {
    let mut moved = false;
    let c_out = client.take_output();
    if !c_out.is_empty() {
        server.on_input(&c_out).unwrap();
        moved = true;
    }
    let s_out = server.take_output();
    if !s_out.is_empty() {
        client.on_input(&s_out).unwrap();
        moved = true;
    }
    moved
}

fn drain_packets(t: &mut Transport<ChaCha8Rng>, into: &mut Vec<Vec<u8>>) {
    while let Some(e) = t.poll_event() {
        if let Event::Packet(p) = e {
            into.push(p.to_vec());
        }
    }
}

#[test]
fn rekey_flood_is_throttled() {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(7));
    let mut client = Transport::new_client(ChaCha8Rng::seed_from_u64(1));
    let mut server = Transport::new_server(ChaCha8Rng::seed_from_u64(2), host_key);

    for _ in 0..32 {
        let moved = pump(&mut client, &mut server);
        if client.is_established() && server.is_established() && !moved {
            break;
        }
    }
    assert!(client.is_established() && server.is_established());

    // Hammer the server with back-to-back re-keys and no application traffic between
    // them. After the tolerated burst the server must drop us with a protocol error.
    let mut disconnected = false;
    for _ in 0..10 {
        client.initiate_rekey();
        for _ in 0..16 {
            let moved = pump(&mut client, &mut server);
            while let Some(e) = client.poll_event() {
                if let Event::Disconnect { reason, .. } = e
                    && reason == 2
                {
                    disconnected = true;
                }
            }
            if !moved {
                break;
            }
        }
        if disconnected {
            break;
        }
    }
    assert!(disconnected, "a re-key flood must be throttled with a disconnect");
    // The server must enter the closing state and stop processing further input.
    assert!(server.is_closing(), "server should be closing after the flood");
}

#[test]
fn rekey_preserves_session_and_flushes_queued_traffic() {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(7));
    let mut client = Transport::new_client(ChaCha8Rng::seed_from_u64(1));
    let mut server = Transport::new_server(ChaCha8Rng::seed_from_u64(2), host_key);

    // Initial handshake.
    for _ in 0..32 {
        let moved = pump(&mut client, &mut server);
        if client.is_established() && server.is_established() && !moved {
            break;
        }
    }
    assert!(client.is_established() && server.is_established());

    let session_id = client.session_id().unwrap().to_vec();
    assert_eq!(session_id, server.session_id().unwrap());

    // Start a re-key, then enqueue a packet while it is in progress.
    client.initiate_rekey();
    assert!(client.is_rekeying());
    client.send_packet(b"during-rekey").unwrap(); // first byte 'd' (100), not a KEX id

    // Drive the re-key to completion.
    let mut server_packets = Vec::new();
    for _ in 0..32 {
        let moved = pump(&mut client, &mut server);
        drain_packets(&mut server, &mut server_packets);
        if !client.is_rekeying() && !server.is_rekeying() && !moved {
            break;
        }
    }
    assert!(!client.is_rekeying() && !server.is_rekeying());

    // The session id is fixed by the first exchange and must not change.
    assert_eq!(client.session_id().unwrap(), &session_id[..]);

    // Traffic that flows after the re-key uses the new keys.
    client.send_packet(b"after-rekey").unwrap(); // first byte 'a' (97)
    for _ in 0..8 {
        let moved = pump(&mut client, &mut server);
        drain_packets(&mut server, &mut server_packets);
        if !moved {
            break;
        }
    }

    assert!(
        server_packets.iter().any(|p| p == b"during-rekey"),
        "queued packet not delivered after rekey"
    );
    assert!(
        server_packets.iter().any(|p| p == b"after-rekey"),
        "post-rekey packet not delivered"
    );
}
