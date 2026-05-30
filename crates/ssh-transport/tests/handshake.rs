//! In-memory integration test: a client and server [`Transport`] complete the full
//! handshake against each other and exchange encrypted application packets — the M1
//! "our client ↔ our server complete KEX" criterion, with no sockets involved.

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use ssh_transport::{Event, HostKey, Transport};

/// Pump all currently-available bytes between the two peers once.
fn exchange(
    client: &mut Transport<ChaCha8Rng>,
    server: &mut Transport<ChaCha8Rng>,
) -> Result<bool, ssh_transport::SshError> {
    let mut moved = false;
    let c_out = client.take_output();
    if !c_out.is_empty() {
        server.on_input(&c_out)?;
        moved = true;
    }
    let s_out = server.take_output();
    if !s_out.is_empty() {
        client.on_input(&s_out)?;
        moved = true;
    }
    Ok(moved)
}

fn run_handshake() -> (Transport<ChaCha8Rng>, Transport<ChaCha8Rng>, Vec<Event>, Vec<Event>) {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(3));
    let mut client = Transport::new_client(ChaCha8Rng::seed_from_u64(1));
    let mut server = Transport::new_server(ChaCha8Rng::seed_from_u64(2), host_key);

    let mut client_events = Vec::new();
    let mut server_events = Vec::new();

    for _ in 0..32 {
        let moved = exchange(&mut client, &mut server).expect("handshake byte exchange");
        while let Some(e) = client.poll_event() {
            client_events.push(e);
        }
        while let Some(e) = server.poll_event() {
            server_events.push(e);
        }
        if client.is_established() && server.is_established() && !moved {
            break;
        }
    }
    (client, server, client_events, server_events)
}

#[test]
fn client_and_server_establish_with_matching_session_id() {
    let (client, server, client_events, _server_events) = run_handshake();

    assert!(client.is_established(), "client did not establish");
    assert!(server.is_established(), "server did not establish");

    let cs = client.session_id().expect("client session id");
    let ss = server.session_id().expect("server session id");
    assert_eq!(cs, ss, "session ids must match");
    assert_eq!(cs.len(), 32);

    assert!(
        client_events.iter().any(|e| matches!(e, Event::ServerHostKey(_))),
        "client should observe the server host key"
    );
    assert!(client_events.iter().any(|e| matches!(e, Event::Established)));
}

#[test]
fn established_peers_exchange_encrypted_packets() {
    let (mut client, mut server, _, _) = run_handshake();

    // Client -> server.
    client.send_packet(b"ping from client").unwrap();
    server.on_input(&client.take_output()).unwrap();
    let got = drain_packet(&mut server);
    assert_eq!(got, b"ping from client");

    // Server -> client.
    server.send_packet(b"pong from server").unwrap();
    client.on_input(&server.take_output()).unwrap();
    let got = drain_packet(&mut client);
    assert_eq!(got, b"pong from server");
}

fn drain_packet(t: &mut Transport<ChaCha8Rng>) -> Vec<u8> {
    while let Some(e) = t.poll_event() {
        if let Event::Packet(p) = e {
            return p;
        }
    }
    panic!("expected an Event::Packet");
}
