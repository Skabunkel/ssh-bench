//! In-memory client ↔ server authentication tests (success and failure paths).

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    ServerAuthHandler, ServerConnection, ServerEvent, UserKeypair, UserPublicKey,
};

// --- test handlers ---

struct TestServer {
    password: Option<(String, String)>,
    authorized: Option<UserPublicKey>,
}

impl ServerAuthHandler for TestServer {
    fn verify_password(&mut self, user: &str, password: &str) -> bool {
        self.password
            .as_ref()
            .is_some_and(|(u, p)| u == user && p == password)
    }
    fn is_authorized_key(&mut self, _user: &str, key: &UserPublicKey) -> bool {
        self.authorized.as_ref() == Some(key)
    }
}

struct TestClient {
    user: Box<str>,
    attempts: Vec<AuthAttempt>,
    trust_host: bool,
}

impl ClientAuthHandler for TestClient {
    fn username(&self) -> Box<str> {
        self.user.clone()
    }
    fn verify_host_key(&mut self, _key: &HostPublicKey) -> bool {
        self.trust_host
    }
    fn next_auth(&mut self, _can_continue: &[Box<str>]) -> Option<AuthAttempt> {
        if self.attempts.is_empty() {
            None
        } else {
            Some(self.attempts.remove(0))
        }
    }
}

// --- harness ---

type Client = ClientConnection<ChaCha8Rng, TestClient>;
type Server = ServerConnection<ChaCha8Rng, TestServer>;

fn run(client: &mut Client, server: &mut Server) -> (Vec<ClientEvent>, Vec<ServerEvent>) {
    let mut ce = Vec::new();
    let mut se = Vec::new();
    for _ in 0..64 {
        let c_out = client.take_output();
        let mut moved = false;
        if !c_out.is_empty() {
            server.on_input(&c_out).unwrap();
            moved = true;
        }
        let s_out = server.take_output();
        if !s_out.is_empty() {
            client.on_input(&s_out).unwrap();
            moved = true;
        }
        while let Some(e) = client.poll_event() {
            ce.push(e);
        }
        while let Some(e) = server.poll_event() {
            se.push(e);
        }
        if !moved {
            break;
        }
    }
    (ce, se)
}

fn make_server(handler: TestServer) -> Server {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(100));
    ServerConnection::new(ChaCha8Rng::seed_from_u64(101), host_key, handler)
}

fn make_client(handler: TestClient) -> Client {
    ClientConnection::new(ChaCha8Rng::seed_from_u64(202), handler)
}

#[test]
fn password_auth_succeeds() {
    let mut server = make_server(TestServer {
        password: Some(("myuser".into(), "secret".into())),
        authorized: None,
    });
    let mut client = make_client(TestClient {
        user: "myuser".into(),
        attempts: vec![AuthAttempt::Password("secret".into())],
        trust_host: true,
    });
    let (ce, se) = run(&mut client, &mut server);
    assert!(client.is_authenticated());
    assert!(ce.iter().any(|e| matches!(e, ClientEvent::Authenticated)));
    assert!(
        se.iter()
            .any(|e| matches!(e, ServerEvent::Authenticated { user } if &**user == "myuser"))
    );
}

#[test]
fn password_auth_fails_with_wrong_password() {
    let mut server = make_server(TestServer {
        password: Some(("myuser".into(), "secret".into())),
        authorized: None,
    });
    let mut client = make_client(TestClient {
        user: "myuser".into(),
        attempts: vec![AuthAttempt::Password("wrong".into())],
        trust_host: true,
    });
    let (ce, _se) = run(&mut client, &mut server);
    assert!(!client.is_authenticated());
    assert!(
        ce.iter()
            .any(|e| matches!(e, ClientEvent::AuthFailed { .. }))
    );
}

#[test]
fn publickey_auth_succeeds() {
    let key = UserKeypair::generate(&mut ChaCha8Rng::seed_from_u64(303));
    let mut server = make_server(TestServer {
        password: None,
        authorized: Some(key.public()),
    });
    let mut client = make_client(TestClient {
        user: "myuser".into(),
        attempts: vec![AuthAttempt::PublicKey(Box::new(key))],
        trust_host: true,
    });
    let (_ce, _se) = run(&mut client, &mut server);
    assert!(client.is_authenticated());
}

#[test]
fn publickey_auth_fails_for_unauthorized_key() {
    let client_key = UserKeypair::generate(&mut ChaCha8Rng::seed_from_u64(404));
    let other_key = UserKeypair::generate(&mut ChaCha8Rng::seed_from_u64(405));
    let mut server = make_server(TestServer {
        password: None,
        authorized: Some(other_key.public()), // not the client's key
    });
    let mut client = make_client(TestClient {
        user: "myuser".into(),
        attempts: vec![AuthAttempt::PublicKey(Box::new(client_key))],
        trust_host: true,
    });
    let (ce, _se) = run(&mut client, &mut server);
    assert!(!client.is_authenticated());
    assert!(
        ce.iter()
            .any(|e| matches!(e, ClientEvent::AuthFailed { .. }))
    );
}

#[test]
fn falls_back_from_publickey_to_password() {
    let wrong_key = UserKeypair::generate(&mut ChaCha8Rng::seed_from_u64(505));
    let mut server = make_server(TestServer {
        password: Some(("myuser".into(), "secret".into())),
        authorized: None, // no key authorized → publickey fails, password then tried
    });
    let mut client = make_client(TestClient {
        user: "myuser".into(),
        attempts: vec![
            AuthAttempt::PublicKey(Box::new(wrong_key)),
            AuthAttempt::Password("secret".into()),
        ],
        trust_host: true,
    });
    let (_ce, _se) = run(&mut client, &mut server);
    assert!(client.is_authenticated());
}

#[test]
fn auth_cap_disconnects_after_repeated_failures() {
    let mut server = make_server(TestServer {
        password: Some(("myuser".into(), "secret".into())),
        authorized: None,
    });
    // The default cap is 6 attempts; feed six wrong passwords.
    let attempts = (0..6)
        .map(|_| AuthAttempt::Password("wrong".into()))
        .collect();
    let mut client = make_client(TestClient {
        user: "myuser".into(),
        attempts,
        trust_host: true,
    });
    let (ce, se) = run(&mut client, &mut server);
    assert!(!client.is_authenticated());
    assert!(
        se.iter().any(|e| matches!(e, ServerEvent::AuthExhausted)),
        "server should signal AuthExhausted at the cap"
    );
    // The client sees the disconnect with NO_MORE_AUTH_METHODS_AVAILABLE (reason 14).
    assert!(
        ce.iter()
            .any(|e| matches!(e, ClientEvent::Disconnect { reason, .. } if *reason == 14)),
        "client should be disconnected once the cap is hit"
    );
}

#[test]
fn client_aborts_on_untrusted_host_key() {
    let mut server = make_server(TestServer {
        password: Some(("myuser".into(), "secret".into())),
        authorized: None,
    });
    let mut client = make_client(TestClient {
        user: "myuser".into(),
        attempts: vec![AuthAttempt::Password("secret".into())],
        trust_host: false, // reject the host key
    });
    let (ce, _se) = run(&mut client, &mut server);
    assert!(!client.is_authenticated());
    assert!(ce.iter().any(|e| matches!(e, ClientEvent::HostKeyRejected)));
}
