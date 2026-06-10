# Protocol fuzzing

Coverage-guided (libFuzzer) fuzzing of the SSH protocol engine's untrusted-input surface.
This complements the in-suite randomized/mutation tests in
`crates/ssh-transport/tests/fuzz_smoke.rs` (which run on stable in normal CI); these
targets reach far deeper with coverage feedback.

This is a **standalone** crate (its `Cargo.toml` carries an empty `[workspace]` table), so
the main `cargo build --workspace` / `cargo test --workspace` ignore it.

## Prerequisites

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target            | Entry point fuzzed                                  |
|-------------------|-----------------------------------------------------|
| `server_on_input` | `ServerConnection::on_input` (server attack surface)|
| `client_on_input` | `ClientConnection::on_input` (client attack surface)|
| `kexinit_parse`   | `KexInit::parse` (first structured message)         |
| `decompress`      | `Decompressor::decompress` (zlib / decompression bombs) |

## Running

From the repo root:

```sh
cargo +nightly fuzz run server_on_input
cargo +nightly fuzz run decompress
# time-boxed, e.g. 5 minutes:
cargo +nightly fuzz run kexinit_parse -- -max_total_time=300
```

The invariant under test is the same as the in-suite harness: arbitrary or corrupted
bytes must only ever produce `Ok`/`Err`, never a panic, integer overflow, or hang. A crash
is written to `fuzz/artifacts/<target>/` and reproduces with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```
