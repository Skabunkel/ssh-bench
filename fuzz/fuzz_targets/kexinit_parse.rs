//! Fuzz the KEXINIT parser directly (the first structured message a peer sends).
#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_transport::algo::KexInit;

fuzz_target!(|data: &[u8]| {
    let _ = KexInit::parse(data);
});
