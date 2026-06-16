//! **Service** layer: the public SSH client API. Wires the [`ssh_transport`] engine
//! to [`ssh_io`] drivers. No other layer may depend on this crate.
