# Handshake

A handshake implementation for a P2P node

 - Based on [ljedrz](https://github.com/ljedrz)'s [pea2pea](https://github.com/ljedrz/pea2pea) P2P node architecture.
 - Uses the Elliptic Curve Diffie-Hellman key exchange, leveraging Rust's [ring](https://crates.io/crates/ring) cryptographic primitives.
 - Aims to keep things simple: only mandatory parameters are exchanged during the handhake, as explicitly required.

