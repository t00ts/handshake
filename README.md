# Handshake

A handshake implementation for a P2P node

 - Based on [ljedrz](https://github.com/ljedrz)'s [pea2pea](https://github.com/ljedrz/pea2pea) P2P node architecture.
 - Uses the Elliptic Curve [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange), leveraging Rust's [ring](https://crates.io/crates/ring) cryptographic primitives.
 - Aims to keep things simple: only mandatory parameters are exchanged during the handhake, as explicitly required.


### Brief overview

On any handshake we consider two participants:

1. The **initiator**: The node that wants to join the network
2. The **responder**: An existing peer in the network

The handshake process goes as follows:

0. Both nodes have generated an ephemeral key pair for the session.
1. The **initiator** generates a random salt and sends it along with its public key to the **responder**.
2. The **responder** receives the salt and the **initiator**'s public key, and responds with its own public key.
3. The **initiator** receives the **responder**'s public key. 
4. Both compute and store the shared secret that will allow them to talk to each other during the session.

### Testing

Running `cargo test` should run all tests that showcase the handshake works in multiple environments:

1. Basic scenario with just two nodes.
2. A linear topology consisting of 10 nodes.
3. A mesh topology consisting of 10 nodes.

To ensure the handshake has indeed taken place we check the following:

1. Both nodes have agreed on a common shared secret (and the secrets match)
2. Nodes are sequentially connected and have agreed on a common shared secret _only_ with the next node in the chain.
3. All nodes have successfully connected to all other peers in the network.