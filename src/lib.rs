// lib.rs

mod secret;

use pea2pea::{protocols::Handshake, Config, Connection, ConnectionSide, Node, Pea2Pea};
use ring::{
    agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    error::Unspecified,
    hkdf::{Salt, HKDF_SHA256},
    rand::{SecureRandom, SystemRandom},
};
use secret::SharedSecret;
use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Length (in bytes) of the public key exchanged during the handshake
const PUBLIC_KEY_LENGTH: usize = 32;

/// Length (in bytes) of the random salt exchanged during the handshake
const SALT_LENGTH: usize = 16;

#[allow(dead_code)]
#[cfg_attr(test, derive(Clone))]
struct PeerData {
    shared_secret: SharedSecret,
    nonce: u64,
}

impl PeerData {
    /// Create a new [PeerData]
    fn new(shared_secret: SharedSecret) -> Self {
        Self {
            shared_secret,
            nonce: 0,
        }
    }
}

/// A simple P2P node that implements a basic diffie-hellman handshake
#[derive(Clone)]
pub struct SimpleNode {
    node: Node,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerData>>>,
}

impl Pea2Pea for SimpleNode {
    fn node(&self) -> &Node {
        &self.node
    }
}

impl SimpleNode {
    /// Create a new [SimpleNode]
    pub fn new(name: &str) -> Self {
        let cfg = Config {
            name: Some(name.into()),
            ..Default::default()
        };
        Self {
            node: Node::new(cfg),
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update handshake information for a connected peer node
    fn add_peer(&self, socket_addr: SocketAddr, data: PeerData) -> Result<(), Error> {
        let mut peers = self
            .peers
            .write()
            .map_err(|_| Error::new(ErrorKind::Other, "Mutex lock failed"))?;
        peers.insert(socket_addr, data);
        Ok(())
    }

    #[cfg(test)]
    fn peer_data(&self, peer_addr: SocketAddr) -> Option<PeerData> {
        let peers = self.peers.read().ok()?;
        peers.get(&peer_addr).cloned()
    }
}

impl Handshake for SimpleNode {
    async fn perform_handshake(&self, mut conn: Connection) -> io::Result<Connection> {
        // initialize a random number generator
        let rng = SystemRandom::new();

        // generate an ephemeral key pair
        let private_key = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_| Error::new(ErrorKind::Other, "Failed creating ephemeral private key"))?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| Error::new(ErrorKind::Other, "Failed computing private key"))?;

        // buffer for the handshake info being exchanged
        let mut handshake_buffer = [0u8; PUBLIC_KEY_LENGTH + SALT_LENGTH];

        // the actual tcp stream
        let node_conn_side = !conn.side();
        let stream = self.borrow_stream(&mut conn);

        match node_conn_side {
            ConnectionSide::Initiator => {
                // generate a random salt
                let rng = SystemRandom::new();
                let mut salt = [0u8; SALT_LENGTH];
                rng.fill(&mut salt)
                    .map_err(|_| Error::new(ErrorKind::Other, "Failed to generate random salt"))?;

                // send public key and random salt
                handshake_buffer[..PUBLIC_KEY_LENGTH].copy_from_slice(public_key.as_ref());
                handshake_buffer[PUBLIC_KEY_LENGTH..].copy_from_slice(&salt);
                stream.write_all(&handshake_buffer).await?;

                // receive the peer's public key
                let mut peer_public_key_bytes = [0u8; PUBLIC_KEY_LENGTH];
                let len = stream.read(&mut peer_public_key_bytes).await?;
                if len != PUBLIC_KEY_LENGTH {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid key length received",
                    ));
                }
                let peer_public_key = UnparsedPublicKey::new(&X25519, peer_public_key_bytes);

                // compute shared secret for this peer
                let shared_secret = compute_shared_secret(private_key, peer_public_key, &salt)
                    .map_err(|_| Error::new(ErrorKind::Other, "Failed computing shared secret"))?;

                // store it
                self.add_peer(conn.addr(), PeerData::new(shared_secret))?;
            }
            ConnectionSide::Responder => {
                // receive the peer's public key and random salt
                let len = stream.read(&mut handshake_buffer).await?;
                if len != PUBLIC_KEY_LENGTH + SALT_LENGTH {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid handshake data received",
                    ));
                }
                let peer_public_key =
                    UnparsedPublicKey::new(&X25519, &handshake_buffer[..PUBLIC_KEY_LENGTH]);
                let salt = &handshake_buffer[PUBLIC_KEY_LENGTH..];

                // send own public key
                stream.write_all(public_key.as_ref()).await?;

                // compute shared secret for this peer
                let shared_secret = compute_shared_secret(private_key, peer_public_key, salt)
                    .map_err(|_| Error::new(ErrorKind::Other, "Failed computing shared secret"))?;

                // store it
                self.add_peer(conn.addr(), PeerData::new(shared_secret))?;
            }
        };

        Ok(conn)
    }
}

/// Computes the shared secret with an ephemeral private key and the given public key
fn compute_shared_secret<B: AsRef<[u8]>>(
    my_private_key: EphemeralPrivateKey,
    peer_public_key: UnparsedPublicKey<B>,
    salt: &[u8],
) -> Result<SharedSecret, Unspecified> {
    agree_ephemeral(
        my_private_key,
        &UnparsedPublicKey::new(&X25519, peer_public_key.as_ref()),
        |key_material| {
            // initialize salt
            let salt = Salt::new(HKDF_SHA256, salt);
            // generate a prk from the shared secret and the salt using hmac
            let prk = salt.extract(key_material);
            // add context info and generate okm
            let info: &[&[u8]] = &[b"shared session key"];
            let okm = prk.expand(info, HKDF_SHA256).expect("HKDF expand failed");
            // write derived keying material into session key
            let mut session_key = [0u8; 32];
            okm.fill(&mut session_key).expect("fill failed");
            // return as vec
            session_key.to_vec().into()
        },
    )
}

#[cfg(test)]
mod tests {

    use super::*;
    use pea2pea::{connect_nodes, Topology};
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn basic_node_handshake() {
        // two test nodes
        let initiator = SimpleNode::new("initiator");
        let responder = SimpleNode::new("responder");

        // enable handshake for both test nodes
        for node in [&initiator, &responder] {
            node.enable_handshake().await;
        }

        // responder needs to listen for incoming connections
        let responder_addr = responder.node().start_listening().await.unwrap();

        // initiator now attempts to connect
        initiator.node().connect(responder_addr).await.unwrap();

        // give it a second
        let _ = sleep(Duration::from_secs(1));

        // get initiator socket addr (using the responder's address book)
        let responder_connections = responder.node().connection_infos();
        let initiator_addr = responder_connections.values().next().unwrap();

        // check the mutually agreed secrets
        let pd_initiator = initiator.peer_data(responder_addr);
        let pd_responder = responder.peer_data(initiator_addr.addr());

        // make sure they match
        assert!(pd_initiator.is_some());
        assert!(pd_responder.is_some());
        let peer_initiator = pd_initiator.unwrap();
        let peer_responder = pd_responder.unwrap();
        assert_eq!(peer_initiator.shared_secret, peer_responder.shared_secret);
    }

    #[tokio::test]
    async fn linear_nodes() {
        const NODE_COUNT: usize = 10;
        const LAST_NODE: usize = NODE_COUNT - 1;

        // create some nodes
        let mut nodes = Vec::with_capacity(NODE_COUNT);
        for i in 0..NODE_COUNT {
            let name = format!("Node {}", i);
            nodes.push(SimpleNode::new(&name));
        }

        // enable handshake
        for node in &nodes {
            node.enable_handshake().await;
            node.node().start_listening().await.unwrap();
        }

        // connect nodes linearly
        connect_nodes(&nodes, Topology::Line).await.unwrap();

        // give it a second
        let _ = sleep(Duration::from_secs(1));

        for i in 0..NODE_COUNT - 1 {
            // all nodes except the first and last should have 2 connections
            match i {
                0 | LAST_NODE => assert_eq!(1, nodes[i].node.connected_addrs().len()),
                _ => assert_eq!(2, nodes[i].node.connected_addrs().len()),
            }
            // make sure they all have a shared secret with the next node (linear)
            let next_node_addr = nodes[i + 1].node.listening_addr().unwrap();
            let pd = nodes[i].peer_data(next_node_addr);
            assert!(pd.is_some_and(|d| !d.shared_secret.as_bytes().is_empty()));
            // no other nodes should've handshaked
            for j in 0..NODE_COUNT {
                if j != i + 1 {
                    let other_node_addr = nodes[j].node.listening_addr().unwrap();
                    let pd = nodes[i].peer_data(other_node_addr);
                    assert!(pd.is_none())
                }
            }
        }
    }

    #[tokio::test]
    async fn mesh_nodes() {
        const NODE_COUNT: usize = 10;

        // create some nodes
        let mut nodes = Vec::with_capacity(NODE_COUNT);
        for i in 0..NODE_COUNT {
            let name = format!("Node {}", i);
            nodes.push(SimpleNode::new(&name));
        }

        // enable handshake
        for node in &nodes {
            node.enable_handshake().await;
            node.node().start_listening().await.unwrap();
        }

        // connect nodes in a mesh
        connect_nodes(&nodes, Topology::Mesh).await.unwrap();

        // give it a second
        let _ = sleep(Duration::from_secs(2));

        // all nodes should have 9 connections (all peers)
        for i in 0..NODE_COUNT {
            assert_eq!(NODE_COUNT - 1, nodes[i].node.connected_addrs().len());
        }
    }
}
