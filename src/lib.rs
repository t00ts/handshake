// lib.rs

use std::{io::{self, ErrorKind}, sync::{Arc, Mutex}};
use pea2pea::{protocols::Handshake, Config, Connection, ConnectionSide, Node, Pea2Pea};
use ring::{agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519}, error::Unspecified, hkdf::{Salt, HKDF_SHA256}, rand::SystemRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};


/// Length (in bytes) of the public key exchanged during the handshake
const PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Default)]
struct NodeData {
    shared_secret: Vec<u8>,
    nonce: u64,
}

/// A simple P2P node that implements a basic diffie-hellman handshake
#[derive(Clone)]
pub struct DhNode {
    node: Node,
    data: Arc<Mutex<NodeData>>
}

impl Pea2Pea for DhNode {
    fn node(&self) -> &Node {
        &self.node
    }
}


impl DhNode {

    pub fn new(name: &str) -> Self {
        let cfg = Config{
            name: Some(name.into()),
            ..Default::default()
        };
        Self {
            node: Node::new(cfg),
            data: Arc::new(Mutex::new(NodeData::default())),
        }
    }

    #[cfg(test)]
    fn shared_secret(&self) -> Option<Vec<u8>> {
        self.data.lock()
            .and_then(|data| Ok(data.shared_secret.clone()))
            .ok()
    }

}

impl Handshake for DhNode {

    async fn perform_handshake(&self, mut conn: Connection) -> io::Result<Connection> {

        // initialize a random number generator
        let rng = SystemRandom::new();

        // generate an ephemeral key pair
        let private_key = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_| io::Error::new(ErrorKind::Other, "Failed creating ephemeral private key"))?;
        let public_key = private_key.compute_public_key()
            .map_err(|_| io::Error::new(ErrorKind::Other, "Failed computing private key"))?;

        // buffer to read the public key being exchanged
        let mut public_key_bytes = [0u8; PUBLIC_KEY_LENGTH];

        // the actual tcp stream
        let node_conn_side = !conn.side();
        let stream = self.borrow_stream(&mut conn);

        match node_conn_side {
            ConnectionSide::Initiator => {

                // send public key
                stream.write_all(public_key.as_ref()).await?;

                // receive the peer's public key
                let len = stream.read(&mut public_key_bytes).await?;
                if len != PUBLIC_KEY_LENGTH {
                    return Err(io::Error::new(ErrorKind::InvalidData, "Invalid key length received"));
                }
                let peer_public_key = UnparsedPublicKey::new(&X25519, public_key_bytes);

                // compute and store shared secret
                let mut node_data = self.data.lock()
                    .map_err(|_| io::Error::new(ErrorKind::Other, "Mutex lock failed"))?;
                node_data.shared_secret = compute_shared_secret(private_key, peer_public_key)
                    .map_err(|_| io::Error::new(ErrorKind::Other, "Failed computing shared secret"))?;

            }
            ConnectionSide::Responder => {

                // receive the peer's public key
                let len = stream.read(&mut public_key_bytes).await?;
                if len != PUBLIC_KEY_LENGTH {
                    return Err(io::Error::new(ErrorKind::InvalidData, "Invalid key length received"));
                }
                let peer_public_key = UnparsedPublicKey::new(&X25519, public_key_bytes);

                // send own public key
                stream.write_all(public_key.as_ref()).await?;

                // compute and store shared secret
                let mut node_data = self.data.lock()
                    .map_err(|_| io::Error::new(ErrorKind::Other, "Mutex lock failed"))?;
                node_data.shared_secret = compute_shared_secret(private_key, peer_public_key)
                    .map_err(|_| io::Error::new(ErrorKind::Other, "Failed computing shared secret"))?;

            }
        };

        Ok(conn)

    }

}


/// Computes the shared secret with an ephemeral private key and the given public key
fn compute_shared_secret<B: AsRef<[u8]>>(my_private_key: EphemeralPrivateKey, peer_public_key: UnparsedPublicKey<B>) -> Result<Vec<u8>, Unspecified> {
    agree_ephemeral(
        my_private_key,
        &UnparsedPublicKey::new(&X25519, peer_public_key.as_ref()),
        |key_material| {
            let salt = Salt::new(HKDF_SHA256, &[1,3,3,7]);
            let prk = salt.extract(key_material);
            let info: &[&[u8]] = &[b"shared session key"];
            let okm = prk.expand(info, HKDF_SHA256).expect("HKDF expand failed");
            let mut session_key = [0u8; 32];
            okm.fill(&mut session_key).expect("fill failed");
            session_key.to_vec()
        }
    )
}


#[cfg(test)]
mod tests {

    use super::*;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn test_node_handshake() {

        // two test nodes
        let initiator = DhNode::new("initiator");
        let responder = DhNode::new("responder");

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

        // check the agreed secrets
        let secret_initiator = initiator.shared_secret();
        let secret_responder = responder.shared_secret();

        // make sure they match
        assert!(secret_initiator.is_some());
        assert!(secret_responder.is_some());
        assert_eq!(secret_initiator, secret_responder);
    
    }

}