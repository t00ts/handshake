use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(test, derive(Clone))]
#[derive(Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    /// Creates a new `SharedSecret` from a `Vec<u8>`
    pub fn new(secret: Vec<u8>) -> Self {
        SharedSecret(secret)
    }

    /// Access the inner secret bytes
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SharedSecret {
    fn from(value: Vec<u8>) -> Self {
        SharedSecret::new(value)
    }
}

#[test]
fn test_secret() {
    // example secret
    let secret_bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    // a copy to check later
    let secret_unsafe_copy = secret_bytes.clone();

    // the `new` constructor takes ownership of the original `secret_bytes`
    let shared_secret = SharedSecret::new(secret_bytes);

    assert_eq!(&secret_unsafe_copy, shared_secret.as_bytes())

    // the actual `SharedSecret` will be zeroized when it goes out of scope
}
