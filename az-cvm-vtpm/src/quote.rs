use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Quote {
    pub signature: Vec<u8>,
    pub message: Vec<u8>,
    pub pcrs: Vec<[u8; 32]>,
}
