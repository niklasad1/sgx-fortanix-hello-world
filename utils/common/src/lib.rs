/// Sha256( g_a | g_b | vk)
pub struct QuoteManifest([u8; 64]);

impl QuoteManifest {
    pub fn new(g_a: &[u8; 32], g_b: &[u8; 32], vk: &[u8; 16]) -> Self {
        let mut input: Vec<u8> = Vec::new();
        let mut digest = [0_u8; 64];

        input.extend(g_a);
        input.extend(g_b);
        input.extend(vk);
        crypto::hash::sha256(&input, &mut digest);
        Self(digest)
    }

    pub fn as_fixed_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Interface for remote attestation
pub trait RemoteAttestation {
    type Error: std::fmt::Debug;
    type Output;

    type Stage1;
    type Stage2;
    type Stage3;

    fn stage_one(&mut self) -> Result<Self::Stage1, Self::Error>;
    fn stage_two(&mut self, input: Self::Stage1) -> Result<Self::Stage2, Self::Error>;
    fn stage_three(&mut self, input: Self::Stage2) -> Result<Self::Stage3, Self::Error>;
    fn stage_four(&mut self, input: Self::Stage3) -> Result<Self::Output, Self::Error>;
}
