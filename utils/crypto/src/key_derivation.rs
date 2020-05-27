use crate::mac;
use types::{H128, H256};

/// Generate key derivation key
pub fn generate_kdk(mut g_ab: H256) -> H128 {
    let key = [0_u8; 16];
    g_ab.as_bytes_mut().reverse();
    mac::cmac_aes128(&key.into(), g_ab.as_bytes())
}

pub fn generate_smk(kdk: &H128) -> H128 {
    const BYTES: [u8; 7] = [0x01, 'S' as u8, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    mac::cmac_aes128(kdk, &BYTES)
}

/// Generate secret key
pub fn generate_sk(kdk: &H128) -> H128 {
    const BYTES: [u8; 6] = [0x01, 'S' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    mac::cmac_aes128(kdk, &BYTES)
}

/// Generate verification key
pub fn generate_mk(kdk: &H128) -> H128 {
    const BYTES: [u8; 6] = [0x01, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    mac::cmac_aes128(kdk, &BYTES)
}

/// Generate verification key
pub fn generate_vk(kdk: &H128) -> H128 {
    const BYTES: [u8; 6] = [0x01, 'V' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    mac::cmac_aes128(kdk, &BYTES)
}
