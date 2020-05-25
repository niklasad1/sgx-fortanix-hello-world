use aes::Aes128;
use attestation_types::H128;
use cmac::{Cmac, Mac};

pub fn cmac_aes128(key: &H128, data: &[u8]) -> H128 {
    let mut mac = Cmac::<Aes128>::new_varkey(key.as_bytes()).unwrap();
    mac.input(data);
    H128::from_slice(&mac.result().code())
}

pub fn cmac_aes128_verify(key: &H128, data: &[u8], other: &H128) -> bool {
    let current = cmac_aes128(key, data);
    &current == other
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let key = [0_u8; 16];
        let data = [0_u8, 1, 2, 3, 4, 5, 7];
        let mac = cmac_aes128(&key, &data);
        assert!(cmac_aes128_verify(&key, &data, &mac));
    }
}
