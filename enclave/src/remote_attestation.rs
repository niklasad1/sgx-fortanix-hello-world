use std::io::{Read, Write};
use std::net::TcpStream;
use crypto::{RsaVerificationKeypair, EphemeralKeypair};

type SigningKey = ();
type MasterKey = ();

pub fn attest(verification_key: RsaVerificationKeypair, mut ephemeral_key: EphemeralKeypair, mut stream: TcpStream) -> (SigningKey, MasterKey) {
    // 1. Send: public key
    let g_e = ephemeral_key.public();
    stream.write_all(&g_e).unwrap();
    println!("[ENCLAVE]: 1) tx g_e: {:?}", g_e);

    // 2. Read: (g_b || SPID || g_ab)
    let mut msg2 = vec![0; crypto::CURVE_25519_PUBLIC_KEY_SIZE + crypto::SPID_SIZE + crypto::CURVE_25519_SHARED_SECRET_SIZE];
    stream.read_exact(&mut msg2).unwrap();
    println!("[ENCLAVE]: 2) rx {:?}", msg2);

    let g_c: Vec<u8> = msg2.iter().cloned().take(crypto::CURVE_25519_PUBLIC_KEY_SIZE).collect();
    let spid: Vec<u8> = msg2.iter().cloned().skip(crypto::CURVE_25519_PUBLIC_KEY_SIZE).take(crypto::SPID_SIZE).collect();
    let g_ce: Vec<u8> = msg2.iter().cloned().skip(crypto::CURVE_25519_PUBLIC_KEY_SIZE + crypto::SPID_SIZE).collect();
    
    let g_ec = ephemeral_key.shared_secret(&g_c);
    println!("g_ec: {:?}", g_ec);
    println!("g_ce: {:?}", g_ce);

    // 3: Send MAC(Quote)

    println!("attest");
    ((), ())
}
