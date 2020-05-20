use std::io::{Read, Write};
use std::net::TcpStream;
use crypto::verification_key::{Keypair as VerificationKeypair};
use crypto::ephemeral_diffie_hellman::{Keypair as EphemeralKeypair};
use crypto::intel::SPID_SIZE;

type SigningKey = ();
type MasterKey = ();

pub fn attest(verification_key: VerificationKeypair, mut ephemeral_key: EphemeralKeypair, mut stream: TcpStream) -> (SigningKey, MasterKey) {
    // 1. Send: public key
    let g_e = ephemeral_key.public_key();
    stream.write_all(&g_e).unwrap();
    println!("[ENCLAVE]: 1) tx g_e: {:?}", g_e);

    // 2. Read: (g_b || SPID || g_ab)
    let mut msg2 = vec![0; 32 + SPID_SIZE + 32];
    stream.read_exact(&mut msg2).unwrap();
    println!("[ENCLAVE]: 2) rx (g_c || spid || g_ce");

    let mut g_c = [0_u8; 32];
    g_c.copy_from_slice(&msg2[0..32]);
    let spid: Vec<u8> = msg2.iter().cloned().skip(32).take(SPID_SIZE).collect();
    let g_ce: Vec<u8> = msg2.iter().cloned().skip(32 + SPID_SIZE).collect();

    println!("[ENCLAVE]: 2) g_c: {:?}", g_c);;
    println!("[ENCLAVE]: 2) spid: {:?}", spid);;
    println!("[ENCLAVE]: 2) g_ce: {:?}", g_ce);;

    let g_ec = ephemeral_key.shared_secret(g_c);
    assert_eq!(g_ce, g_ec.to_vec());

    // 3: Send MAC(Quote)

    println!("attest");
    ((), ())
}
