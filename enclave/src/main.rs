#[cfg(not(target_env = "sgx"))]
std::compile_error!("Enclave must be built for --target x86_64-fortanix-unknown-sgx");

use std::net::{TcpListener, SocketAddr};
use crypto::ephemeral_diffie_hellman::{Keypair as EphemeralKeypair};

const SOCKADDR: &str = "127.0.0.1:63001";

mod attestation;

fn main() -> std::io::Result<()> {
    println!("[ENCLAVE]: starting at {}", SOCKADDR);
    let client_stream = TcpListener::bind(SOCKADDR)?.accept()?.0;
    let (master_key, signing_key) = attestation::attest(EphemeralKeypair::new(), client_stream);

    println!("[ENCLAVE]: signing_key: {:?}", signing_key);
    println!("[ENCLAVE]: master_key: {:?}", master_key);

    Ok(())
}
