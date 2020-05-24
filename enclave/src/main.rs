#[cfg(not(target_env = "sgx"))]
std::compile_error!("Enclave must be built for --target x86_64-fortanix-unknown-sgx");

use std::net::{TcpListener, SocketAddr};

use crypto::verification_key::{Keypair as VerificationKeypair};
use crypto::ephemeral_diffie_hellman::{Keypair as EphemeralKeypair};

const SOCKADDR: &str = "127.0.0.1:63001";
const PRIVATE_KEY_PEM: &[u8] = std::include_bytes!("../../private.pem");

mod attestation;

fn main() -> std::io::Result<()> {
    println!("[ENCLAVE]: starting at {}", SOCKADDR);
    let client_stream = TcpListener::bind(SOCKADDR)?.accept()?.0;
    attestation::attest(VerificationKeypair::from_private_key_pem_bytes(PRIVATE_KEY_PEM), EphemeralKeypair::new(), client_stream);

    Ok(())
}
