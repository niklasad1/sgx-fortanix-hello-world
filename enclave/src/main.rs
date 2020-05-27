#[cfg(not(target_env = "sgx"))]
std::compile_error!("Enclave must be built for --target x86_64-fortanix-unknown-sgx");

use attestation::Attestation;
use std::net::TcpListener;
use crypto::key_agreement::EphemeralKeypair;
use types::error::Error;

const SOCKADDR: &str = "127.0.0.1:63001";

mod attestation;

fn main() -> Result<(), Error> {
    println!("[ENCLAVE]: starting at {}", SOCKADDR);
    let mut client_stream = TcpListener::bind(SOCKADDR)?.accept()?.0;
    let (master_key, signing_key) = Attestation::new(EphemeralKeypair::new(), &mut client_stream).attest()?;

    println!("[ENCLAVE]: signing_key: {:?}", signing_key);
    println!("[ENCLAVE]: master_key: {:?}", master_key);

    // open a direct stream using master and signing key....

    Ok(())
}
