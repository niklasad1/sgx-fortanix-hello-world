use std::net::TcpListener;

use attestation::ServiceProviderAttestation;
use crypto::key_agreement::EphemeralKeypair;
use types::error::Error;

mod attestation;
mod ias;

const SOCKADDR: &str = "127.0.0.1:63004";

fn main() -> Result<(), Error> {
    println!("[SERVICE PROVIDER]: starting listener: {}", SOCKADDR);

    let ephemeral_key = EphemeralKeypair::new();
    let listener = TcpListener::bind(SOCKADDR)?;
    let mut client_stream = listener.accept()?.0;
    let (master_key, signing_key) = ServiceProviderAttestation::new(&mut client_stream, ephemeral_key).attest()?;

    println!(
        "[SERVICE PROVIDER]: master_key: {:?} signing_key: {:?}",
        master_key, signing_key
    );

    Ok(())
}
