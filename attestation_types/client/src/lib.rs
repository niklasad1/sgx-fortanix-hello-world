use std::net::TcpStream;

use attestation::{EnclaveHello, ClientHello, QuoteReport};
use crate::{ClientHello, EnclaveHello, QuoteReport};
use crypto::ephemeral_diffie_hellman::Keypair as EphemeralKeypair;

pub fn attest(ephemeral_key: EphemeralKeypair, mut client_stream: TcpStream) {
    // 1. Receive `EnclaveHello`
    let enclave_hello: EnclaveHello = bincode::deserialize_from(&mut client_stream).unwrap();
    println!("[CLIENT]: enclave_hello: {:?}", enclave_hello);

    // 2. Send ClientHello
    let client_hello = ClientHello {
        g_c: ephemeral_key.public_key(),
        g_ce: ephemeral_key.shared_secret(enclave_hello.g_e),
    };
    bincode::serialize_into(&mut client_stream, &client_hello).unwrap();
    println!("[CLIENT]: client_hello: {:?}", client_hello);

    // 3. Receive `QuoteReport`
    let quote: QuoteReport = bincode::deserialize_from(&mut client_stream).unwrap();
    println!("[CLIENT]: quote {:?}", quote);
}



fn https_client() {

}
