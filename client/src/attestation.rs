use std::net::TcpStream;

use aesm_client::{AesmClient, QuoteType};
use attestation_types::*;
use crypto::ephemeral_diffie_hellman::Keypair as EphemeralKeypair;

pub fn attest(aesm_client: AesmClient, mut enclave_stream: TcpStream, mut sp_stream: TcpStream) {
    let quote_info = aesm_client.init_quote().unwrap();
    let gid = quote_info.gid().to_vec();

    // This is assigned to zero because we use Intel Attestation Service
    let msg0 = MessageZero { extended_gid: 0 };

    let g_a: Public = bincode::deserialize_from(&mut enclave_stream).unwrap();
    let msg1 = MessageOne { g_a, gid };

    // 1. Send MessageZero and MessageOne to the service provider
    bincode::serialize_into(&mut sp_stream, &msg0).unwrap();
    bincode::serialize_into(&mut sp_stream, &msg1).unwrap();
    println!("[CLIENT] sent msg0 and msg1 to [SERVICE PROVIDER]");

    // 2. Receive `MessageTwo` from the service provider
    let msg2: MessageTwo = bincode::deserialize_from(&mut sp_stream).unwrap();
    println!("[CLIENT] received msg2: {:?}", msg2);

    // 2. Send `MessageTwo` to the enclave
    bincode::serialize_into(&mut enclave_stream, &msg2).unwrap();
    println!("[CLIENT] sent msg2 to [ENCLAVE]");


    loop {}
}
