use std::io::{Read, Write};
use std::net::TcpStream;

use aesm_client::{AesmClient, QuoteInfo, QuoteType};
use attestation_types::*;
use sgx_isa::Report;

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

    // 2 a) Receive `MessageTwo` from the service provider
    let msg2: MessageTwo = bincode::deserialize_from(&mut sp_stream).unwrap();
    println!("[CLIENT] received msg2: {:?}", msg2);

    // 2 b). Send `MessageTwo` to the enclave
    bincode::serialize_into(&mut enclave_stream, &msg2).unwrap();
    println!("[CLIENT] sent msg2 to [ENCLAVE]");

    quote(
        &mut enclave_stream,
        &aesm_client,
        &quote_info,
        msg2.spid.clone(),
        msg2.sig_rl.clone(),
        QuoteType::from_u32(msg2.quote_kind).unwrap(),
        vec![0_u8; 16],
    );

    let msg3: MessageThree = bincode::deserialize_from(&enclave_stream).unwrap();
    println!("[CLIENT]: received msg3");
    bincode::serialize_into(&mut sp_stream, &msg3).unwrap();

    loop {}
}

fn quote(
    mut stream: &mut TcpStream,
    aesm_client: &AesmClient,
    quote_info: &QuoteInfo,
    spid: Vec<u8>,
    sig_rl: Vec<u8>,
    quote_kind: QuoteType,
    nonce: Vec<u8>,
) {
    bincode::serialize_into(&mut stream, quote_info.target_info()).unwrap();

    // TODO: check why `deserialize_from` doesn't work here
    let mut report = vec![0u8; Report::UNPADDED_SIZE];
    stream.read_exact(&mut report[..]).unwrap();

    let quote = aesm_client
        .get_quote(report, spid, sig_rl, quote_kind, nonce)
        .unwrap();
    bincode::serialize_into(&mut stream, quote.quote()).unwrap();
    bincode::serialize_into(&mut stream, quote.qe_report()).unwrap();
}
