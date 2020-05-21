use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use crypto::ephemeral_diffie_hellman::Keypair as EphemeralKeypair;
use crypto::verification_key::Keypair as VerificationKeypair;
use sgx_isa::{Report, Targetinfo};

use crate::*;

// TODO(digital signature of shared secret)
pub fn attest(
    _verification: VerificationKeypair,
    ephemeral_key: EphemeralKeypair,
    mut client_stream: TcpStream,
    quote_sockaddr: SocketAddr,
) {
    let g_e = ephemeral_key.public_key();
    // 1. Send `EnclaveHello`
    let enclave_hello = EnclaveHello { g_e };
    bincode::serialize_into(&mut client_stream, &enclave_hello).unwrap();
    println!("[ENCLAVE]: enclave_hello: {:?}", enclave_hello);

    // 2. Read ClientHello
    let client_hello: ClientHello = bincode::deserialize_from(&mut client_stream).unwrap();
    println!("[ENCLAVE]: client_hello: {:?}", client_hello);

    let g_ec = ephemeral_key.shared_secret(client_hello.g_c);
    assert_eq!(client_hello.g_ce, g_ec);

    // g_ec and g_ce is now our `shared secret key`
    let mut digest = [0_u8; 64];
    let mut verification_report = Vec::new();
    verification_report.extend(g_e.iter());
    verification_report.extend(client_hello.g_c.iter());
    crypto::hash::sha256(&verification_report, &mut digest);
    //
    let q = quote(digest, quote_sockaddr);
    println!("quote: {:?}", q);
    //

    // 3: Send Quote
    let quote_report = QuoteReport { q };
    bincode::serialize_into(&mut client_stream, &quote_report).unwrap();

    // 4. .... TODO
}

fn quote(manifest_data: [u8; 64], quote: SocketAddr) -> Vec<u8> {
    let mut stream = TcpStream::connect(quote).unwrap();
    let mut qe_target_info = [0u8; Targetinfo::UNPADDED_SIZE];
    stream.read_exact(&mut qe_target_info).unwrap();

    let target_info = Targetinfo::try_copy_from(&qe_target_info).unwrap();
    let report = Report::for_target(&target_info, &manifest_data);
    stream.write_all(report.as_ref()).unwrap();

    // TODO(verify this length...)
    let mut quote = vec![0u8; 1116];
    stream.read_exact(&mut quote[..]).unwrap();
    let mut qe_report = vec![0u8; 432];
    stream.read_exact(&mut qe_report[..]).unwrap();

    quote
}
