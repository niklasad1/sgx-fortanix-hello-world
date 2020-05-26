use std::io::Write;
use std::net::TcpStream;

use attestation_types::*;
use crypto::ephemeral_diffie_hellman::Keypair as EphemeralKeypair;
use crypto::key_derivation;
use sgx_isa::{Report, Targetinfo};

pub fn attest(ephemeral_key: EphemeralKeypair, mut client_stream: TcpStream) -> (H128, H128) {
    println!("[ENCLAVE]: client stream established; start attestation");

    let g_a = ephemeral_key.public_key();

    // 1. Send public key the client
    bincode::serialize_into(&mut client_stream, &g_a).unwrap();

    // 2.
    let msg2: MessageTwo = bincode::deserialize_from(&mut client_stream).unwrap();
    println!("[ENCLAVE]: received msg2: {:?}", msg2);

    let g_ab = ephemeral_key.shared_secret(msg2.g_b.into());
    // TODO: this should be digitally signed and verified here...
    assert_eq!(g_ab, msg2.g_ab);
    let kdk = key_derivation::generate_kdk(msg2.g_ab);
    let smk = key_derivation::generate_smk(&kdk);

    assert!(msg2.verify(&smk, crypto::mac::cmac_aes128_verify), "mac in msg2 failed");

    // 3. Build  `MessageThree`
    //
    //  a) get quote
    //
    let vk = key_derivation::generate_vk(&kdk);
    // println!("[ENCLAVE]: g_a: {:?}", g_a);
    // println!("[ENCLAVE]: g_b: {:?}", msg2.g_b);
    // println!("[ENCLAVE]: kdk: {:?}", kdk);
    // println!("[ENCLAVE]: smk: {:?}", smk);
    // println!("[ENCLAVE]: vk: {:?}", vk);

    let digest = crypto::intel::quote_manifest(g_a, msg2.g_b, vk);

    let q = quote(&digest, &mut client_stream);
    let ps_security_prop: Vec<u8> = Vec::new();

    let msg3 = MessageThree::new(g_a, ps_security_prop, q, crypto::mac::cmac_aes128, &smk);

    bincode::serialize_into(&mut client_stream, &msg3).unwrap();
    let msg4: MessageFour = bincode::deserialize_from(&mut client_stream).unwrap();

    println!("[ENCLAVE]: msg4: {:?}", msg4);

    (key_derivation::generate_mk(&kdk), key_derivation::generate_sk(&kdk))
}


fn quote(manifest_data: &[u8; 64], mut stream: &mut TcpStream) -> Vec<u8> {
    let qe_target_info: Vec<u8> = bincode::deserialize_from(&mut stream).unwrap();

    let target_info = Targetinfo::try_copy_from(&qe_target_info).unwrap();
    // TODO: check why `serialize_into` doesn't work
    let report = Report::for_target(&target_info, manifest_data);
    stream.write_all(report.as_ref()).unwrap();

    let quote: Vec<u8> = bincode::deserialize_from(&mut stream).unwrap();
    let quote_report: Vec<u8> = bincode::deserialize_from(&mut stream).unwrap();

    quote
}
