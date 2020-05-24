use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use attestation_types::*;
use crypto::ephemeral_diffie_hellman::Keypair as EphemeralKeypair;
use crypto::verification_key::Keypair as VerificationKeypair;
use crypto::key_derivation;
use sgx_isa::{Report, Targetinfo};

use crate::*;

pub fn attest(
    _verification: VerificationKeypair,
    ephemeral_key: EphemeralKeypair,
    mut client_stream: TcpStream,
) {
    println!("[ENCLAVE]: client stream established; start attestation");

    // 1. Send public key the client
    bincode::serialize_into(&mut client_stream, &ephemeral_key.public_key()).unwrap();

    // 2.
    let msg2: MessageTwo = bincode::deserialize_from(&mut client_stream).unwrap();
    println!("[ENCLAVE]: received msg2: {:?}", msg2);

    let g_ab = ephemeral_key.shared_secret(msg2.g_b.into());
    // TODO: this should be digitally signed and verified here...
    assert_eq!(g_ab, msg2.g_ab);
    let kdk = key_derivation::generate_kdk(msg2.g_ab);
    let smk = key_derivation::generate_smk(&kdk);

    let mut mac_input: Vec<u8> = Vec::new();

    mac_input.extend(msg2.g_b.as_bytes());
    mac_input.extend(msg2.spid.as_bytes());
    mac_input.extend(&msg2.quote_kind.to_be_bytes());
    mac_input.extend(&msg2.kdf_id.to_be_bytes());
    mac_input.extend(g_ab.as_bytes());
    mac_input.extend(msg2.sig_rl.clone());

    // check that the MAC's is the same
    assert!(crypto::mac::cmac_aes128_verify(smk.as_bytes(), &mac_input, &msg2.mac));

    println!("[ENCLAVE]: TODO build message3");


    loop {}
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
