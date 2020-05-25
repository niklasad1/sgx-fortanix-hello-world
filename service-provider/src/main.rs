use std::io::{Read, Write};
use std::net::TcpListener;

use attestation_types::*;
use crypto::ephemeral_diffie_hellman::Keypair as EphemeralKeypair;
use crypto::key_derivation;
use sgx_isa::Report;

mod ias;

const SOCKADDR: &str = "127.0.0.1:63004";

fn main() -> std::io::Result<()> {
    println!("[SERVICE PROVIDER]: starting listener: {}", SOCKADDR);

    let ephemeral_key = EphemeralKeypair::new();

    let listener = TcpListener::bind(SOCKADDR)?;
    let mut stream = listener.accept()?.0;

    //1. Read MessageZero and MessageOne
    let msg0: MessageZero = bincode::deserialize_from(&mut stream).unwrap();
    let msg1: MessageOne = bincode::deserialize_from(&mut stream).unwrap();
    println!("[SERVICE PROVIDER]: received msg0: {:?}", msg0);
    println!("[SERVICE PROVIDER]: received msg1 {:?}", msg1);

    // 2. Fetch signature revocation list from Intel
    let sig_rl = ias::get_signature_revocation_list(msg1.gid);

    // 3. Compute shared secret, derive shared key and build message two
    let g_b: Public = ephemeral_key.public_key().into();
    let quote_kind: u32 = 0;
    let spid: Spid = hex::decode(ias::SPID).unwrap();

    let g_ab = ephemeral_key.shared_secret(msg1.g_a.into());
    let kdk = key_derivation::generate_kdk(g_ab);
    let smk = key_derivation::generate_smk(&kdk);

    let msg2 = MessageTwo::new(
        g_ab,
        g_b,
        quote_kind,
        sig_rl,
        spid,
        &smk,
        crypto::mac::cmac_aes128
    );

    bincode::serialize_into(&mut stream, &msg2).unwrap();
    let msg3: MessageThree = bincode::deserialize_from(&mut stream).unwrap();
    println!("[SERVICE PROVIDER]: received msg3");

    //4. Validation before creating MessageFour 
    assert_eq!(msg1.g_a, msg3.g_a, "g_a in msg1 != g_b in msg3");
    assert!(msg3.verify(&smk, crypto::mac::cmac_aes128_verify), "mac in msg3 failed");
    let vk = key_derivation::generate_vk(&kdk);
    // println!("[SP]: g_a: {:?}", msg3.g_a);
    // println!("[SP]: g_b: {:?}", g_b);
    // println!("[SP]: kdk: {:?}", kdk);
    // println!("[SP]: smk: {:?}", smk);
    // println!("[SP]: vk: {:?}", vk);
    let quote_manifest = crypto::intel::quote_manifest(msg3.g_a, g_b, vk);

    // The deserialization doesn't seem the work properly... maybe I don't understand???
    // let r: Report = bincode::deserialize(&msg3.quote).unwrap();
    // println!("{:?}", r);

    assert_eq!(&quote_manifest[0..32], &msg3.quote[368..400], "reportdata mismatch");

    // send quote to `IAS`
    ias::get_report(&msg3.quote);

    loop {}
}
