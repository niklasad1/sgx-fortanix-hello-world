use std::io::{Read, Write};
use std::net::TcpListener;

use attestation_types::*;
use crypto::ephemeral_diffie_hellman::Keypair as EphemeralKeypair;
use crypto::key_derivation;

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
    let sig_rl = ias::signature_revocation_list_request(msg1.gid);
    
    // 3. Compute shared secret, derive shared key and build message two
    let g_b: Public = ephemeral_key.public_key().into();
    let kdf_id: u32 = 1;
    let quote_kind: u32 = 0;
    let spid: Spid = Spid::from_slice(&hex::decode(ias::SPID).unwrap());

    let g_ab = ephemeral_key.shared_secret(msg1.g_a.into());
    let kdk = key_derivation::generate_kdk(g_ab);
    let smk = key_derivation::generate_smk(&kdk);

    let mut mac_input: Vec<u8> = Vec::new();
     
    mac_input.extend(g_b.as_bytes());
    mac_input.extend(spid.as_bytes());
    mac_input.extend(&quote_kind.to_be_bytes());
    mac_input.extend(&kdf_id.to_be_bytes());
    mac_input.extend(g_ab.as_bytes());
    mac_input.extend(sig_rl.clone());

    let mac = crypto::mac::cmac_aes128(smk.as_bytes(), &mac_input);

    let msg2 = MessageTwo {
        g_b,
        spid,
        quote_kind,
        g_ab,
        sig_rl,
        kdf_id,
        mac
    };

    bincode::serialize_into(&mut stream, &msg2).unwrap();

    loop {}

    Ok(())
}
