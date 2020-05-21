use std::net::TcpStream;
use std::path::Path;
use std::{thread, time};

use aesm_client::{AesmClient, QuoteType};
use crypto::ephemeral_diffie_hellman::Keypair as EphemeralKeypair;
use enclave_runner::{Command as EnclaveRunner, EnclaveBuilder};
use sgxs_loaders::isgx::Device as IsgxDevice;

mod attestation;
mod quoting;

const ENCLAVE_SOCKADDR: &str = "127.0.0.1:63001";
const QUOTING_SOCKADDR: &str = "127.0.0.1:63002";
const SPID: &str = "5ADBE60B563D4BC970ED2EAC0916FD72";

fn usage(name: &String) {
    println!("Usage:\n{} <path_to_sgxs_file, signature>", name);
}

fn parse_args() -> Result<(String, String), ()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 {
        Ok((args[1].clone(), args[2].clone()))
    } else {
        usage(&args[0]);
        Err(())
    }
}

fn build_enclave() -> EnclaveRunner {
    let (enclave, enclave_signature) = parse_args().unwrap();
    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();
    let mut enclave_builder = EnclaveBuilder::new(enclave.as_ref());
    enclave_builder
        .signature(Path::new(&enclave_signature))
        .unwrap();
    enclave_builder.build(&mut device).unwrap()
}

fn run_enclave() -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let enclave = build_enclave();
        enclave
            .run()
            .map_err(|e| {
                println!("Error while executing SGX enclave.\n{}", e);
                std::process::exit(1)
            })
            .unwrap();
    })
}

fn main() -> std::io::Result<()> {
    let _enclave = run_enclave();
    let quote_config = quoting::Config {
        spid: hex::decode(SPID).unwrap(),
        revocation_list: Vec::new(),
        quote_kind: QuoteType::Unlinkable.into(),
    };
    let _quote = quoting::run(QUOTING_SOCKADDR, quote_config);

    thread::sleep(time::Duration::from_secs(5));

    let ephemeral_key = EphemeralKeypair::new();

    // initiate remote attestation
    let stream = TcpStream::connect(ENCLAVE_SOCKADDR)?;
    attestation::attest(ephemeral_key, stream);

    // secure channel established.....!

    loop {}
}
