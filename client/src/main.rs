use std::net::TcpStream;
use std::path::Path;
use std::{thread, time};

use aesm_client::AesmClient;
use crypto::ephemeral_diffie_hellman::Keypair as EphemeralKeypair;
use enclave_runner::{Command as EnclaveRunner, EnclaveBuilder};
use sgxs_loaders::isgx::Device as IsgxDevice;

mod attestation;

const ENCLAVE_SOCKADDR: &str = "127.0.0.1:63001";
const SERVICE_PROVIDER_SOCKADDR: &str = "127.0.0.1:63004";

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

    thread::sleep(time::Duration::from_secs(5));

    println!("[CLIENT]: loaded enclave");

    // initiate remote attestation
    let enclave_stream = TcpStream::connect(ENCLAVE_SOCKADDR)?;
    let sp_stream = TcpStream::connect(SERVICE_PROVIDER_SOCKADDR)?;
    let aesm_client = AesmClient::new();
    attestation::attest(aesm_client, enclave_stream, sp_stream);

    // secure channel established.....!

    loop {}
}
