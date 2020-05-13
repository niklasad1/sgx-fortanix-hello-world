#![allow(unused)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::{thread, time};

use aesm_client::{AesmClient, QuoteType};
use enclave_runner::EnclaveBuilder;
use sgxs_loaders::isgx::Device as IsgxDevice;
use sgx_isa::Report;

// Intel IAS keys
const SPID: &str = "5ADBE60B563D4BC970ED2EAC0916FD72";
const PRIMARY_KEY: &str = "e9589de0dfe5482588600a73d08b70f6";

const ENCLAVE_SOCKADDR: &str = "127.0.0.1:63001";
const QUOTING_SOCKADDR: &str = "127.0.0.1:63002";

const SPID_SIZE: usize = 16;
const NONCE_SIZE: usize = 16;

fn usage(name: &String) {
    println!("Usage:\n{} <path_to_sgxs_file>", name);
}

fn parse_args() -> Result<String, ()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 {
        Ok(args[1].clone())
    } else {
        usage(&args[0]);
        Err(())
    }
}

fn main() {
    let file = parse_args().unwrap();

    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();

    let mut enclave_builder = EnclaveBuilder::new(file.as_ref());
    enclave_builder.dummy_signature();
    let enclave = enclave_builder.build(&mut device).unwrap();
    println!("Starting Quoting TCP Server: {}", QUOTING_SOCKADDR);

    let quote = thread::spawn(move || {
        let listener = TcpListener::bind(QUOTING_SOCKADDR).expect("Tcp bind failed");
        for stream in listener.incoming() {
            let mut stream = stream.expect("faulty stream received");
            let mut report = Vec::new();
            stream.read_to_end(&mut report).unwrap();

            let client = AesmClient::new();
            let quote_info = client.init_quote().expect("init quote failed");
            let revocation_list = Vec::new();
            let nonce = vec![0_u8; NONCE_SIZE];
            let spid: Vec<u8> = hex::decode(SPID).unwrap();

            println!("received EREPORT: {:?}", report);
            // println!("target_info: {:?}", quote_info);
            // println!("SPID: {:?}", spid);

            assert_eq!(spid.len(), SPID_SIZE);

            let quote = client.get_quote(
                &quote_info,
                report,
                spid,
                revocation_list,
                QuoteType::Unlinkable,
                nonce,
            ).expect("quoting failed");

            println!("quote epid: {:?}", quote.quote());
            println!("quote report: {:?}", quote.qe_report());
        }
    });

    thread::sleep(time::Duration::from_millis(20));

    enclave
        .run()
        .map_err(|e| {
            println!("Error while executing SGX enclave.\n{}", e);
            std::process::exit(1)
        })
        .unwrap();
}
