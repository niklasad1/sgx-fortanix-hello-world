use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use aesm_client::{AesmClient, QuoteType};
use sgx_isa::Report;

pub struct Config {
    pub spid: Vec<u8>,
    pub revocation_list: Vec<u8>,
    pub quote_kind: u32
}

/// Starts a TCP server that waits for `Quoting requests`, it connects to the `Quoting Enclave`
/// Using the `aesmd service (/var/run/aesmd/)`
pub fn run(address: &'static str, config: Config) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener = TcpListener::bind(address).expect("Tcp bind failed");
        println!("[Quoting]: Starting at {}", address);

        let client = AesmClient::new();
        let quote_info = client.init_quote().expect("init quote failed");
        let nonce = vec![0_u8; 16];

        for stream in listener.incoming() {
            println!("Quoting Request");
            let mut stream = stream.expect("faulty stream received");
            stream.write_all(quote_info.target_info()).unwrap();
            let mut report = vec![0u8; Report::UNPADDED_SIZE];
            stream.read_exact(&mut report[..]).unwrap();

            let quote = client
                .get_quote(
                    // &quote_info,
                    report,
                    config.spid.clone(),
                    config.revocation_list.clone(),
                    QuoteType::from_u32(config.quote_kind).unwrap(),
                    nonce.clone(),
                )
                .expect("quoting failed");
            stream.write_all(quote.quote()).unwrap();
            stream.write_all(quote.qe_report()).unwrap();

            println!("[QE]: quoting succeed");
        }
    })
}
