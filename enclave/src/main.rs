#![allow(unused)]

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
// use std::time::{SystemTime, UNIX_EPOCH};

// use chrono::prelude::*;

use aesm_client::sgx::AesmClientExt;
use aesm_client::AesmClient;

use serde::ser::Serialize;

// use mbedtls::hash::Type::Sha256;
// use mbedtls::pk::Pk;
// use mbedtls::rng::Rdrand;
// use mbedtls::ssl::config::{Endpoint, Preset, Transport};
// use mbedtls::ssl::{Config, Context};
// use mbedtls::x509::certificate::{Builder, Certificate};
// use mbedtls::x509::Time;
// use mbedtls::Result as TlsResult;

use sgx_isa::{Report, Targetinfo};

const SOCKADDR: &str = "127.0.0.1:63001";
const QUOTING_SOCKADDR: &str = "127.0.0.1:63002";

// Intel IAS keys
const SPID: &str = "5ADBE60B563D4BC970ED2EAC0916FD72";
const PRIMARY_KEY: &str = "e9589de0dfe5482588600a73d08b70f6";

fn main() -> std::io::Result<()> {
    // 1. generate report, ignore manifest data for now
    let report = Report::for_self();
    let targetinfo = Targetinfo::from(report.clone());
    // println!("targetinfo = {:?}", targetinfo);
    let mut user_data = [0_u8; 64];
    let report = Report::for_target(&targetinfo, &user_data);

    // println!("report MAC: {:?}", report.mac);
    // println!("report KEYID: {:?}", report.keyid);
    // println!("report CPUSVN: {:?}", report.cpusvn);
    // println!("report MRSIGNER: {:?}", report.mrsigner);
    // println!("report MRENCLAVE: {:?}", report.mrenclave);

    // 2. send for quoting
    let mut stream = TcpStream::connect(QUOTING_SOCKADDR)?;
    stream.write_all(report.as_ref())?;

    // let (mut key, mut cert) = get_key_and_cert();
    // let listener = TcpListener::bind(SOCKADDR).unwrap();
    //
    // println!("Enclave starting TLS Server: {}", SOCKADDR);
    //
    // for stream in listener.incoming() {
    //     println!("Tcp connection received");
    //     let stream = stream?;
    //     let _ = serve(stream, &mut key, &mut cert).unwrap();
    //     println!("Connection closed!");
    // }

    Ok(())
}
