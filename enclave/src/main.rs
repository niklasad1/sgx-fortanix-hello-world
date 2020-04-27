use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::TcpListener;

use rand_core::RngCore;
use rdrand::RdRand;

const SOCKADDR: &str = "127.0.0.1:65000";

fn main() -> std::io::Result<()> {
    let mut rng = RdRand::new().unwrap();

    println!("Enclave RNG Generator Service running on: {}", SOCKADDR);

    let listener = TcpListener::bind(SOCKADDR)?;

    // accept connections and process them serially
    for stream in listener.incoming() {
        let s = stream?;

        let mut r = BufReader::new(s.try_clone()?);
        let mut w = BufWriter::new(s);
        let mut rx = String::new();
        r.read_line(&mut rx)?;
        println!("Received RNG request");

        let rand = rng.next_u64();
        println!("Enclave RNG; generated random number = {}", rand);

        let reply = format!("SGX random number={}\r\n", rand);
        w.write(reply.as_ref())?;
    }
    Ok(())
}
