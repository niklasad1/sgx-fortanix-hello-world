use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use aesm_client::AesmClient;
use enclave_runner::EnclaveBuilder;
use sgxs_loaders::isgx::Device as IsgxDevice;

use futures::future;
use hyper::rt::Future;
use hyper::service::service_fn;
use hyper::{Body, Request, Response, Server};

type BoxFut = Box<dyn Future<Item = Response<Body>, Error = hyper::Error> + Send>;

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

fn fetch_enclave_randomness(_req: Request<Body>) -> BoxFut {
    let mut stream = TcpStream::connect("127.0.0.1:65000").unwrap();
    let _len = stream.write(b"GET SGX\r\n").unwrap();
    let mut stream = BufReader::new(stream);
    let mut sgx_reply = String::new();
    stream.read_line(&mut sgx_reply).unwrap();

    Box::new(future::ok(Response::new(Body::from(sgx_reply))))
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

    // let _handle = std::thread::spawn(move || {
    //     let addr = ([127, 0, 0, 1], 62000).into();
    //     let server = Server::bind(&addr)
    //         .serve(|| service_fn(fetch_enclave_randomness))
    //         .map_err(|e| eprintln!("server error: {}", e));
    //
    //     println!("HTTP Server listening on http://{}", addr);
    //     hyper::rt::run(server);
    // });

    enclave
        .run()
        .map_err(|e| {
            println!("Error while executing SGX enclave.\n{}", e);
            std::process::exit(1)
        })
        .unwrap();
}
