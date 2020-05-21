use std::net::TcpStream;

use attestation_types::{ClientHello, EnclaveHello, QuoteReport};
use crypto::ephemeral_diffie_hellman::Keypair as EphemeralKeypair;
use hyper::{body::to_bytes, client, Body, Request};
use tokio::runtime::Runtime;

const IAS_REPORT_URL: &str = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report";

pub fn attest(ephemeral_key: EphemeralKeypair, mut client_stream: TcpStream) {
    // 1. Receive `EnclaveHello`
    let enclave_hello: EnclaveHello = bincode::deserialize_from(&mut client_stream).unwrap();
    println!("[CLIENT]: enclave_hello: {:?}", enclave_hello);

    // 2. Send ClientHello
    let client_hello = ClientHello {
        g_c: ephemeral_key.public_key(),
        g_ce: ephemeral_key.shared_secret(enclave_hello.g_e),
    };
    bincode::serialize_into(&mut client_stream, &client_hello).unwrap();
    println!("[CLIENT]: client_hello: {:?}", client_hello);

    // 3. Receive `QuoteReport`
    let quote: QuoteReport = bincode::deserialize_from(&mut client_stream).unwrap();

    // Send Quote report to Intel Attestation Service (IAS)
    ias_request(quote);
}

fn ias_request(quote: QuoteReport) {
    let client: client::Client<_, hyper::Body> =
        client::Client::builder().build(hyper_rustls::HttpsConnector::new());

    let encoded_quote = base64::encode(&quote.q);
    let body = format!("{{\"isvEnclaveQuote\":\"{}\"}}", encoded_quote);
    let req = Request::post(IAS_REPORT_URL)
        .header("Content-Type", "application/json")
        .header("Ocp-Apim-Subscription-Key","e9589de0dfe5482588600a73d08b70f6")
        .body(Body::from(body))
        .unwrap();

    let fut = async move {
        let res = client.request(req).await.unwrap();
        println!("Status:\n{}", res.status());
        println!("Headers:\n{:#?}", res.headers());

        let body: Body = res.into_body();
        let body = to_bytes(body).await.unwrap();
        println!("Body:\n{}", String::from_utf8_lossy(&body));
        ()
    };

    let mut rt = Runtime::new().unwrap();
    rt.block_on(fut);
}
