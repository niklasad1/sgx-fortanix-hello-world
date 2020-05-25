//! API for communication the Intel Attestation Service via http(s)
//!
//! The interface is based on <https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf>
//!

use hyper::{body::to_bytes, client, Body, Request};
use tokio::runtime::Runtime;

const IAS_REPORT_URL: &str = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report";
const IAS_SIGRL_URL: &str = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/sigrl";

pub const SPID: &str = "5ADBE60B563D4BC970ED2EAC0916FD72";
pub const API_KEY: &str = "e9589de0dfe5482588600a73d08b70f6";

pub fn get_report(quote: &[u8]) {
    let client: client::Client<_, hyper::Body> =
        client::Client::builder().build(hyper_rustls::HttpsConnector::new());

    let encoded_quote = base64::encode(&quote);
    let body = format!("{{\"isvEnclaveQuote\":\"{}\"}}", encoded_quote);
    let req = Request::post(IAS_REPORT_URL)
        .header("Content-Type", "application/json")
        .header("Ocp-Apim-Subscription-Key", API_KEY)
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

/// `attestation/v4/sigrl/{gid}`
///
/// Returns `Base 64-encoded SigRL for EPID group identified by {gid} parameter` in success and it
/// may be empty
pub fn get_signature_revocation_list(gid: Vec<u8>) -> Vec<u8> {
    let client: client::Client<_, hyper::Body> =
        client::Client::builder().build(hyper_rustls::HttpsConnector::new());
    let url = format!("{}/{}", IAS_SIGRL_URL, hex::encode(gid));

    let req = Request::get(url)
        .header("Content-Type", "application/json")
        .header("Ocp-Apim-Subscription-Key", API_KEY)
        .body(Body::empty())
        .unwrap();

    let fut = async move {
        let res = client.request(req).await?;

        if res.status().as_u16() != 200 {
            panic!("[SERVICE PROVIDER]: signature revocation list request failed");
        }

        // If the header has `content-length == 0`, the body should be empty so don't try read the
        // body then....
        if res
            .headers()
            .get("content-length")
            .map_or(false, |l| l == "0")
        {
            to_bytes(Body::empty()).await
        } else {
            to_bytes(res.into_body()).await
        }
    };

    let mut rt = Runtime::new().unwrap();
    rt.block_on(fut).unwrap().to_vec()
}
