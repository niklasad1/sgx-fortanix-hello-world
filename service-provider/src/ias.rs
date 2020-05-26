//! API for communication the Intel Attestation Service via HTTP(s)
//!
//! The interface is based on <https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf>
//!
//! What is PSE Manifest??

use crypto::x509::Certificate;
use hyper::{body::to_bytes, client, Body, Request};
use serde::Deserialize;
use tokio::runtime::Runtime;

const INTEL_ROOT_CERT: &[u8] = std::include_bytes!("../../Intel_SGX_Attestation_RootCA.pem");

const IAS_REPORT_URL: &str = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report";
const IAS_SIGRL_URL: &str = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/sigrl";

pub const SPID: &str = "5ADBE60B563D4BC970ED2EAC0916FD72";
pub const API_KEY: &str = "e9589de0dfe5482588600a73d08b70f6";

/// Certificate chain
///
/// 1) Attestation Report Signing CA Certificate:CN=Intel SGX Attestation Report Signing CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US
/// 2) Attestation Report Signing Certificate:CN=Intel SGX Attestation Report Signing, O=Intel Corporation, L=Santa Clara, ST=CA, C=US 
pub struct ReportSigningCertificateChain {
    root: Certificate,
    leaf: Certificate,
}

impl ReportSigningCertificateChain {
    pub fn new(certs: Vec<Certificate>, root: &Certificate) -> Self {
      let (root, leaf) = if &certs[0] == root {
        (0, 1)
      } else {
        (1, 0)
      };

      Self { root: certs[root].clone(), leaf: certs[leaf].clone() }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationReport {
    id: String,
    timestamp: String,
    /// Possible values:
    ///
    /// "OK"
    /// "SIGNATURE_INVALID–EPID"
    /// "GROUP_REVOKED–TheEPID"
    /// "SIGNATURE_REVOKED"
    /// "KEY_REVOKED"
    /// "SIGRL_VERSION_MISMATCH"
    /// "GROUP_OUT_OF_DATE"
    pub isv_enclave_quote_status: String,
    isv_enclave_quote_body: String,
    revocation_reason: Option<String>,
    pse_manifest_status: Option<String>,
    pse_manifest_hash: Option<String>,
    pub platform_info_blob: Option<String>,
    nonce: Option<String>,
    // only for linkable
    epid_pseudonym: Option<String>,
    advisory_url: Option<String>,
    advisory_ids: Option<String>,
}

pub fn get_report(quote: &[u8]) -> AttestationReport {
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

        if res.status().as_u16() != 200 {
            panic!("[SERVICE PROVIDER]: verify attestation evidence request failed");
        }

        // TODO: cache this with lazy_static or something
        let mut root_cert = Certificate::from_pem(INTEL_ROOT_CERT);

        let ias_report_signature = base64::decode(res.headers().get("X-IASReport-Signature").unwrap().as_bytes()).unwrap();
        let ias_certs_pem = res.headers().get("X-IASReport-Signing-Certificate").unwrap().as_bytes().to_vec();
        let ias_certs_pem: Vec<u8> = percent_encoding::percent_decode(&ias_certs_pem).collect();


        let certs: Vec<Certificate> = pem::parse_many(&ias_certs_pem).iter().map(|pem| Certificate::from_pem(&pem.contents)).collect();
        let mut cert_chain = ReportSigningCertificateChain::new(certs, &root_cert);
        cert_chain.leaf.verify_certificate(&mut root_cert).expect("verify_certificate failed");
        let bytes = to_bytes(res.into_body()).await.unwrap();
        cert_chain.leaf.verify_signature(&bytes, &ias_report_signature).expect("verify_signature failed");
        assert_eq!(root_cert, cert_chain.root, "root cert =! certification chain root");

        serde_json::from_slice(&bytes).unwrap()
    };

    let mut rt = Runtime::new().unwrap();
    rt.block_on(fut)
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
        to_bytes(res.into_body()).await
    };

    let mut rt = Runtime::new().unwrap();
    rt.block_on(fut).unwrap().to_vec()
}
