use std::io::Read;
use std::net::TcpStream;

use aesm_client::{AesmClient, QuoteInfo, QuoteType};
use common::RemoteAttestation;
use types::*;
use types::error::Error;
use types::attestation_messages::*;
use sgx_isa::Report;


pub struct StageOne;

pub struct StageTwo {
    msg2: MessageTwo
}

pub struct StageThree;

pub struct ClientAttestation<'a> {
    client: AesmClient,
    quote_info: QuoteInfo,
    enclave: &'a mut TcpStream,
    service_provider: &'a mut TcpStream
}

impl<'a> ClientAttestation<'a> {
    pub fn new(client: AesmClient, enclave: &'a mut  TcpStream, service_provider: &'a mut TcpStream) -> Self {
        let quote_info = client.init_quote().unwrap();
        Self { client, enclave, service_provider, quote_info }
    }

    pub fn attest(mut self) -> Result<(), Error> {
        let state = self.stage_one()?;
        let state = self.stage_two(state)?;
        let state = self.stage_three(state)?;
        self.stage_four(state)
    }
}

impl<'a> RemoteAttestation for ClientAttestation<'a> {
    type Error = Error;
    type Output = ();

    type Stage1 = StageOne;
    type Stage2 = StageTwo;
    type Stage3 = StageThree;

    fn stage_one(&mut self) -> Result<Self::Stage1, Self::Error> {
        let gid = self.quote_info.gid().to_vec();

        // This is assigned to zero because we use Intel Attestation Service
        let msg0 = MessageZero { extended_gid: 0 };

        let g_a: Public = bincode::deserialize_from(&mut self.enclave)?;
        let msg1 = MessageOne { g_a, gid };


        // 1. Send MessageZero and MessageOne to the service provider
        bincode::serialize_into(&mut self.service_provider, &msg0)?;
        bincode::serialize_into(&mut self.service_provider, &msg1)?;
        println!("[CLIENT] sent msg0 and msg1 to [SERVICE PROVIDER]");
        Ok(StageOne)
    }

    fn stage_two(&mut self, _input: Self::Stage1) -> Result<Self::Stage2, Self::Error> {
        let msg2: MessageTwo = bincode::deserialize_from(&mut self.service_provider)?;
        println!("[CLIENT] received msg2: {:?}", msg2);
        bincode::serialize_into(&mut self.enclave, &msg2)?;
        println!("[CLIENT] sent msg2 to [ENCLAVE]");
        Ok(StageTwo { msg2 })
    }

    fn stage_three(&mut self, input: Self::Stage2) -> Result<Self::Stage3, Self::Error> {
        quote(
            &mut self.enclave,
            &self.client,
            &self.quote_info,
            input.msg2.spid.clone(),
            input.msg2.sig_rl.clone(),
            QuoteType::from_u32(input.msg2.quote_kind).map_err(|e| Error::Custom(format!("{:?}", e)))?,
            vec![0_u8; 16],
        )?;

        let msg3: MessageThree = bincode::deserialize_from(&mut self.enclave)?;
        println!("[CLIENT]: received msg3");
        bincode::serialize_into(&mut self.service_provider, &msg3)?;
        Ok(StageThree)
    }

    fn stage_four(&mut self, _input: Self::Stage3) -> Result<Self::Output, Self::Error> {
        let msg4: MessageFour = bincode::deserialize_from(&mut self.service_provider)?;
        println!("[CLIENT]: received msg4: {:?}", msg4);
        bincode::serialize_into(&mut self.enclave, &msg4)?;
        println!("[CLIENT]: done");
        Ok(())
    }
}

// Reads the target info from the `quoting enclave` and passes it along the enclave
fn quote(
    mut stream: &mut TcpStream,
    aesm_client: &AesmClient,
    quote_info: &QuoteInfo,
    spid: Vec<u8>,
    sig_rl: Vec<u8>,
    quote_kind: QuoteType,
    nonce: Nonce,
) -> Result<(), Error> {
    bincode::serialize_into(&mut stream, quote_info.target_info())?;

    // TODO: check why `deserialize_from` doesn't work here
    let mut report = vec![0u8; Report::UNPADDED_SIZE];
    stream.read_exact(&mut report[..])?;

    let quote = aesm_client
        .get_quote(report, spid, sig_rl, quote_kind, nonce).map_err(|e| Error::Custom(format!("{:?}", e)))?;

    bincode::serialize_into(&mut stream, quote.quote())?;
    bincode::serialize_into(&mut stream, quote.qe_report()).map_err(Into::into)
}
