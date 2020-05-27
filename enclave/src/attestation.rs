use std::io::Write;
use std::net::TcpStream;

use common::{QuoteManifest, RemoteAttestation};
use crypto::key_agreement::EphemeralKeypair;
use crypto::key_derivation;
use sgx_isa::{Report, Targetinfo};
use types::*;
use types::error::Error;
use types::attestation_messages::*;

pub struct StageOne {
    g_a: H256,
}

pub struct StageTwo {
    g_a: H256,
    msg2: MessageTwo,
}

pub struct StageThree {
    kdk: H128,
}

pub struct Attestation<'a> {
    ephemeral_key: EphemeralKeypair,
    client_stream: &'a mut TcpStream,
}

impl<'a> Attestation<'a> {
    pub fn new(ephemeral_key: EphemeralKeypair, client_stream: &'a mut TcpStream) -> Self {
        Self { client_stream, ephemeral_key }
    }

    pub fn attest(mut self) -> Result<(H128, H128), Error> {
        let stage = self.stage_one()?;
        let stage = self.stage_two(stage)?;
        let stage = self.stage_three(stage)?;
        self.stage_four(stage)
    }
}

impl<'a> RemoteAttestation for Attestation<'a> {
    type Error = Error;
    type Output = (H128, H128);

    type Stage1 = StageOne;
    type Stage2 = StageTwo;
    type Stage3 = StageThree;

    fn stage_one(&mut self) -> Result<Self::Stage1, Self::Error> {
        let g_a = self.ephemeral_key.public_key();
        println!("[ENCLAVE]: client stream established; start attestation");
        // Initialize enclave context; Send public key the client
        bincode::serialize_into(&mut self.client_stream, &g_a)?;
        Ok(StageOne { g_a })
    }

    fn stage_two(&mut self, input: Self::Stage1) -> Result<Self::Stage2, Self::Error> {
        let msg2: MessageTwo = bincode::deserialize_from(&mut self.client_stream)?;
        println!("[ENCLAVE]: received msg2: {:?}", msg2);
        Ok(StageTwo { g_a: input.g_a, msg2 })
    }

    fn stage_three(&mut self, input: Self::Stage2) -> Result<Self::Stage3, Self::Error> {
        // TODO: shared secret should be digitally signed and verified here...
        let g_ab = self.ephemeral_key.shared_secret(input.msg2.g_b.into());

        if g_ab != input.msg2.g_ab {
           return Err(Error::Custom(format!("Shared secret secret agreement failed; g_ab: {} g_b: {}", g_ab, input.msg2.g_ab)));
        }

        let kdk = key_derivation::generate_kdk(input.msg2.g_ab);
        let smk = key_derivation::generate_smk(&kdk);

        if !input.msg2.verify(&smk, crypto::mac::cmac_aes128_verify) {
           return Err(Error::Custom("cmac_aes128 failed".to_string()));
        }

        // 3. Build  `MessageThree`
        let vk = key_derivation::generate_vk(&kdk);
        let digest = QuoteManifest::new(input.g_a.as_fixed_bytes(), input.msg2.g_b.as_fixed_bytes(), vk.as_fixed_bytes());

        let q = quote(digest.as_fixed_bytes(), &mut self.client_stream)?;
        let ps_security_prop: Vec<u8> = Vec::new();

        let msg3 = MessageThree::new(input.g_a, ps_security_prop, q, crypto::mac::cmac_aes128, &smk);
        bincode::serialize_into(&mut self.client_stream, &msg3)?;

        Ok(StageThree { kdk })
    }

    fn stage_four(&mut self, input: Self::Stage3) -> Result<(H128, H128), Self::Error> {
        let msg4: MessageFour = bincode::deserialize_from(&mut self.client_stream)?;
        println!("[ENCLAVE]: msg4: {:?}", msg4);
        Ok((key_derivation::generate_mk(&input.kdk), key_derivation::generate_sk(&input.kdk)))
    }
}


fn quote(manifest_data: &[u8; 64], mut stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let qe_target_info: Vec<u8> = bincode::deserialize_from(&mut stream)?;

    let target_info = Targetinfo::try_copy_from(&qe_target_info).ok_or_else(|| Error::Custom("TargetInfo from the quoting enclave couldn't be decoded".to_string()))?;

    // TODO: check why `serialize_into` doesn't work, probably deserialization/serialization thingy w.r.t to alignment in the Report
    let report = Report::for_target(&target_info, manifest_data);
    stream.write_all(report.as_ref())?;

    let quote: Vec<u8> = bincode::deserialize_from(&mut stream)?;
    // TODO: verify quoting report
    let _quote_report: Vec<u8> = bincode::deserialize_from(&mut stream)?;

    Ok(quote)
}
