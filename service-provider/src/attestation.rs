use std::net::TcpStream;

use types::*;
use types::attestation_messages::*;
use types::error::Error;
use common::{QuoteManifest, RemoteAttestation};
use crypto::key_agreement::EphemeralKeypair;
use crypto::key_derivation;

pub struct ServiceProviderAttestation<'a> {
    client_stream: &'a mut TcpStream,
    ephemeral_key: EphemeralKeypair
}

impl<'a> ServiceProviderAttestation<'a> {
    pub fn new(client_stream: &'a mut TcpStream, ephemeral_key: EphemeralKeypair) -> Self {
        Self { client_stream, ephemeral_key }
    }

    pub fn attest(mut self) -> Result<(H128, H128), Error> {
        let state = self.stage_one()?;
        let state = self.stage_two(state)?;
        let state = self.stage_three(state)?;
        self.stage_four(state)
    }
}

pub struct StageOne {
    msg0: MessageZero,
    msg1: MessageOne
}

pub struct StageTwo {
    msg1: MessageOne,
    msg2: MessageTwo,
    kdk: H128,
    smk: H128,
}

pub struct StageThree {
    msg1: MessageOne,
    msg2: MessageTwo,
    msg3: MessageThree,
    kdk: H128,
    smk: H128,
}

impl<'a> RemoteAttestation for ServiceProviderAttestation<'a> {
    type Error = Error;
    type Output = (H128, H128);

    type Stage1 = StageOne;
    type Stage2 = StageTwo;
    type Stage3 = StageThree;

    fn stage_one(&mut self) -> Result<Self::Stage1, Self::Error> {
        let msg0: MessageZero = bincode::deserialize_from(&mut self.client_stream)?;
        let msg1: MessageOne = bincode::deserialize_from(&mut self.client_stream)?;
        println!("[SERVICE PROVIDER]: received msg0: {:?}", msg0);
        println!("[SERVICE PROVIDER]: received msg1 {:?}", msg1);
        Ok(StageOne { msg0, msg1 })
    }

    fn stage_two(&mut self, input: Self::Stage1) -> Result<Self::Stage2, Self::Error> {
        // 2. Fetch signature revocation list from Intel
        let sig_rl = crate::ias::get_signature_revocation_list(input.msg1.gid.clone());

        // 3. Compute shared secret, derive shared key and build message two
        let g_b: Public = self.ephemeral_key.public_key();
        let quote_kind: u32 = 0;
        let spid: Spid = hex::decode(crate::ias::SPID).map_err(|e| format!("SPID couldn't be hex decoded {}", e))?;

        let g_ab = self.ephemeral_key.shared_secret(input.msg1.g_a);
        let kdk = key_derivation::generate_kdk(g_ab);
        let smk = key_derivation::generate_smk(&kdk);

        let msg2 = MessageTwo::new(
            g_ab,
            g_b,
            quote_kind,
            sig_rl,
            spid,
            &smk,
            crypto::mac::cmac_aes128
        );

        bincode::serialize_into(&mut self.client_stream, &msg2)?;
        Ok(StageTwo { msg1: input.msg1, msg2, kdk, smk })
    }

    fn stage_three(&mut self, input: Self::Stage2) -> Result<Self::Stage3, Self::Error> {
        let msg3: MessageThree = bincode::deserialize_from(&mut self.client_stream)?;
        println!("[SERVICE PROVIDER]: received msg3");
        Ok(StageThree { msg1: input.msg1, msg2: input.msg2, msg3, kdk: input.kdk, smk: input.smk })
    }

    fn stage_four(&mut self, input: Self::Stage3) -> Result<Self::Output, Self::Error> {
        //4. Validation before creating MessageFour
        if input.msg1.g_a != input.msg3.g_a {
            return Err(Error::Custom("Different g_a received in msg1 and msg3".to_string()));
        }

        if !input.msg3.verify(&input.smk, crypto::mac::cmac_aes128_verify) {
            return Err(Error::Custom("BAD CMAC".to_string()));
        }

        let vk = key_derivation::generate_vk(&input.kdk);
        let quote_manifest = QuoteManifest::new(input.msg3.g_a.as_fixed_bytes(), input.msg2.g_b.as_fixed_bytes(), vk.as_fixed_bytes());

        if quote_manifest.as_bytes() != &input.msg3.quote[368..432] {
            return Err(Error::Custom("BAD REPORTDATA".to_string()));
        }

        // send quote to `IAS`
        //
        // 1. validate certificate signature
        // 2. validate report signature
        let attestation_report = crate::ias::get_report(&input.msg3.quote);

        println!("[SERVICE PROVIDER]: {:?}", attestation_report);

        // TODO: proper verification
        println!("[SERVICE PROVIDER]: Quote MRSIGNER: {:?}", &input.msg3.quote[176..208]);
        println!("[SERVICE PROVIDER]: Quote MRENCLAVE: {:?}", &input.msg3.quote[112..144]);
        println!("[SERVICE PROVIDER]: Quote CPUSVN: {:?}", &input.msg3.quote[48..64]);
        println!("[SERVICE PROVIDER]: Quote ISVSVN: {:?}", &input.msg3.quote[306..308]);

        let mk = key_derivation::generate_mk(&input.kdk);
        let sk = key_derivation::generate_sk(&input.kdk);

        let msg4 = MessageFour {
           enclave_trusted: true,
           pse_trusted: false,
        };

        bincode::serialize_into(&mut self.client_stream, &msg4)?;
        println!("[SERVICE PROVIDER]: signing_key: {:?}", sk);
        println!("[SERVICE PROVIDER]: master_key: {:?}", mk);

        Ok((mk, sk))
    }
}
