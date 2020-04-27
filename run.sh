#!/usr/bin/bash

cargo build -p runner
cargo build -p enclave --target=x86_64-fortanix-unknown-sgx
ftxsgx-elf2sgxs ./target/x86_64-fortanix-unknown-sgx/debug/enclave --heap-size 0x20000 --stack-size 0x20000 --threads 6 --debug
./target/debug/runner ./target/x86_64-fortanix-unknown-sgx/debug/enclave.sgxs
