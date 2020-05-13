#!/usr/bin/env bash

cargo build -p runner --release
cargo build -p enclave --target=x86_64-fortanix-unknown-sgx --release
ftxsgx-elf2sgxs ./target/x86_64-fortanix-unknown-sgx/release/enclave --heap-size 0x20000 --stack-size 0x20000 --threads 6 --debug
./target/release/runner ./target/x86_64-fortanix-unknown-sgx/release/enclave.sgxs
