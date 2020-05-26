#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

INTEL_CERT_URL="https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem"
INTEL_ROOT_CERT=Intel_SGX_Attestation_RootCA.pem
TARGET=./target/x86_64-fortanix-unknown-sgx/release/enclave
TARGET_SGXS=$TARGET.sgxs
TARGET_SIGN=$TARGET.sign
PRIVATE_KEY=private.pem
PUBLIC_KEY=public.pem
CLIENT=./target/release/client
SERVICE_PROVIDER=./target/release/service-provider


if [ ! -f $INTEL_ROOT_CERT ]; then
  curl -O $INTEL_CERT_URL
fi

if [ ! -f $PRIVATE_KEY ]; then
    openssl genrsa -3 3072 > $PRIVATE_KEY
    openssl rsa -in $PRIVATE_KEY -pubout > $PUBLIC_KEY
fi

trap 'kill $BGPID; exit' INT
cargo build -p service-provider --release
cargo build -p client --release
cargo build -p enclave --target=x86_64-fortanix-unknown-sgx --release
ftxsgx-elf2sgxs $TARGET --heap-size 0x20000 --stack-size 0x20000 --threads 6 --debug
# sign the enclave
sgxs-sign --key $PRIVATE_KEY $TARGET_SGXS $TARGET_SIGN -d --xfrm 7/0 --isvprodid 0 --isvsvn 0
$CLIENT $TARGET_SGXS $TARGET_SIGN &
BGPID=$!
$SERVICE_PROVIDER
