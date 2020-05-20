#!/usr/bin/env bash

TARGET=./target/x86_64-fortanix-unknown-sgx/release/enclave
TARGET_SGXS=$TARGET.sgxs
TARGET_SIGN=$TARGET.sign
PRIVATE_KEY=private.pem
PUBLIC_KEY=public.pem

if [ ! -f $PRIVATE_KEY ]; then
    openssl genrsa -3 3072 > $PRIVATE_KEY
    openssl rsa -in $PRIVATE_KEY -pubout > $PUBLIC_KEY
fi

cargo build -p runner --release
cargo build -p enclave --target=x86_64-fortanix-unknown-sgx --release
ftxsgx-elf2sgxs $TARGET --heap-size 0x20000 --stack-size 0x20000 --threads 6 --debug
# sign the enclave
sgxs-sign --key $PRIVATE_KEY $TARGET_SGXS $TARGET_SIGN -d --xfrm 7/0 --isvprodid 0 --isvsvn 0
./target/release/runner $TARGET_SGXS $TARGET_SIGN
