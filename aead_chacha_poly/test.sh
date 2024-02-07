#! /usr/bin/bash
cargo build --release

echo "plaintext:"
hexdump -C ./tests/sunscreen.txt

echo "AAD:"
hexdump -C ./tests/adfile

echo "Key:"
hexdump -C ./tests/keyfile

echo "Nonce:"
echo "          07 00 00 00 40 41 42 43 44 45 46 47"

echo ""
echo "Computing tag:"

TAG=$(../target/release/aead_wrap ./tests/keyfile 070000004041424344454647 ./tests/adfile ./tests/sunscreen.txt ./ciphertext.bin)

echo $TAG

echo ""
echo "ciphertext:"
hexdump -C ./ciphertext.bin

echo ""
echo "Unwrapping with tag:"

../target/release/aead_unwrap ./tests/keyfile 070000004041424344454647 ./tests/adfile ./ciphertext.bin $TAG

rm ./ciphertext.bin

echo ""
