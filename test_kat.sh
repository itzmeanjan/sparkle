#!/bin/bash

# Script for ease of execution of Known Answer Tests against Sparkle implementation

# generate shared library object
make lib

# ---

mkdir -p tmp
pushd tmp

# download compressed NIST LWC submission of Sparkle
wget -O sparkle.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/sparkle.zip
# uncomress
unzip sparkle.zip

# copy Known Answer Tests outside of uncompressed NIST LWC submission directory
cp sparkle/Implementations/crypto_hash/esch256v2/LWC_HASH_KAT_256.txt ../
cp sparkle/Implementations/crypto_hash/esch384v2/LWC_HASH_KAT_384.txt ../
cp sparkle/Implementations/crypto_aead/schwaemm256128v2/LWC_AEAD_KAT_128_256.txt ../
cp sparkle/Implementations/crypto_aead/schwaemm192192v2/LWC_AEAD_KAT_192_192.txt ../
cp sparkle/Implementations/crypto_aead/schwaemm128128v2/LWC_AEAD_KAT_128_128.txt ../
cp sparkle/Implementations/crypto_aead/schwaemm256256v2/LWC_AEAD_KAT_256_256.txt ../

popd

# ---

# remove NIST LWC submission zip
rm -rf tmp

# move Known Answer Tests to execution directory
mv LWC_HASH_KAT_256.txt wrapper/python/
mv LWC_HASH_KAT_384.txt wrapper/python/
mv LWC_AEAD_KAT_128_256.txt wrapper/python/
mv LWC_AEAD_KAT_192_192.txt wrapper/python/
mv LWC_AEAD_KAT_128_128.txt wrapper/python/
mv LWC_AEAD_KAT_256_256.txt wrapper/python/

# ---

pushd wrapper/python

# run tests
python3 -m pytest -v

# clean up
rm LWC_*_KAT_*.txt

popd

make clean

# ---
