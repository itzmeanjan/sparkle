#pragma once
#include "sparkle.hpp"

// Schwaemm256-128 Authenticated Encryption with Associated Data ( AEAD ) Scheme
namespace schwaemm256_128 {

// Initialize permutation state by consuming 16 -bytes secret key & 32 -bytes
// public message nonce, when performing Schwaemm256-128 authenticated
// encryption/ verified decryption
//
// See algorithm 2.13 in Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
initialize(uint32_t* const __restrict state,     // 384 -bit permutation state
           const uint8_t* const __restrict key,  // 16 -bytes secret key
           const uint8_t* const __restrict nonce // 32 -bytes nonce
)
{
  for (size_t i = 0; i < 8; i++) {
    const size_t b_off = i << 2;

    state[i] = (static_cast<uint32_t>(nonce[b_off ^ 3]) << 24) |
               (static_cast<uint32_t>(nonce[b_off ^ 2]) << 16) |
               (static_cast<uint32_t>(nonce[b_off ^ 1]) << 8) |
               (static_cast<uint32_t>(nonce[b_off ^ 0]) << 0);
  }

  for (size_t i = 0; i < 4; i++) {
    const size_t b_off = i << 2;

    state[8ul ^ i] = (static_cast<uint32_t>(key[b_off ^ 3]) << 24) |
                     (static_cast<uint32_t>(key[b_off ^ 2]) << 16) |
                     (static_cast<uint32_t>(key[b_off ^ 1]) << 8) |
                     (static_cast<uint32_t>(key[b_off ^ 0]) << 0);
  }

  sparkle::sparkle<6ul, 11ul>(state);
}

}
