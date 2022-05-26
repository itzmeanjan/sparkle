#pragma once
#include "sparkle.hpp"

// Schwaemm128-128 Authenticated Encryption with Associated Data ( AEAD ) Scheme
namespace schwaemm128_128 {

// To distinguish padded associated data block from non-padded one, this
// constant is XORed into inner part of permutation state, when processing last
// associated data block
constexpr uint32_t CONST_A0 = (0u ^ (1u << 2)) << 24;

// To distinguish non-padded associated data block from padded one, this
// constant is XORed into inner part of permutation state, when processing last
// associated data block
constexpr uint32_t CONST_A1 = (1u ^ (1u << 2)) << 24;

// To distinguish padded plain text block from non-padded one, this constant is
// XORed into inner part of permutation state, when processing last plain text
// block
constexpr uint32_t CONST_M0 = (2u ^ (1u << 2)) << 24;

// To distinguish non-padded plain text block from padded one, this constant is
// XORed into inner part of permutation state, when processing last plain text
// block
constexpr uint32_t CONST_M1 = (3u ^ (1u << 2)) << 24;

// Initialize permutation state by consuming 16 -bytes secret key & 16 -bytes
// public message nonce, when performing Schwaemm128-128 authenticated
// encryption/ verified decryption
//
// See algorithm 2.17 in Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
initialize(uint32_t* const __restrict state,     // 256 -bit permutation state
           const uint8_t* const __restrict key,  // 16 -bytes secret key
           const uint8_t* const __restrict nonce // 16 -bytes nonce
)
{
  for (size_t i = 0; i < 4; i++) {
    const size_t b_off = i << 2;

    const size_t s_idx0 = i;
    const size_t s_idx1 = 4ul ^ i;

    state[s_idx0] = (static_cast<uint32_t>(nonce[b_off ^ 3]) << 24) |
                    (static_cast<uint32_t>(nonce[b_off ^ 2]) << 16) |
                    (static_cast<uint32_t>(nonce[b_off ^ 1]) << 8) |
                    (static_cast<uint32_t>(nonce[b_off ^ 0]) << 0);

    state[s_idx1] = (static_cast<uint32_t>(key[b_off ^ 3]) << 24) |
                    (static_cast<uint32_t>(key[b_off ^ 2]) << 16) |
                    (static_cast<uint32_t>(key[b_off ^ 1]) << 8) |
                    (static_cast<uint32_t>(key[b_off ^ 0]) << 0);
  }

  sparkle::sparkle<4ul, 10ul>(state);
}

}
