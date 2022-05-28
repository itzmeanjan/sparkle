#pragma once
#include "sparkle.hpp"
#include "utils.hpp"
#include <cstring>

// Schwaemm256-256 Authenticated Encryption with Associated Data ( AEAD ) Scheme
namespace schwaemm256_256 {

// These many bytes are consumed into permutation state, in every iteration
constexpr size_t RATE = 32;

// These many 32 -bit words are present in rate width of permutation
constexpr size_t RATE_W = RATE >> 2;

// To distinguish padded associated data block from non-padded one, this
// constant is XORed into inner part of permutation state, when processing last
// associated data block
constexpr uint32_t CONST_A0 = (0u ^ (1u << 4)) << 24;

// To distinguish non-padded associated data block from padded one, this
// constant is XORed into inner part of permutation state, when processing last
// associated data block
constexpr uint32_t CONST_A1 = (1u ^ (1u << 4)) << 24;

// To distinguish padded plain text block from non-padded one, this constant is
// XORed into inner part of permutation state, when processing last plain text
// block
constexpr uint32_t CONST_M0 = (2u ^ (1u << 4)) << 24;

// To distinguish non-padded plain text block from padded one, this constant is
// XORed into inner part of permutation state, when processing last plain text
// block
constexpr uint32_t CONST_M1 = (3u ^ (1u << 4)) << 24;

// Initialize permutation state by consuming 32 -bytes secret key & 32 -bytes
// public message nonce, when performing Schwaemm256-256 authenticated
// encryption/ verified decryption
//
// See algorithm 2.19 in Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
initialize(uint32_t* const __restrict state,     // 512 -bit permutation state
           const uint8_t* const __restrict key,  // 32 -bytes secret key
           const uint8_t* const __restrict nonce // 32 -bytes nonce
)
{

  for (size_t i = 0; i < RATE_W; i++) {
    const size_t b_off = i << 2;

    const size_t s_idx0 = i;
    const size_t s_idx1 = RATE_W ^ i;

    state[s_idx0] = (static_cast<uint32_t>(nonce[b_off ^ 3]) << 24) |
                    (static_cast<uint32_t>(nonce[b_off ^ 2]) << 16) |
                    (static_cast<uint32_t>(nonce[b_off ^ 1]) << 8) |
                    (static_cast<uint32_t>(nonce[b_off ^ 0]) << 0);

    state[s_idx1] = (static_cast<uint32_t>(key[b_off ^ 3]) << 24) |
                    (static_cast<uint32_t>(key[b_off ^ 2]) << 16) |
                    (static_cast<uint32_t>(key[b_off ^ 1]) << 8) |
                    (static_cast<uint32_t>(key[b_off ^ 0]) << 0);
  }

  sparkle::sparkle<RATE_W, 12ul>(state);
}

// FeistelSwap - invoked from combined feedback function `𝜌`,  which is used for
// differentiating between cipher text & outer part of permutation state
//
// See section 2.3.2 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
//
// Note, `s` is 256 -bit wide i.e.
//
// `s1 || s2 = s` meaning |s1| = |s2| = RATE >> 1 = 128 -bit
//
// To be more specific, `s` is actually outer part of permutation state !
static inline void
feistel_swap(uint32_t* const __restrict s)
{
  std::swap(s[0], s[4]);
  std::swap(s[1], s[5]);
  std::swap(s[2], s[6]);
  std::swap(s[3], s[7]);

  s[4] ^= s[0];
  s[5] ^= s[1];
  s[6] ^= s[2];
  s[7] ^= s[3];
}

// Feedback function `𝜌1`, used during Schwaemm256-256 Authenticated Encryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rho1(uint32_t* const __restrict s,      // 256 -bit
     const uint32_t* const __restrict d // 256 -bit
)
{
  feistel_swap(s);

  for (size_t i = 0; i < RATE_W; i++) {
    s[i] ^= d[i];
  }
}

// Feedback function `𝜌2`, used during Schwaemm256-256 Authenticated Encryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rho2(uint32_t* const __restrict s,      // 256 -bit
     const uint32_t* const __restrict d // 256 -bit
)
{
  for (size_t i = 0; i < RATE_W; i++) {
    s[i] ^= d[i];
  }
}

// Inverse Feedback function `𝜌'1`, used during Schwaemm256-256 Verified
// Decryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rhoprime1(uint32_t* const __restrict s,      // 256 -bit
          const uint32_t* const __restrict d // 256 -bit
)
{
  uint32_t s_[RATE_W];
  std::memcpy(s_, s, RATE);

  feistel_swap(s);

  for (size_t i = 0; i < RATE_W; i++) {
    s[i] ^= s_[i] ^ d[i];
  }
}

// Inverse Feedback function `𝜌'2`, used during Schwaemm256-256 Authenticated
// Decryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rhoprime2(uint32_t* const __restrict s,      // 256 -bit
          const uint32_t* const __restrict d // 256 -bit
)
{
  for (size_t i = 0; i < RATE_W; i++) {
    s[i] ^= d[i];
  }
}

}
