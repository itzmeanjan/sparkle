#pragma once
#include "sparkle.hpp"
#include <cstring>

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

// FeistelSwap - invoked from combined feedback function `𝜌`,  which is used for
// differentiating between cipher text & outer part of permutation state
//
// See section 2.3.2 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
//
// Note, `s` is 128 -bit wide i.e.
//
// `s1 || s2 = s` meaning |s1| = |s2| = RATE >> 1 = 64 -bit
//
// To be more specific, `s` is actually outer part of permutation state !
static inline void
feistel_swap(uint32_t* const __restrict s)
{
  std::swap(s[0], s[2]);
  std::swap(s[1], s[3]);

  s[2] ^= s[0];
  s[3] ^= s[1];
}

// Feedback function `𝜌1`, used during Schwaemm128-128 Authenticated Encryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rho1(uint32_t* const __restrict s,      // 128 -bit
     const uint32_t* const __restrict d // 128 -bit
)
{
  feistel_swap(s);

  for (size_t i = 0; i < 4; i++) {
    s[i] ^= d[i];
  }
}

// Feedback function `𝜌2`, used during Schwaemm128-128 Authenticated Encryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rho2(uint32_t* const __restrict s,      // 128 -bit
     const uint32_t* const __restrict d // 128 -bit
)
{
  for (size_t i = 0; i < 4; i++) {
    s[i] ^= d[i];
  }
}

// Inverse Feedback function `𝜌'1`, used during Schwaemm128-128 Verified
// Decryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rhoprime1(uint32_t* const __restrict s,      // 128 -bit
          const uint32_t* const __restrict d // 128 -bit
)
{
  uint32_t s_[4];
  std::memcpy(s_, s, 16);

  feistel_swap(s);

  for (size_t i = 0; i < 4; i++) {
    s[i] ^= s_[i] ^ d[i];
  }
}

// Inverse Feedback function `𝜌'2`, used during Schwaemm128-128 Authenticated
// Decryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rhoprime2(uint32_t* const __restrict s,      // 128 -bit
          const uint32_t* const __restrict d // 128 -bit
)
{
  for (size_t i = 0; i < 4; i++) {
    s[i] ^= d[i];
  }
}

}
