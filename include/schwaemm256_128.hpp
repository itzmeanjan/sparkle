#pragma once
#include "sparkle.hpp"
#include <cstring>

// Schwaemm256-128 Authenticated Encryption with Associated Data ( AEAD ) Scheme
namespace schwaemm256_128 {

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

// FeistelSwap - invoked from combined feedback function `𝜌`,  which is used for
// differentiating between cipher text blocks & outer part of permutation state
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

// Feedback function `𝜌1`, used during Schwaemm256-128 Authenticated Encryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rho1(uint32_t* const __restrict s,      // 256 -bit
     const uint32_t* const __restrict d // 256 -bit
)
{
  feistel_swap(s);

  for (size_t i = 0; i < 8; i++) {
    s[i] ^= d[i];
  }
}

// Feedback function `𝜌2`, used during Schwaemm256-128 Authenticated Encryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rho2(uint32_t* const __restrict s,      // 256 -bit
     const uint32_t* const __restrict d // 256 -bit
)
{
  for (size_t i = 0; i < 8; i++) {
    s[i] ^= d[i];
  }
}

// Inverse Feedback function `𝜌'1`, used during Schwaemm256-128 Verified
// Decryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rhoprime1(uint32_t* const __restrict s,      // 256 -bit
          const uint32_t* const __restrict d // 256 -bit
)
{
  uint32_t s_[8];
  std::memcpy(s_, s, 32);

  feistel_swap(s);

  for (size_t i = 0; i < 8; i++) {
    s[i] ^= s_[i] ^ d[i];
  }
}

// Inverse Feedback function `𝜌'2`, used during Schwaemm256-128 Authenticated
// Decryption
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
rhoprime2(uint32_t* const __restrict s,      // 256 -bit
          const uint32_t* const __restrict d // 256 -bit
)
{
  for (size_t i = 0; i < 8; i++) {
    s[i] ^= d[i];
  }
}

// Rate whitening layer, applied to inner part of permutation state
static inline void
omega(const uint32_t* const __restrict in, // 128 -bit
      uint32_t* const __restrict out       // 256 -bit
)
{
  std::memcpy(out + 0, in, 16);
  std::memcpy(out + 4, in, 16);
}

// Consumes non-empty associated data into 384 -bit permutation state using
// algorithm 2.13 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
process_associated_data(
  uint32_t* const __restrict state,     // 384 -bit permutation state
  const uint8_t* const __restrict data, // N (>0) -bytes associated data
  const size_t d_len                    // len(data) = N -bytes | N > 0
)
{
  constexpr size_t RATE = 32; // bytes

  uint32_t buffer0[9];
  uint32_t buffer1[8];

  size_t r_bytes = d_len;
  while (r_bytes > RATE) {
    const size_t b_off = d_len - r_bytes;

    for (size_t i = 0; i < (RATE >> 2); i++) {
      const size_t i_off = i << 2;

      buffer0[i] = (static_cast<uint32_t>(data[b_off + (i_off ^ 3)]) << 24) |
                   (static_cast<uint32_t>(data[b_off + (i_off ^ 2)]) << 16) |
                   (static_cast<uint32_t>(data[b_off + (i_off ^ 1)]) << 8) |
                   (static_cast<uint32_t>(data[b_off + (i_off ^ 0)]) << 0);
    }

    rho1(state, buffer0);
    omega(state + 8, buffer1);

    for (size_t i = 0; i < (RATE >> 2); i++) {
      state[i] ^= buffer1[i];
    }

    sparkle::sparkle<6ul, 7ul>(state);

    r_bytes -= RATE;
  }

  const size_t b_off = d_len - r_bytes;
  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;

  std::memset(buffer0, 0, RATE);

  for (size_t i = 0; i < rb_full_words; i++) {
    const size_t off = i << 2;

    buffer0[i] = (static_cast<uint32_t>(data[b_off + (off ^ 3)]) << 24) |
                 (static_cast<uint32_t>(data[b_off + (off ^ 2)]) << 16) |
                 (static_cast<uint32_t>(data[b_off + (off ^ 1)]) << 8) |
                 (static_cast<uint32_t>(data[b_off + (off ^ 0)]) << 0);
  }

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  const size_t off = rb_full_words << 2;

  for (size_t i = 0; i < rb_rem_bytes; i++) {
    word |= static_cast<uint32_t>(data[b_off + off + i]) << (i << 3);
  }

  const uint32_t words[2] = { 0u, word };
  buffer0[rb_full_words] = words[rb_full_words < 8];

  rho1(state, buffer0);

  constexpr uint32_t consts[2] = { CONST_A1, CONST_A0 };
  state[11] ^= consts[rb_full_words < 8];

  omega(state + 8, buffer1);

  for (size_t i = 0; i < (RATE >> 2); i++) {
    state[i] ^= buffer1[i];
  }

  sparkle::sparkle<6ul, 11ul>(state);
}

// Consumes non-empty plain text data into 384 -bit permutation state, while
// producing equal many cipher text bytes, using algorithm 2.13 of Sparkle
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
process_plain_text(
  uint32_t* const __restrict state,    // 384 -bit permutation state
  const uint8_t* const __restrict txt, // N (>0) -bytes plain text
  uint8_t* const __restrict enc,       // N (>0) -bytes encrypted text
  const size_t ct_len                  // len(txt) = len(enc) = N | N > 0
)
{
  constexpr size_t RATE = 32; // bytes

  uint32_t buffer0[9];
  uint32_t buffer1[8];
  uint32_t buffer2[8];

  size_t r_bytes = ct_len;
  while (r_bytes > RATE) {
    const size_t b_off = ct_len - r_bytes;

    for (size_t i = 0; i < (RATE >> 2); i++) {
      const size_t i_off = i << 2;

      buffer0[i] = (static_cast<uint32_t>(txt[b_off + (i_off ^ 3)]) << 24) |
                   (static_cast<uint32_t>(txt[b_off + (i_off ^ 2)]) << 16) |
                   (static_cast<uint32_t>(txt[b_off + (i_off ^ 1)]) << 8) |
                   (static_cast<uint32_t>(txt[b_off + (i_off ^ 0)]) << 0);
    }

    std::memcpy(buffer2, state, RATE);
    rho2(buffer2, buffer0);

    for (size_t i = 0; i < (RATE >> 2); i++) {
      const size_t i_off = i << 2;

      enc[b_off + (i_off ^ 0)] = static_cast<uint8_t>(buffer2[i] >> 0);
      enc[b_off + (i_off ^ 1)] = static_cast<uint8_t>(buffer2[i] >> 8);
      enc[b_off + (i_off ^ 2)] = static_cast<uint8_t>(buffer2[i] >> 16);
      enc[b_off + (i_off ^ 3)] = static_cast<uint8_t>(buffer2[i] >> 24);
    }

    rho1(state, buffer0);
    omega(state + 8, buffer1);

    for (size_t i = 0; i < (RATE >> 2); i++) {
      state[i] ^= buffer1[i];
    }

    sparkle::sparkle<6ul, 7ul>(state);

    r_bytes -= RATE;
  }

  const size_t b_off = ct_len - r_bytes;
  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;
  const size_t w_off = rb_full_words << 2;

  std::memset(buffer0, 0, RATE);

  for (size_t i = 0; i < rb_full_words; i++) {
    const size_t i_off = i << 2;

    buffer0[i] = (static_cast<uint32_t>(txt[b_off + (i_off ^ 3)]) << 24) |
                 (static_cast<uint32_t>(txt[b_off + (i_off ^ 2)]) << 16) |
                 (static_cast<uint32_t>(txt[b_off + (i_off ^ 1)]) << 8) |
                 (static_cast<uint32_t>(txt[b_off + (i_off ^ 0)]) << 0);
  }

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  for (size_t i = 0; i < rb_rem_bytes; i++) {
    const size_t idx = b_off + w_off + i;

    word |= static_cast<uint32_t>(txt[idx]) << (i << 3);
  }

  const uint32_t words[2] = { 0u, word };
  buffer0[rb_full_words] = words[rb_full_words < 8];

  std::memcpy(buffer2, state, RATE);
  rho2(buffer2, buffer0);

  for (size_t i = 0; i < rb_full_words; i++) {
    const size_t i_off = i << 2;

    enc[b_off + (i_off ^ 0)] = static_cast<uint8_t>(buffer2[i] >> 0);
    enc[b_off + (i_off ^ 1)] = static_cast<uint8_t>(buffer2[i] >> 8);
    enc[b_off + (i_off ^ 2)] = static_cast<uint8_t>(buffer2[i] >> 16);
    enc[b_off + (i_off ^ 3)] = static_cast<uint8_t>(buffer2[i] >> 24);
  }

  for (size_t i = 0; i < rb_rem_bytes; i++) {
    const size_t idx = b_off + w_off + i;

    enc[idx] = static_cast<uint8_t>(buffer2[rb_full_words] >> (i << 3));
  }

  rho1(state, buffer0);

  constexpr uint32_t consts[2] = { CONST_M1, CONST_M0 };
  state[11] ^= consts[rb_full_words < 8];

  omega(state + 8, buffer1);

  for (size_t i = 0; i < (RATE >> 2); i++) {
    state[i] ^= buffer1[i];
  }

  sparkle::sparkle<6ul, 11ul>(state);
}

}
