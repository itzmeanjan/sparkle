#pragma once
#include "sparkle.hpp"
#include "utils.hpp"
#include <cstring>

// Schwaemm256-128 Authenticated Encryption with Associated Data ( AEAD ) Scheme
namespace schwaemm256_128 {

// These many bytes are consumed into permutation state, in every iteration
constexpr size_t RATE = 32;

// These many 32 -bit words are present in rate width of permutation
constexpr size_t RATE_W = RATE >> 2;

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
  if constexpr (is_little_endian()) {
    std::memcpy(state, nonce, RATE);
  } else {
#if defined __clang__
#pragma unroll 4
#elif defined __GNUG__
#pragma GCC unroll 4
#endif
    for (size_t i = 0; i < 8; i++) {
      const size_t b_off = i << 2;

      state[i] = (static_cast<uint32_t>(nonce[b_off ^ 3]) << 24) |
                 (static_cast<uint32_t>(nonce[b_off ^ 2]) << 16) |
                 (static_cast<uint32_t>(nonce[b_off ^ 1]) << 8) |
                 (static_cast<uint32_t>(nonce[b_off ^ 0]) << 0);
    }
  }

  if constexpr (is_little_endian()) {
    std::memcpy(state + RATE_W, key, RATE >> 1);
  } else {
#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < 4; i++) {
      const size_t b_off = i << 2;

      state[8ul ^ i] = (static_cast<uint32_t>(key[b_off ^ 3]) << 24) |
                       (static_cast<uint32_t>(key[b_off ^ 2]) << 16) |
                       (static_cast<uint32_t>(key[b_off ^ 1]) << 8) |
                       (static_cast<uint32_t>(key[b_off ^ 0]) << 0);
    }
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

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < RATE_W; i++) {
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
#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < RATE_W; i++) {
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
  uint32_t s_[RATE_W];
  std::memcpy(s_, s, RATE);

  feistel_swap(s);

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < RATE_W; i++) {
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
#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < RATE_W; i++) {
    s[i] ^= d[i];
  }
}

// Rate whitening layer, applied to inner part of permutation state
static inline void
omega(const uint32_t* const __restrict in, // 128 -bit
      uint32_t* const __restrict out       // 256 -bit
)
{
  constexpr size_t bytes = RATE >> 1;

  std::memcpy(out + 0, in, bytes);
  std::memcpy(out + 4, in, bytes);
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
  uint32_t buffer0[RATE_W ^ 1];
  uint32_t buffer1[RATE_W];

  size_t r_bytes = d_len;
  while (r_bytes > RATE) {
    const size_t b_off = d_len - r_bytes;

    if constexpr (is_little_endian()) {
      std::memcpy(buffer0, data + b_off, RATE);
    } else {
#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        const size_t i_off = i << 2;

        buffer0[i] = (static_cast<uint32_t>(data[b_off + (i_off ^ 3)]) << 24) |
                     (static_cast<uint32_t>(data[b_off + (i_off ^ 2)]) << 16) |
                     (static_cast<uint32_t>(data[b_off + (i_off ^ 1)]) << 8) |
                     (static_cast<uint32_t>(data[b_off + (i_off ^ 0)]) << 0);
      }
    }

    rho1(state, buffer0);
    omega(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      state[i] ^= buffer1[i];
    }

    sparkle::sparkle<6ul, 7ul>(state);

    r_bytes -= RATE;
  }

  const size_t b_off = d_len - r_bytes;
  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;

  std::memset(buffer0, 0, RATE);

  if constexpr (is_little_endian()) {
    std::memcpy(buffer0, data + b_off, rb_full_words << 2);
  } else {
    for (size_t i = 0; i < rb_full_words; i++) {
      const size_t off = i << 2;

      buffer0[i] = (static_cast<uint32_t>(data[b_off + (off ^ 3)]) << 24) |
                   (static_cast<uint32_t>(data[b_off + (off ^ 2)]) << 16) |
                   (static_cast<uint32_t>(data[b_off + (off ^ 1)]) << 8) |
                   (static_cast<uint32_t>(data[b_off + (off ^ 0)]) << 0);
    }
  }

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  const size_t off = rb_full_words << 2;

  for (size_t i = 0; i < rb_rem_bytes; i++) {
    word |= static_cast<uint32_t>(data[b_off + off + i]) << (i << 3);
  }

  const uint32_t words[2] = { 0u, word };
  buffer0[rb_full_words] = words[rb_full_words < RATE_W];

  rho1(state, buffer0);

  constexpr uint32_t consts[2] = { CONST_A1, CONST_A0 };
  state[11] ^= consts[rb_full_words < RATE_W];

  omega(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < RATE_W; i++) {
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
  uint32_t buffer0[RATE_W ^ 1];
  uint32_t buffer1[RATE_W];
  uint32_t buffer2[RATE_W];

  size_t r_bytes = ct_len;
  while (r_bytes > RATE) {
    const size_t b_off = ct_len - r_bytes;

    if constexpr (is_little_endian()) {
      std::memcpy(buffer0, txt + b_off, RATE);
    } else {
#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        const size_t i_off = i << 2;

        buffer0[i] = (static_cast<uint32_t>(txt[b_off + (i_off ^ 3)]) << 24) |
                     (static_cast<uint32_t>(txt[b_off + (i_off ^ 2)]) << 16) |
                     (static_cast<uint32_t>(txt[b_off + (i_off ^ 1)]) << 8) |
                     (static_cast<uint32_t>(txt[b_off + (i_off ^ 0)]) << 0);
      }
    }

    std::memcpy(buffer2, state, RATE);
    rho2(buffer2, buffer0);

    if constexpr (is_little_endian()) {
      std::memcpy(enc + b_off, buffer2, RATE);
    } else {
#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        const size_t i_off = i << 2;

        enc[b_off + (i_off ^ 0)] = static_cast<uint8_t>(buffer2[i] >> 0);
        enc[b_off + (i_off ^ 1)] = static_cast<uint8_t>(buffer2[i] >> 8);
        enc[b_off + (i_off ^ 2)] = static_cast<uint8_t>(buffer2[i] >> 16);
        enc[b_off + (i_off ^ 3)] = static_cast<uint8_t>(buffer2[i] >> 24);
      }
    }

    rho1(state, buffer0);
    omega(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < RATE_W; i++) {
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

  if constexpr (is_little_endian()) {
    std::memcpy(buffer0, txt + b_off, rb_full_words << 2);
  } else {
    for (size_t i = 0; i < rb_full_words; i++) {
      const size_t i_off = i << 2;

      buffer0[i] = (static_cast<uint32_t>(txt[b_off + (i_off ^ 3)]) << 24) |
                   (static_cast<uint32_t>(txt[b_off + (i_off ^ 2)]) << 16) |
                   (static_cast<uint32_t>(txt[b_off + (i_off ^ 1)]) << 8) |
                   (static_cast<uint32_t>(txt[b_off + (i_off ^ 0)]) << 0);
    }
  }

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  for (size_t i = 0; i < rb_rem_bytes; i++) {
    const size_t idx = b_off + w_off + i;

    word |= static_cast<uint32_t>(txt[idx]) << (i << 3);
  }

  const uint32_t words[2] = { 0u, word };
  buffer0[rb_full_words] = words[rb_full_words < RATE_W];

  std::memcpy(buffer2, state, RATE);
  rho2(buffer2, buffer0);

  if constexpr (is_little_endian()) {
    std::memcpy(enc + b_off, buffer2, rb_full_words << 2);
  } else {
    for (size_t i = 0; i < rb_full_words; i++) {
      const size_t i_off = i << 2;

      enc[b_off + (i_off ^ 0)] = static_cast<uint8_t>(buffer2[i] >> 0);
      enc[b_off + (i_off ^ 1)] = static_cast<uint8_t>(buffer2[i] >> 8);
      enc[b_off + (i_off ^ 2)] = static_cast<uint8_t>(buffer2[i] >> 16);
      enc[b_off + (i_off ^ 3)] = static_cast<uint8_t>(buffer2[i] >> 24);
    }
  }

  for (size_t i = 0; i < rb_rem_bytes; i++) {
    const size_t idx = b_off + w_off + i;

    enc[idx] = static_cast<uint8_t>(buffer2[rb_full_words] >> (i << 3));
  }

  rho1(state, buffer0);

  constexpr uint32_t consts[2] = { CONST_M1, CONST_M0 };
  state[11] ^= consts[rb_full_words < RATE_W];

  omega(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < RATE_W; i++) {
    state[i] ^= buffer1[i];
  }

  sparkle::sparkle<6ul, 11ul>(state);
}

// Consumes non-empty ( N -many | N > 0 ) encrypted text into 384 -bit
// permutation state, while producing equal many decrypted text bytes, using
// algorithm 2.14 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
process_cipher_text(
  uint32_t* const __restrict state,    // 384 -bit permutation state
  const uint8_t* const __restrict enc, // N (>0) -bytes encrypted text
  uint8_t* const __restrict dec,       // N (>0) -bytes decrypted text
  const size_t ct_len                  // len(enc) = len(dec) = N | N > 0
)
{
  uint32_t buffer0[RATE_W ^ 1];
  uint32_t buffer1[RATE_W];
  uint32_t buffer2[RATE_W];

  size_t r_bytes = ct_len;
  while (r_bytes > RATE) {
    const size_t b_off = ct_len - r_bytes;

    if constexpr (is_little_endian()) {
      std::memcpy(buffer0, enc + b_off, RATE);
    } else {
#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        const size_t i_off = i << 2;

        buffer0[i] = (static_cast<uint32_t>(enc[b_off + (i_off ^ 3)]) << 24) |
                     (static_cast<uint32_t>(enc[b_off + (i_off ^ 2)]) << 16) |
                     (static_cast<uint32_t>(enc[b_off + (i_off ^ 1)]) << 8) |
                     (static_cast<uint32_t>(enc[b_off + (i_off ^ 0)]) << 0);
      }
    }

    std::memcpy(buffer2, state, RATE);
    rhoprime2(buffer2, buffer0);

    if constexpr (is_little_endian()) {
      std::memcpy(dec + b_off, buffer2, RATE);
    } else {
#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        const size_t i_off = i << 2;

        dec[b_off + (i_off ^ 0)] = static_cast<uint8_t>(buffer2[i] >> 0);
        dec[b_off + (i_off ^ 1)] = static_cast<uint8_t>(buffer2[i] >> 8);
        dec[b_off + (i_off ^ 2)] = static_cast<uint8_t>(buffer2[i] >> 16);
        dec[b_off + (i_off ^ 3)] = static_cast<uint8_t>(buffer2[i] >> 24);
      }
    }

    rhoprime1(state, buffer0);
    omega(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < RATE_W; i++) {
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

  if constexpr (is_little_endian()) {
    std::memcpy(buffer0, enc + b_off, rb_full_words << 2);
  } else {
    for (size_t i = 0; i < rb_full_words; i++) {
      const size_t i_off = i << 2;

      buffer0[i] = (static_cast<uint32_t>(enc[b_off + (i_off ^ 3)]) << 24) |
                   (static_cast<uint32_t>(enc[b_off + (i_off ^ 2)]) << 16) |
                   (static_cast<uint32_t>(enc[b_off + (i_off ^ 1)]) << 8) |
                   (static_cast<uint32_t>(enc[b_off + (i_off ^ 0)]) << 0);
    }
  }

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  for (size_t i = 0; i < rb_rem_bytes; i++) {
    const size_t idx = b_off + w_off + i;

    word |= static_cast<uint32_t>(enc[idx]) << (i << 3);
  }

  const uint32_t words[2] = { 0u, word };
  buffer0[rb_full_words] = words[rb_full_words < RATE_W];

  std::memcpy(buffer2, state, RATE);
  rhoprime2(buffer2, buffer0);

  if constexpr (is_little_endian()) {
    std::memcpy(dec + b_off, buffer2, rb_full_words << 2);
  } else {
    for (size_t i = 0; i < rb_full_words; i++) {
      const size_t i_off = i << 2;

      dec[b_off + (i_off ^ 0)] = static_cast<uint8_t>(buffer2[i] >> 0);
      dec[b_off + (i_off ^ 1)] = static_cast<uint8_t>(buffer2[i] >> 8);
      dec[b_off + (i_off ^ 2)] = static_cast<uint8_t>(buffer2[i] >> 16);
      dec[b_off + (i_off ^ 3)] = static_cast<uint8_t>(buffer2[i] >> 24);
    }
  }

  for (size_t i = 0; i < rb_rem_bytes; i++) {
    const size_t idx = b_off + w_off + i;

    dec[idx] = static_cast<uint8_t>(buffer2[rb_full_words] >> (i << 3));
  }

  if (r_bytes < RATE) {
    std::memset(buffer2 + rb_full_words, 0, RATE - w_off);

    uint32_t word = 0x80u << (rb_rem_bytes << 3);

    for (size_t i = 0; i < rb_rem_bytes; i++) {
      const size_t idx = b_off + w_off + i;

      word |= static_cast<uint32_t>(dec[idx]) << (i << 3);
    }

    buffer2[rb_full_words] = word;

    rho1(state, buffer2);
  } else {
    rhoprime1(state, buffer0);
  }

  constexpr uint32_t consts[2] = { CONST_M1, CONST_M0 };
  state[11] ^= consts[rb_full_words < RATE_W];

  omega(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < RATE_W; i++) {
    state[i] ^= buffer1[i];
  }

  sparkle::sparkle<6ul, 11ul>(state);
}

// Finalization step of Schwaemm256-128 AEAD, where 16 -bytes of authentication
// tag is produced
//
// See algorithm 2.13 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
finalize(
  const uint32_t* const __restrict state, // 384 -bit of permutation state
  const uint8_t* const __restrict key,    // 16 -bytes secret key
  uint8_t* const __restrict tag           // 16 -bytes authentication tag
)
{
  constexpr size_t words = RATE_W >> 1;
  constexpr size_t words_b = words << 2;

  uint32_t buffer[words];

  if constexpr (is_little_endian()) {
    std::memcpy(buffer, key, words_b);
  } else {
#if defined __clang__
#pragma unroll 4
#elif defined __GNUG__
#pragma GCC unroll 4
#endif
    for (size_t i = 0; i < words; i++) {
      const size_t b_off = i << 2;

      buffer[i] = (static_cast<uint32_t>(key[b_off ^ 3]) << 24) |
                  (static_cast<uint32_t>(key[b_off ^ 2]) << 16) |
                  (static_cast<uint32_t>(key[b_off ^ 1]) << 8) |
                  (static_cast<uint32_t>(key[b_off ^ 0]) << 0);
    }
  }

  if constexpr (is_little_endian()) {
#if defined __clang__
#pragma unroll 4
#elif defined __GNUG__
#pragma GCC unroll 4
#endif
    for (size_t i = 0; i < words; i++) {
      buffer[i] ^= state[RATE_W ^ i];
    }

    std::memcpy(tag, buffer, words_b);
  } else {
#if defined __clang__
#pragma unroll 4
#elif defined __GNUG__
#pragma GCC unroll 4
#endif
    for (size_t i = 0; i < words; i++) {
      const size_t b_off = i << 2;
      const uint32_t t_word = state[RATE_W ^ i] ^ buffer[i];

      tag[b_off ^ 0] = static_cast<uint8_t>(t_word >> 0);
      tag[b_off ^ 1] = static_cast<uint8_t>(t_word >> 8);
      tag[b_off ^ 2] = static_cast<uint8_t>(t_word >> 16);
      tag[b_off ^ 3] = static_cast<uint8_t>(t_word >> 24);
    }
  }
}

// Schwaemm256-128 authenticated encryption, which computes N (>=0) -bytes of
// cipher text from equal many bytes of plain text, given 16 -bytes secret key,
// 32 -bytes public message nonce & M (>=0 ) -bytes associated data ( never
// encrypted )
//
// Schwaemm256-128 AEAD scheme provides confidentiality ( only for plain text ),
// authenticity & integrity, which results into generation of 16 -bytes
// authentication tag ( during encryption ), which must be checked for equality
// ( during decryption ) before consuming decrypted bytes !
//
// See algorithm 2.13 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
encrypt(const uint8_t* const __restrict key,   // 16 -bytes secret key
        const uint8_t* const __restrict nonce, // 32 -bytes nonce
        const uint8_t* const __restrict data,  // N (>=0) -bytes associated data
        const size_t d_len,                    // len(data) = N | N >= 0
        const uint8_t* const __restrict txt,   // N (>=0) -bytes plain text
        uint8_t* const __restrict enc,         // N (>=0) -bytes cipher text
        const size_t ct_len,                   // len(txt) = len(enc) = N | >= 0
        uint8_t* const __restrict tag          // 16 -bytes authentication tag
)
{
  uint32_t state[12];

  initialize(state, key, nonce);

  if (d_len > 0) {
    process_associated_data(state, data, d_len);
  }
  if (ct_len > 0) {
    process_plain_text(state, txt, enc, ct_len);
  }

  finalize(state, key, tag);
}

// Schwaemm256-128 verified decryption, which computes N (>=0) -bytes of
// deciphered text from equal many bytes of encrypted text, given 16 -bytes
// secret key, 32 -bytes public message nonce, 16 -bytes authentication tag &
// M (>=0) -bytes associated data ( never encrypted )
//
// Schwaemm256-128 AEAD scheme provides confidentiality ( only for plain text ),
// authenticity & integrity, which results into generation of 16 -bytes
// authentication tag ( during encryption ), which is checked for equality
// during decryption & equality test result is returned from this function
//
// Note, before consuming decrypted bytes ( pointed to by `dec` ), one must
// check for truth value of this function's return value.
//
// See algorithm 2.14 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline bool
decrypt(const uint8_t* const __restrict key,   // 16 -bytes secret key
        const uint8_t* const __restrict nonce, // 32 -bytes nonce
        const uint8_t* const __restrict tag,   // 16 -bytes authentication tag
        const uint8_t* const __restrict data,  // N (>=0) -bytes associated data
        const size_t d_len,                    // len(data) = N | N >= 0
        const uint8_t* const __restrict enc,   // N (>=0) -bytes encrypted text
        uint8_t* const __restrict dec,         // N (>=0) -bytes decrypted text
        const size_t ct_len                    // len(enc) = len(dec) = N | >= 0
)
{
  uint32_t state[12];
  uint8_t tag_[16];

  initialize(state, key, nonce);

  if (d_len > 0) {
    process_associated_data(state, data, d_len);
  }
  if (ct_len > 0) {
    process_cipher_text(state, enc, dec, ct_len);
  }

  finalize(state, key, tag_);

  bool flag = false;
  for (size_t i = 0; i < 16; i++) {
    flag |= (tag[i] ^ tag_[i]);
  }
  return !flag;
}

}
