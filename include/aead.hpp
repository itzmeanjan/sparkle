#pragma once
#include <cstring>

#include "sparkle.hpp"
#include "utils.hpp"

// Common ( generic ) routines used in Schwaemm AEAD implementation
namespace aead {

// Initialize permutation state by consuming CAPACITY -bytes secret key & RATE
// -bytes public message nonce, when performing SchwaemmX-Y authenticated
// encryption/ verified decryption | X, Y ∈ {128, 192, 256}
//
// See algorithm 2.13 in Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t RATE,
         const size_t CAPACITY,
         const size_t nb,
         const size_t ns>
static inline void
initialize(
  uint32_t* const __restrict state,     // ((RATE + CAPACITY) << 3) -bit state
  const uint8_t* const __restrict key,  // CAPACITY -bytes secret key
  const uint8_t* const __restrict nonce // RATE -bytes nonce
)
{
  constexpr size_t RATE_W = RATE >> 2;         // # -of 32 -bit words
  constexpr size_t CAPACITY_W = CAPACITY >> 2; // # -of 32 -bit words

  if constexpr (sparkle_utils::is_little_endian()) {
    std::memcpy(state, nonce, RATE);
  } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      const size_t b_off = i << 2;

      state[i] = (static_cast<uint32_t>(nonce[b_off ^ 3]) << 24) |
                 (static_cast<uint32_t>(nonce[b_off ^ 2]) << 16) |
                 (static_cast<uint32_t>(nonce[b_off ^ 1]) << 8) |
                 (static_cast<uint32_t>(nonce[b_off ^ 0]) << 0);
    }
  }

  if constexpr (sparkle_utils::is_little_endian()) {
    std::memcpy(state + RATE_W, key, CAPACITY);
  } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < CAPACITY_W; i++) {
      const size_t b_off = i << 2;

      state[RATE_W + i] = (static_cast<uint32_t>(key[b_off ^ 3]) << 24) |
                          (static_cast<uint32_t>(key[b_off ^ 2]) << 16) |
                          (static_cast<uint32_t>(key[b_off ^ 1]) << 8) |
                          (static_cast<uint32_t>(key[b_off ^ 0]) << 0);
    }
  }

  sparkle::sparkle<nb, ns>(state);
}

// FeistelSwap - invoked from combined feedback function `𝜌`,  which is used for
// differentiating between cipher text blocks & outer part of permutation state
//
// See section 2.3.2 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
//
// Note, `s` is RATE -bytes wide i.e.
//
// `s1 || s2 = s` meaning |s1| = |s2| = (RATE >> 1) << 3 -bit
//
// To be more specific, `s` is actually outer part of permutation state !
template<const size_t RATE>
static inline void
feistel_swap(uint32_t* const __restrict s)
{
  if constexpr ((RATE ^ 32ul) == 0) {
    std::swap(s[0], s[4]);
    std::swap(s[1], s[5]);
    std::swap(s[2], s[6]);
    std::swap(s[3], s[7]);

    s[4] ^= s[0];
    s[5] ^= s[1];
    s[6] ^= s[2];
    s[7] ^= s[3];
  } else if constexpr ((RATE ^ 24ul) == 0) {
    std::swap(s[0], s[3]);
    std::swap(s[1], s[4]);
    std::swap(s[2], s[5]);

    s[3] ^= s[0];
    s[4] ^= s[1];
    s[5] ^= s[2];
  } else if constexpr ((RATE ^ 16ul) == 0) {
    std::swap(s[0], s[2]);
    std::swap(s[1], s[3]);

    s[2] ^= s[0];
    s[3] ^= s[1];
  }
}

// Feedback function `𝜌1`, used during SchwaemmX-Y Authenticated
// Encryption | X, Y ∈ {128, 192, 256}
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t RATE>
static inline void
rho1(uint32_t* const __restrict s,      // RATE -bytes wide
     const uint32_t* const __restrict d // RATE -bytes wide
)
{
  constexpr size_t RATE_W = RATE >> 2; // # -of 32 -bit words

  feistel_swap<RATE>(s);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < RATE_W; i++) {
    s[i] ^= d[i];
  }
}

// Feedback function `𝜌2`, used during SchwaemmX-Y Authenticated
// Encryption | X, Y ∈ {128, 192, 256}
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t RATE>
static inline void
rho2(uint32_t* const __restrict s,      // RATE -bytes wide
     const uint32_t* const __restrict d // RATE -bytes wide
)
{
  constexpr size_t RATE_W = RATE >> 2; // # -of 32 -bit words

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < RATE_W; i++) {
    s[i] ^= d[i];
  }
}

// Inverse Feedback function `𝜌'1`, used during SchwaemmX-Y Verified
// Decryption | X, Y ∈ {128, 192, 256}
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t RATE>
static inline void
rhoprime1(uint32_t* const __restrict s,      // RATE -bytes wide
          const uint32_t* const __restrict d // RATE -bytes wide
)
{
  constexpr size_t RATE_W = RATE >> 2; // # -of 32 -bit words

  uint32_t s_[RATE_W];
  std::memcpy(s_, s, RATE);

  feistel_swap<RATE>(s);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < RATE_W; i++) {
    s[i] ^= s_[i] ^ d[i];
  }
}

// Inverse Feedback function `𝜌'2`, used during SchwaemmX-Y Verified
// Decryption | X, Y ∈ {128, 192, 256}
//
// See section 2.3.2 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t RATE>
static inline void
rhoprime2(uint32_t* const __restrict s,      // RATE -bytes wide
          const uint32_t* const __restrict d // RATE -bytes wide
)
{
  constexpr size_t RATE_W = RATE >> 2; // # -of 32 -bit words

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < RATE_W; i++) {
    s[i] ^= d[i];
  }
}

// Rate whitening layer, applied to 128 -bit wide inner part of permutation
// state, for Schwaemm256-128 AEAD
template<const size_t CAPACITY>
static inline void
omega(const uint32_t* const __restrict in, // 128 -bit
      uint32_t* const __restrict out       // 256 -bit
)
{
  constexpr size_t CAPACITY_W = CAPACITY >> 2; // # -of 32 -bit words

  std::memcpy(out, in, CAPACITY);
  std::memcpy(out + CAPACITY_W, in, CAPACITY);
}

// Generic routine for consuming non-empty associated data into permutation
// state using algorithm 2.13 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t RATE,
         const size_t CAPACITY,
         const uint32_t CONST_A0,
         const uint32_t CONST_A1,
         const size_t nb,
         const size_t ns_slim,
         const size_t ns_big>
static inline void
process_data(
  uint32_t* const __restrict state,     // permutation state
  const uint8_t* const __restrict data, // N (>0) -bytes associated data
  const size_t d_len                    // len(data) = N -bytes | N > 0
)
{
  constexpr size_t RATE_W = RATE >> 2; // # -of 32 -bit words

  uint32_t buffer0[RATE_W ^ 1];
  uint32_t buffer1[RATE_W];

  size_t r_bytes = d_len;
  while (r_bytes > RATE) {
    const size_t b_off = d_len - r_bytes;

    if constexpr (sparkle_utils::is_little_endian()) {
      std::memcpy(buffer0, data + b_off, RATE);
    } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        const size_t i_off = i << 2;

        buffer0[i] = (static_cast<uint32_t>(data[b_off + (i_off ^ 3)]) << 24) |
                     (static_cast<uint32_t>(data[b_off + (i_off ^ 2)]) << 16) |
                     (static_cast<uint32_t>(data[b_off + (i_off ^ 1)]) << 8) |
                     (static_cast<uint32_t>(data[b_off + (i_off ^ 0)]) << 0);
      }
    }

    rho1<RATE>(state, buffer0);

    if constexpr (((RATE ^ 32ul) | (CAPACITY ^ 16ul)) == 0) {
      omega<CAPACITY>(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        state[i] ^= buffer1[i];
      }
    } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        state[i] ^= state[RATE_W + i];
      }
    }

    sparkle::sparkle<nb, ns_slim>(state);

    r_bytes -= RATE;
  }

  const size_t b_off = d_len - r_bytes;
  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;

  std::memset(buffer0, 0, RATE);

  if constexpr (sparkle_utils::is_little_endian()) {
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

  rho1<RATE>(state, buffer0);

  constexpr uint32_t consts[2] = { CONST_A1, CONST_A0 };
  state[(nb << 1) - 1] ^= consts[rb_full_words < RATE_W];

  if constexpr (((RATE ^ 32ul) | (CAPACITY ^ 16ul)) == 0) {
    omega<CAPACITY>(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      state[i] ^= buffer1[i];
    }
  } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      state[i] ^= state[RATE_W + i];
    }
  }

  sparkle::sparkle<nb, ns_big>(state);
}

// Generic routine for consuming non-empty plain text data into permutation
// state, while producing equal many cipher text bytes, using algorithm 2.{13,
// 15, 17, 19} of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t RATE,
         const size_t CAPACITY,
         const uint32_t CONST_M0,
         const uint32_t CONST_M1,
         const size_t nb,
         const size_t ns_slim,
         const size_t ns_big>
static inline void
process_text(uint32_t* const __restrict state,    // permutation state
             const uint8_t* const __restrict txt, // N (>0) -bytes plain text
             uint8_t* const __restrict enc, // N (>0) -bytes encrypted text
             const size_t ct_len            // len(txt) = len(enc) = N | N > 0
)
{
  constexpr size_t RATE_W = RATE >> 2; // # -of 32 -bit words

  uint32_t buffer0[RATE_W + 1];
  uint32_t buffer1[RATE_W];
  uint32_t buffer2[RATE_W];

  size_t r_bytes = ct_len;
  while (r_bytes > RATE) {
    const size_t b_off = ct_len - r_bytes;

    if constexpr (sparkle_utils::is_little_endian()) {
      std::memcpy(buffer0, txt + b_off, RATE);
    } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
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
    rho2<RATE>(buffer2, buffer0);

    if constexpr (sparkle_utils::is_little_endian()) {
      std::memcpy(enc + b_off, buffer2, RATE);
    } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        const size_t i_off = i << 2;

        enc[b_off + (i_off ^ 0)] = static_cast<uint8_t>(buffer2[i] >> 0);
        enc[b_off + (i_off ^ 1)] = static_cast<uint8_t>(buffer2[i] >> 8);
        enc[b_off + (i_off ^ 2)] = static_cast<uint8_t>(buffer2[i] >> 16);
        enc[b_off + (i_off ^ 3)] = static_cast<uint8_t>(buffer2[i] >> 24);
      }
    }

    rho1<RATE>(state, buffer0);

    if constexpr (((RATE ^ 32ul) | (CAPACITY ^ 16ul)) == 0) {
      omega<CAPACITY>(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        state[i] ^= buffer1[i];
      }
    } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        state[i] ^= state[RATE_W + i];
      }
    }

    sparkle::sparkle<nb, ns_slim>(state);

    r_bytes -= RATE;
  }

  const size_t b_off = ct_len - r_bytes;
  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;
  const size_t w_off = rb_full_words << 2;

  std::memset(buffer0, 0, RATE);

  if constexpr (sparkle_utils::is_little_endian()) {
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
  rho2<RATE>(buffer2, buffer0);

  if constexpr (sparkle_utils::is_little_endian()) {
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

  rho1<RATE>(state, buffer0);

  constexpr uint32_t consts[2] = { CONST_M1, CONST_M0 };
  state[(nb << 1) - 1] ^= consts[rb_full_words < RATE_W];

  if constexpr (((RATE ^ 32ul) | (CAPACITY ^ 16ul)) == 0) {
    omega<CAPACITY>(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      state[i] ^= buffer1[i];
    }
  } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      state[i] ^= state[RATE_W + i];
    }
  }

  sparkle::sparkle<nb, ns_big>(state);
}

// Generic routines for consuming non-empty ( N -many | N > 0 ) encrypted text
// into permutation state, while producing equal many decrypted text bytes,
// using algorithm 2.{14, 16, 18, 20} of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t RATE,
         const size_t CAPACITY,
         const uint32_t CONST_M0,
         const uint32_t CONST_M1,
         const size_t nb,
         const size_t ns_slim,
         const size_t ns_big>
static inline void
process_cipher(
  uint32_t* const __restrict state,    // permutation state
  const uint8_t* const __restrict enc, // N (>0) -bytes encrypted text
  uint8_t* const __restrict dec,       // N (>0) -bytes decrypted text
  const size_t ct_len                  // len(enc) = len(dec) = N | N > 0
)
{
  constexpr size_t RATE_W = RATE >> 2; // # -of 32 -bit words

  uint32_t buffer0[RATE_W + 1];
  uint32_t buffer1[RATE_W];
  uint32_t buffer2[RATE_W];

  size_t r_bytes = ct_len;
  while (r_bytes > RATE) {
    const size_t b_off = ct_len - r_bytes;

    if constexpr (sparkle_utils::is_little_endian()) {
      std::memcpy(buffer0, enc + b_off, RATE);
    } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
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
    rhoprime2<RATE>(buffer2, buffer0);

    if constexpr (sparkle_utils::is_little_endian()) {
      std::memcpy(dec + b_off, buffer2, RATE);
    } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        const size_t i_off = i << 2;

        dec[b_off + (i_off ^ 0)] = static_cast<uint8_t>(buffer2[i] >> 0);
        dec[b_off + (i_off ^ 1)] = static_cast<uint8_t>(buffer2[i] >> 8);
        dec[b_off + (i_off ^ 2)] = static_cast<uint8_t>(buffer2[i] >> 16);
        dec[b_off + (i_off ^ 3)] = static_cast<uint8_t>(buffer2[i] >> 24);
      }
    }

    rhoprime1<RATE>(state, buffer0);

    if constexpr (((RATE ^ 32ul) | (CAPACITY ^ 16ul)) == 0) {
      omega<CAPACITY>(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        state[i] ^= buffer1[i];
      }
    } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
      for (size_t i = 0; i < RATE_W; i++) {
        state[i] ^= state[RATE_W + i];
      }
    }

    sparkle::sparkle<nb, ns_slim>(state);

    r_bytes -= RATE;
  }

  const size_t b_off = ct_len - r_bytes;
  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;
  const size_t w_off = rb_full_words << 2;

  std::memset(buffer0, 0, RATE);

  if constexpr (sparkle_utils::is_little_endian()) {
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
  rhoprime2<RATE>(buffer2, buffer0);

  if constexpr (sparkle_utils::is_little_endian()) {
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

    rho1<RATE>(state, buffer2);
  } else {
    rhoprime1<RATE>(state, buffer0);
  }

  constexpr uint32_t consts[2] = { CONST_M1, CONST_M0 };
  state[(nb << 1) - 1] ^= consts[rb_full_words < RATE_W];

  if constexpr (((RATE ^ 32ul) | (CAPACITY ^ 16ul)) == 0) {
    omega<CAPACITY>(state + RATE_W, buffer1);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      state[i] ^= buffer1[i];
    }
  } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      state[i] ^= state[RATE_W + i];
    }
  }

  sparkle::sparkle<nb, ns_big>(state);
}

// Finalization step of SchwaemmX-Y AEAD | X, Y ∈ {128, 192, 256}, where Y -bit
// ( = CAPACITY -bytes ) authentication tag is produced
//
// See algorithm 2.13 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t RATE, const size_t CAPACITY>
static inline void
finalize(const uint32_t* const __restrict state, // permutation state
         const uint8_t* const __restrict key,    // CAPACITY -bytes secret key
         uint8_t* const __restrict tag           // CAPACITY -bytes tag
)
{
  constexpr size_t RATE_W = RATE >> 2;         // # -of 32 -bit words
  constexpr size_t CAPACITY_W = CAPACITY >> 2; // # -of 32 -bit words

  uint32_t buffer[CAPACITY_W];

  if constexpr (sparkle_utils::is_little_endian()) {
    std::memcpy(buffer, key, CAPACITY);
  } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < CAPACITY_W; i++) {
      const size_t b_off = i << 2;

      buffer[i] = (static_cast<uint32_t>(key[b_off ^ 3]) << 24) |
                  (static_cast<uint32_t>(key[b_off ^ 2]) << 16) |
                  (static_cast<uint32_t>(key[b_off ^ 1]) << 8) |
                  (static_cast<uint32_t>(key[b_off ^ 0]) << 0);
    }
  }

  if constexpr (sparkle_utils::is_little_endian()) {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < CAPACITY_W; i++) {
      buffer[i] ^= state[RATE_W + i];
    }

    std::memcpy(tag, buffer, CAPACITY);
  } else {
#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < CAPACITY_W; i++) {
      const size_t b_off = i << 2;
      const uint32_t t_word = state[RATE_W + i] ^ buffer[i];

      tag[b_off ^ 0] = static_cast<uint8_t>(t_word >> 0);
      tag[b_off ^ 1] = static_cast<uint8_t>(t_word >> 8);
      tag[b_off ^ 2] = static_cast<uint8_t>(t_word >> 16);
      tag[b_off ^ 3] = static_cast<uint8_t>(t_word >> 24);
    }
  }
}

// Generic authenticated encryption routine which can be used with SchwaemmX-Y
// AEAD | X, Y ∈ {128, 192, 256}
//
// i)   R = X >> 3 (bytes)
// ii)  C = Y >> 3 (bytes)
// iii) A{0, 1} = constant to be used when mixing associated data into state
// iv)  M{0, 1} = constant to be used when mixing plain text into state
// v)   BR = # -of branches in permutation state | = ((R + C) >> 2) >> 1
// vi)  S = # -of steps in slim variant of Sparkle permutation
// vii) B = # -of steps in big variant of Sparkle permutation
template<const size_t R,
         const size_t C,
         const uint32_t A0,
         const uint32_t A1,
         const uint32_t M0,
         const uint32_t M1,
         const size_t BR,
         const size_t S,
         const size_t B>
static inline void
encrypt(const uint8_t* const __restrict key,   // C -bytes secret key
        const uint8_t* const __restrict nonce, // R -bytes nonce
        const uint8_t* const __restrict data,  // N (>=0) -bytes associated data
        const size_t d_len,                    // len(data) = N | N >= 0
        const uint8_t* const __restrict txt,   // N (>=0) -bytes plain text
        uint8_t* const __restrict enc,         // N (>=0) -bytes cipher text
        const size_t ct_len,                   // len(txt) = len(enc) = N | >= 0
        uint8_t* const __restrict tag          // C -bytes authentication tag
)
{
  uint32_t state[BR << 1];

  initialize<R, C, BR, B>(state, key, nonce);

  if (d_len > 0) {
    process_data<R, C, A0, A1, BR, S, B>(state, data, d_len);
  }
  if (ct_len > 0) {
    process_text<R, C, M0, M1, BR, S, B>(state, txt, enc, ct_len);
  }

  finalize<R, C>(state, key, tag);
}

// Generic verified decryption routine which can be used with SchwaemmX-Y
// AEAD | X, Y ∈ {128, 192, 256}
//
// i)   R = X >> 3 (bytes)
// ii)  C = Y >> 3 (bytes)
// iii) A{0, 1} = constant to be used when mixing associated data into state
// iv)  M{0, 1} = constant to be used when mixing plain text into state
// v)   BR = # -of branches in permutation state | = ((R + C) >> 2) >> 1
// vi)  S = # -of steps in slim variant of Sparkle permutation
// vii) B = # -of steps in big variant of Sparkle permutation
template<const size_t R,
         const size_t C,
         const uint32_t A0,
         const uint32_t A1,
         const uint32_t M0,
         const uint32_t M1,
         const size_t BR,
         const size_t S,
         const size_t B>
static inline bool
decrypt(const uint8_t* const __restrict key,   // C -bytes secret key
        const uint8_t* const __restrict nonce, // R -bytes nonce
        const uint8_t* const __restrict tag,   // C -bytes authentication tag
        const uint8_t* const __restrict data,  // N (>=0) -bytes associated data
        const size_t d_len,                    // len(data) = N | N >= 0
        const uint8_t* const __restrict enc,   // N (>=0) -bytes encrypted text
        uint8_t* const __restrict dec,         // N (>=0) -bytes decrypted text
        const size_t ct_len                    // len(enc) = len(dec) = N | >= 0
)
{
  uint32_t state[BR << 1];
  uint8_t tag_[C];

  initialize<R, C, BR, B>(state, key, nonce);

  if (d_len > 0) {
    process_data<R, C, A0, A1, BR, S, B>(state, data, d_len);
  }
  if (ct_len > 0) {
    process_cipher<R, C, M0, M1, BR, S, B>(state, enc, dec, ct_len);
  }

  finalize<R, C>(state, key, tag_);

  bool flag = false;
  for (size_t i = 0; i < C; i++) {
    flag |= (tag[i] ^ tag_[i]);
  }
  return !flag;
}

} // namespace aead
