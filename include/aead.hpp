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
  constexpr size_t RATE_W = RATE >> 2; // # -of 32 -bit words

  sparkle_utils::copy_le_bytes_to_words<RATE>(nonce, state);
  sparkle_utils::copy_le_bytes_to_words<CAPACITY>(key, state + RATE_W);

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
feistel_swap(uint32_t* const s)
{
  if constexpr (RATE == 32) {
    static_assert(RATE == 32, "Rate must be = 32 -bytes");

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 4
#endif
    for (size_t i = 0; i < 4; i++) {
      // swap
      s[i] ^= s[4 + i];
      s[4 + i] ^= s[i];
      s[i] ^= s[4 + i];

      // xor
      s[4 + i] ^= s[i];
    }
  } else if constexpr (RATE == 24) {
    static_assert(RATE == 24, "Rate must be = 24 -bytes");

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 3
#endif
    for (size_t i = 0; i < 3; i++) {
      // swap
      s[i] ^= s[3 + i];
      s[3 + i] ^= s[i];
      s[i] ^= s[3 + i];

      // xor
      s[3 + i] ^= s[i];
    }
  } else {
    static_assert(RATE == 16, "Rate must be = 16 -bytes");

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 2
#endif
    for (size_t i = 0; i < 2; i++) {
      // swap
      s[i] ^= s[2 + i];
      s[2 + i] ^= s[i];
      s[i] ^= s[2 + i];

      // xor
      s[2 + i] ^= s[i];
    }
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
  if constexpr (RATE == 16) {
    static_assert(RATE == 16, "Rate must be = 16 -bytes");
    constexpr size_t RATE_W = RATE >> 2;

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 4
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      s[i] ^= d[i];
    }
  } else if constexpr (RATE == 24) {
    static_assert(RATE == 24, "Rate must be = 24 -bytes");
    constexpr size_t RATE_W = RATE >> 2;

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 6
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      s[i] ^= d[i];
    }
  } else {
    static_assert(RATE == 32, "Rate must be = 32 -bytes");
    constexpr size_t RATE_W = RATE >> 2;

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      s[i] ^= d[i];
    }
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
  feistel_swap<RATE>(s);
  rho2<RATE>(s, d);
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
  uint32_t s_[RATE / 4];
  std::memcpy(s_, s, RATE);

  feistel_swap<RATE>(s);

  if constexpr (RATE == 16) {
    static_assert(RATE == 16, "Rate must be = 16 -bytes");
    constexpr size_t RATE_W = RATE >> 2;

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 4
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      s[i] ^= s_[i] ^ d[i];
    }
  } else if constexpr (RATE == 24) {
    static_assert(RATE == 24, "Rate must be = 24 -bytes");
    constexpr size_t RATE_W = RATE >> 2;

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 6
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      s[i] ^= s_[i] ^ d[i];
    }
  } else {
    static_assert(RATE == 32, "Rate must be = 32 -bytes");
    constexpr size_t RATE_W = RATE >> 2;

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 8
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      s[i] ^= s_[i] ^ d[i];
    }
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
  rho2<RATE>(s, d);
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

// Rate whitening layer ( applied before each call to Sparkle permutation except
// when it's being initialized ) which XORs the value of 𝒲𝑐,𝑟(𝑆_𝑅) to the outer
// part s.t. 𝑆_𝑅 denotes the internal state corresponding to the inner part.
//
// Read more about it in section 2.3.2 ( bottom of page 14 ) of the Sparkle
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t RATE, const size_t CAPACITY>
static inline void
whiten_rate(uint32_t* const state)
{
  constexpr size_t RATE_W = RATE >> 2; // # -of 32 -bit words

  if constexpr ((RATE == 32) && (CAPACITY == 16)) {
    static_assert((RATE == 32) && (CAPACITY == 16),
                  "Rate must be = 32 and Capacity must be = 16");

    uint32_t buffer[RATE_W];
    omega<CAPACITY>(state + RATE_W, buffer);

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      state[i] ^= buffer[i];
    }
  } else {
    static_assert(!((RATE == 32) && (CAPACITY == 16)),
                  "Rate must be != 32 and Capacity must be != 16");

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#endif
    for (size_t i = 0; i < RATE_W; i++) {
      state[i] ^= state[RATE_W + i];
    }
  }
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
  uint32_t buffer0[RATE_W + 1];

  // process full message blocks, except last one ( even if that's full )
  size_t r_bytes = d_len;
  while (r_bytes > RATE) {
    const size_t b_off = d_len - r_bytes;

    sparkle_utils::copy_le_bytes_to_words<RATE>(data + b_off, buffer0);
    rho1<RATE>(state, buffer0);
    whiten_rate<RATE, CAPACITY>(state);
    sparkle::sparkle<nb, ns_slim>(state);

    r_bytes -= RATE;
  }

  // process last message block, it can be full/ partially filled
  size_t b_off = d_len - r_bytes;

  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_full_bytes = rb_full_words << 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;

  std::memset(buffer0, 0, RATE);
  sparkle_utils::copy_le_bytes_to_words(data + b_off, buffer0, rb_full_bytes);
  b_off += rb_full_bytes;

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  sparkle_utils::copy_le_bytes_to_words(data + b_off, &word, rb_rem_bytes);

  const uint32_t words[]{ 0u, word };
  buffer0[rb_full_words] = words[rb_full_words < RATE_W];

  rho1<RATE>(state, buffer0);

  constexpr uint32_t consts[]{ CONST_A1, CONST_A0 };
  state[(nb << 1) - 1] ^= consts[rb_full_words < RATE_W];

  whiten_rate<RATE, CAPACITY>(state);
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

  // process full message blocks, except last one ( even if that's full )
  size_t r_bytes = ct_len;
  while (r_bytes > RATE) {
    const size_t b_off = ct_len - r_bytes;

    sparkle_utils::copy_le_bytes_to_words<RATE>(txt + b_off, buffer0);
    std::memcpy(buffer1, state, RATE);
    rho2<RATE>(buffer1, buffer0);
    sparkle_utils::copy_words_to_le_bytes<RATE>(buffer1, enc + b_off);

    rho1<RATE>(state, buffer0);
    whiten_rate<RATE, CAPACITY>(state);
    sparkle::sparkle<nb, ns_slim>(state);

    r_bytes -= RATE;
  }

  // process last message block, it can be full/ partially filled
  size_t b_off = ct_len - r_bytes;

  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_full_bytes = rb_full_words << 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;

  std::memset(buffer0, 0, RATE);
  sparkle_utils::copy_le_bytes_to_words(txt + b_off, buffer0, rb_full_bytes);
  b_off += rb_full_bytes;

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  sparkle_utils::copy_le_bytes_to_words(txt + b_off, &word, rb_rem_bytes);

  const uint32_t words[]{ 0u, word };
  buffer0[rb_full_words] = words[rb_full_words < RATE_W];

  std::memcpy(buffer1, state, RATE);
  rho2<RATE>(buffer1, buffer0);

  b_off -= rb_full_bytes;
  sparkle_utils::copy_words_to_le_bytes(buffer1, enc + b_off, r_bytes);

  rho1<RATE>(state, buffer0);

  constexpr uint32_t consts[]{ CONST_M1, CONST_M0 };
  state[(nb << 1) - 1] ^= consts[rb_full_words < RATE_W];

  whiten_rate<RATE, CAPACITY>(state);
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

  // process full message blocks, except last one ( even if that's full )
  size_t r_bytes = ct_len;
  while (r_bytes > RATE) {
    const size_t b_off = ct_len - r_bytes;

    sparkle_utils::copy_le_bytes_to_words<RATE>(enc + b_off, buffer0);
    std::memcpy(buffer1, state, RATE);
    rhoprime2<RATE>(buffer1, buffer0);
    sparkle_utils::copy_words_to_le_bytes<RATE>(buffer1, dec + b_off);

    rhoprime1<RATE>(state, buffer0);
    whiten_rate<RATE, CAPACITY>(state);
    sparkle::sparkle<nb, ns_slim>(state);

    r_bytes -= RATE;
  }

  // process last message block, it can be full/ partially filled
  size_t b_off = ct_len - r_bytes;

  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_full_bytes = rb_full_words << 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;

  std::memset(buffer0, 0, RATE);
  sparkle_utils::copy_le_bytes_to_words(enc + b_off, buffer0, rb_full_bytes);
  b_off += rb_full_bytes;

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  sparkle_utils::copy_le_bytes_to_words(enc + b_off, &word, rb_rem_bytes);

  const uint32_t words[]{ 0u, word };
  buffer0[rb_full_words] = words[rb_full_words < RATE_W];

  std::memcpy(buffer1, state, RATE);
  rhoprime2<RATE>(buffer1, buffer0);

  b_off -= rb_full_bytes;
  sparkle_utils::copy_words_to_le_bytes(buffer1, dec + b_off, r_bytes);
  b_off += rb_full_bytes;

  // in case last message block is not full
  if (r_bytes < RATE) {
    std::memset(buffer1 + rb_full_words, 0, RATE - rb_full_bytes);

    uint32_t word = 0x80u << (rb_rem_bytes << 3);
    sparkle_utils::copy_le_bytes_to_words(dec + b_off, &word, rb_rem_bytes);
    buffer1[rb_full_words] = word;

    rho1<RATE>(state, buffer1);
  }
  // when last message block is full
  else {
    rhoprime1<RATE>(state, buffer0);
  }

  constexpr uint32_t consts[]{ CONST_M1, CONST_M0 };
  state[(nb << 1) - 1] ^= consts[rb_full_words < RATE_W];

  whiten_rate<RATE, CAPACITY>(state);
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
  sparkle_utils::copy_le_bytes_to_words<CAPACITY>(key, buffer);

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#endif
  for (size_t i = 0; i < CAPACITY_W; i++) {
    buffer[i] ^= state[RATE_W + i];
  }

  sparkle_utils::copy_words_to_le_bytes<CAPACITY>(buffer, tag);
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

  // don't release unverified plain text
  std::memset(dec, 0, flag * ct_len);
  return !flag;
}

} // namespace aead
