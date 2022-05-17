#pragma once
#include "hash.hpp"
#include <cstring>

// Esch256 hash function, based on Sparkle permutation
namespace esch256 {

// Esch256 --- lightweight, cryptographically secure hash function, based on
// Sparkle permutation, producing 32 -bytes output from N -bytes input | N >= 0
//
// Input:
//
// in - N -bytes message
// ilen - len(in) in bytes | ilen >= 0
//
// Output:
//
// out - 32 -bytes Esch256 digest
//
// See algorithm 2.9 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
hash(const uint8_t* const __restrict in, // input message
     const size_t ilen,                  // len(in) = N | N >= 0
     uint8_t* const __restrict out       // 32 -bytes output digest
)
{
  uint32_t state[12] = { 0u };
  uint32_t buffer[6] = { 0u };

  size_t r_bytes = ilen;
  while (r_bytes > hash::RATE) {
    const size_t b_off = ilen - r_bytes;

    std::memset(buffer + 4, 0, 8);

    for (size_t j = 0; j < 4; j++) {
      const size_t i_off = j << 2;

      buffer[j] = (static_cast<uint32_t>(in[b_off + (i_off ^ 3)]) << 24) |
                  (static_cast<uint32_t>(in[b_off + (i_off ^ 2)]) << 16) |
                  (static_cast<uint32_t>(in[b_off + (i_off ^ 1)]) << 8) |
                  (static_cast<uint32_t>(in[b_off + (i_off ^ 0)]) << 0);
    }

    hash::feistel<384ul>(state, buffer);
    sparkle::sparkle<6ul, 7ul>(state);

    r_bytes -= hash::RATE;
  }

  const size_t b_off = ilen - r_bytes;
  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;

  std::memset(buffer, 0, 24);

  for (size_t i = 0; i < rb_full_words; i++) {
    const size_t off = i << 2;

    buffer[i] = (static_cast<uint32_t>(in[b_off + (off ^ 3)]) << 24) |
                (static_cast<uint32_t>(in[b_off + (off ^ 2)]) << 16) |
                (static_cast<uint32_t>(in[b_off + (off ^ 1)]) << 8) |
                (static_cast<uint32_t>(in[b_off + (off ^ 0)]) << 0);
  }

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  const size_t off = rb_full_words << 2;

  for (size_t i = 0; i < rb_rem_bytes; i++) {
    word |= static_cast<uint32_t>(in[b_off + off + i]) << (i << 3);
  }

  const uint32_t words[2] = { 0u, word };
  buffer[rb_full_words] = words[rb_full_words < 4];

  constexpr uint32_t consts[2] = { hash::CONST_M1, hash::CONST_M0 };
  state[5] ^= consts[r_bytes < hash::RATE];

  hash::feistel<384ul>(state, buffer);
  sparkle::sparkle<6ul, 11ul>(state);

  for (size_t i = 0; i < 4; i++) {
    const uint32_t word = state[i];
    const size_t b_off = i << 2;

    out[b_off ^ 0] = static_cast<uint8_t>(word >> 0);
    out[b_off ^ 1] = static_cast<uint8_t>(word >> 8);
    out[b_off ^ 2] = static_cast<uint8_t>(word >> 16);
    out[b_off ^ 3] = static_cast<uint8_t>(word >> 24);
  }

  sparkle::sparkle<6ul, 7ul>(state);

  for (size_t i = 0; i < 4; i++) {
    const uint32_t word = state[i];
    const size_t b_off = i << 2;

    out[16ul + (b_off ^ 0)] = static_cast<uint8_t>(word >> 0);
    out[16ul + (b_off ^ 1)] = static_cast<uint8_t>(word >> 8);
    out[16ul + (b_off ^ 2)] = static_cast<uint8_t>(word >> 16);
    out[16ul + (b_off ^ 3)] = static_cast<uint8_t>(word >> 24);
  }
}

}
