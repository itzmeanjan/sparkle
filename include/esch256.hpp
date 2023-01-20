#pragma once
#include <cstring>

#include "hash.hpp"
#include "utils.hpp"

// Esch256 hash function, based on Sparkle permutation
namespace esch256 {

// Esch256 hash function produces 32 -bytes of digest
constexpr size_t DIGEST_LEN = 32;

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
  uint32_t state[12]{};
  uint32_t buffer[6]{};

  size_t rm_bytes = ilen;
  while (rm_bytes > hash::RATE) {
    const size_t b_off = ilen - rm_bytes;
    sparkle_utils::copy_le_bytes_to_words<hash::RATE>(in + b_off, buffer);

    hash::feistel<384ul>(state, buffer);
    sparkle::sparkle<6ul, 7ul>(state);

    rm_bytes -= hash::RATE;
  }

  size_t b_off = ilen - rm_bytes;

  const size_t rb_full_words = rm_bytes >> 2;
  const size_t rb_full_bytes = rb_full_words << 2;
  const size_t rb_rem_bytes = rm_bytes & 3ul;

  std::memset(buffer, 0, hash::RATE);
  sparkle_utils::copy_le_bytes_to_words(in + b_off, buffer, rb_full_bytes);
  b_off += rb_full_bytes;

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  sparkle_utils::copy_le_bytes_to_words(in + b_off, &word, rb_rem_bytes);

  const uint32_t words[]{ 0u, word };
  buffer[rb_full_words] = words[rb_full_words < 4];

  constexpr uint32_t consts[]{ hash::CONST_M1, hash::CONST_M0 };
  state[5] ^= consts[rm_bytes < hash::RATE];

  hash::feistel<384ul>(state, buffer);
  sparkle::sparkle<6ul, 11ul>(state);

  sparkle_utils::copy_words_to_le_bytes<hash::RATE>(state, out);
  sparkle::sparkle<6ul, 7ul>(state);
  sparkle_utils::copy_words_to_le_bytes<hash::RATE>(state, out + hash::RATE);
}

} // namespace esch256
