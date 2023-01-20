#pragma once
#include <cstring>

#include "hash.hpp"
#include "utils.hpp"

// Esch384 hash function, based on Sparkle permutation
namespace esch384 {

// Esch384 hash function produces 48 -bytes of digest
constexpr size_t DIGEST_LEN = 48;

// Esch384 --- lightweight, cryptographically secure hash function, based on
// Sparkle permutation, producing 48 -bytes digest from N -bytes input | N >= 0
//
// Input:
//
// in - N -bytes message
// ilen - len(in) in bytes | ilen >= 0
//
// Output:
//
// out - 48 -bytes Esch384 digest
//
// See algorithm 2.10 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
hash(const uint8_t* const __restrict in, // input message
     const size_t ilen,                  // len(in) = N | N >= 0
     uint8_t* const __restrict out       // 48 -bytes output digest
)
{
  uint32_t state[16]{};
  uint32_t buffer[8]{};

  size_t r_bytes = ilen;
  while (r_bytes > hash::RATE) {
    const size_t b_off = ilen - r_bytes;
    sparkle_utils::copy_le_bytes_to_words<hash::RATE>(in + b_off, buffer);

    hash::feistel<512ul>(state, buffer);
    sparkle::sparkle<8ul, 8ul>(state);

    r_bytes -= hash::RATE;
  }

  size_t b_off = ilen - r_bytes;

  const size_t rb_full_words = r_bytes >> 2;
  const size_t rb_full_bytes = rb_full_words << 2;
  const size_t rb_rem_bytes = r_bytes & 3ul;

  std::memset(buffer, 0, hash::RATE);
  sparkle_utils::copy_le_bytes_to_words(in + b_off, buffer, rb_full_bytes);
  b_off += rb_full_bytes;

  uint32_t word = 0x80u << (rb_rem_bytes << 3);
  sparkle_utils::copy_le_bytes_to_words(in + b_off, &word, rb_rem_bytes);

  const uint32_t words[2] = { 0u, word };
  buffer[rb_full_words] = words[rb_full_words < 4];

  constexpr uint32_t consts[2] = { hash::CONST_M1, hash::CONST_M0 };
  state[7] ^= consts[r_bytes < hash::RATE];

  hash::feistel<512ul>(state, buffer);
  sparkle::sparkle<8ul, 12ul>(state);

  constexpr size_t off0 = hash::RATE;
  constexpr size_t off1 = off0 + off0;

  sparkle_utils::copy_words_to_le_bytes<hash::RATE>(state, out);
  sparkle::sparkle<8ul, 8ul>(state);
  sparkle_utils::copy_words_to_le_bytes<hash::RATE>(state, out + off0);
  sparkle::sparkle<8ul, 8ul>(state);
  sparkle_utils::copy_words_to_le_bytes<hash::RATE>(state, out + off1);
}

} // namespace esch384
