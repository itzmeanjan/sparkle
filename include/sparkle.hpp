#pragma once
#include <bit>
#include <cstdint>
#include <utility>

// Sparkle Permutation Family
namespace sparkle {

// ARX-box Alzette is a 64 -bit block cipher used as one building block of
// Sparkle Permutation
//
// See section 2.1.1 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const uint32_t c>
static inline std::pair<uint32_t, uint32_t>
alzette(const uint32_t x, const uint32_t y)
{
  uint32_t lw = x + std::rotr(y, 31);
  uint32_t rw = y ^ std::rotr(lw, 24);
  lw ^= c;

  lw = lw + std::rotr(rw, 17);
  rw = rw ^ std::rotr(lw, 17);
  lw ^= c;

  lw = lw + std::rotr(rw, 0);
  rw = rw ^ std::rotr(lw, 31);
  lw ^= c;

  lw = lw + std::rotr(rw, 24);
  rw = rw ^ std::rotr(lw, 16);
  lw ^= c;

  return std::make_pair(lw, rw);
}

}
