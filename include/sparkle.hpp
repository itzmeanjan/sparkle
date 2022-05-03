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

// Diffusion Layer `ℒ4`, used when branch count = 4 i.e. permutation state
// is 256 ( = 32 * (4 * 2) ) -bit wide
//
// See algorithm 2.5 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
diffusion_layer_4(uint32_t* const state)
{
  // feistel round

  uint32_t tx = state[0] ^ state[2];
  uint32_t ty = state[1] ^ state[3];

  tx = std::rotl(tx ^ (tx << 16), 16);
  ty = std::rotl(ty ^ (ty << 16), 16);

  state[5] = state[5] ^ state[1] ^ tx;
  state[7] = state[7] ^ state[3] ^ tx;

  state[4] = state[4] ^ state[0] ^ ty;
  state[6] = state[6] ^ state[2] ^ ty;

  // branch permutation

  uint32_t t0 = state[4];
  uint32_t t1 = state[6];

  state[4] = state[0];
  state[6] = state[2];
  state[0] = t1;
  state[2] = t0;

  t0 = state[5];
  t1 = state[7];

  state[5] = state[1];
  state[7] = state[3];
  state[1] = t1;
  state[3] = t0;
}

}
