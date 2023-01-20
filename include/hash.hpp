#pragma once
#include "sparkle.hpp"

// Common routines used from hash functions Esch256 & Esch384, which are based
// on Sparkle permutation
namespace hash {

// Both Esch256 and Esch384 consume 128 -bit message block per iteration
constexpr size_t RATE = 16ul;

// To distinguish padded input message block from non-padded one, this constant
// is XORed into inner part of permutation state, when processing last message
// block
//
// Note, this is same for both Esch256 and Esch384
constexpr uint32_t CONST_M0 = 1u << 24;

// To distinguish non-padded input message block ( 128 -bit ) from padded one,
// this constant is XORed into inner part of permutation state, during
// processing of last message block
//
// Note, this is same for both Esch256 and Esch384
constexpr uint32_t CONST_M1 = 2u << 24;

// Applies transformation function ℳ3 for Esch256 or ℳ4 for Esch384 ( based on
// state bit width provided in template parameter ) on padded input words &
// finally mixes them into permutation state
//
// This is how 128 -bit message blocks are indirectly injected into permutation
// state.
//
// See section 2.2.2 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
template<const size_t state_w>
static inline void
feistel(uint32_t* const __restrict state, const uint32_t* const __restrict msg)
{
  // This branch is taken when computing Esch256 hash
  //
  // Note, in Esch256 sparkle permutation variant Sparkle384 is used
  // which has state bit width of 384
  if constexpr (state_w == 384ul) {
    static_assert(state_w == 384, "State bit width must be = 384 -bits");

    uint32_t tx = msg[0] ^ msg[2];
    uint32_t ty = msg[1] ^ msg[3];

    tx = std::rotl(tx ^ (tx << 16), 16);
    ty = std::rotl(ty ^ (ty << 16), 16);

    state[0] ^= msg[0] ^ ty;
    state[2] ^= msg[2] ^ ty;
    state[4] ^= ty;

    state[1] ^= msg[1] ^ tx;
    state[3] ^= msg[3] ^ tx;
    state[5] ^= tx;
  }
  // This branch is taken when computing Esch384 hash
  //
  // Note, in Esch384 sparkle permutation variant Sparkle512 is used
  // which has state bit width of 512
  else {
    static_assert(state_w == 512, "State bit width must be = 512 -bits");

    uint32_t tx = msg[0] ^ msg[2];
    uint32_t ty = msg[1] ^ msg[3];

    tx = std::rotl(tx ^ (tx << 16), 16);
    ty = std::rotl(ty ^ (ty << 16), 16);

    state[0] ^= msg[0] ^ ty;
    state[2] ^= msg[2] ^ ty;
    state[4] ^= ty;
    state[6] ^= ty;

    state[1] ^= msg[1] ^ tx;
    state[3] ^= msg[3] ^ tx;
    state[5] ^= tx;
    state[7] ^= tx;
  }
}

} // namespace hash
