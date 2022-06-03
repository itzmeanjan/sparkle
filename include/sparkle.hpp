#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>
#include <utility>

// Sparkle Permutation Family
namespace sparkle {

// Sparkle constants which are XORed into permutation state, see first four
// lines of algorithm 2.{1, 2, 3} in Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
constexpr uint32_t CONST[8] = {0xB7E15162u, 0xBF715880u, 0x38B4DA56u,
                               0x324E7738u, 0xBB1185EBu, 0x4F7C7B57u,
                               0xCFBFA1C8u, 0xC2B3293Du};

// ARX-box Alzette is a 64 -bit block cipher used as one building block of
// Sparkle Permutation
//
// See section 2.1.1 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline std::pair<uint32_t, uint32_t> alzette(const uint32_t x,
                                                    const uint32_t y,
                                                    const uint32_t c) {
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
static inline void diffusion_layer_4(uint32_t* const state) {
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

// Diffusion Layer `ℒ6`, used when branch count = 6 i.e. permutation state
// is 384 ( = 32 * (6 * 2) ) -bit wide
//
// See algorithm 2.6 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void diffusion_layer_6(uint32_t* const state) {
  // feistel round

  uint32_t tx = state[0] ^ state[2] ^ state[4];
  uint32_t ty = state[1] ^ state[3] ^ state[5];

  tx = std::rotl(tx ^ (tx << 16), 16);
  ty = std::rotl(ty ^ (ty << 16), 16);

  state[7] = state[7] ^ state[1] ^ tx;
  state[9] = state[9] ^ state[3] ^ tx;
  state[11] = state[11] ^ state[5] ^ tx;

  state[6] = state[6] ^ state[0] ^ ty;
  state[8] = state[8] ^ state[2] ^ ty;
  state[10] = state[10] ^ state[4] ^ ty;

  // branch permutation

  uint32_t t0 = state[6];
  uint32_t t1 = state[8];
  uint32_t t2 = state[10];

  state[6] = state[0];
  state[8] = state[2];
  state[10] = state[4];
  state[0] = t1;
  state[2] = t2;
  state[4] = t0;

  t0 = state[7];
  t1 = state[9];
  t2 = state[11];

  state[7] = state[1];
  state[9] = state[3];
  state[11] = state[5];
  state[1] = t1;
  state[3] = t2;
  state[5] = t0;
}

// Diffusion Layer `ℒ8`, used when branch count = 8 i.e. permutation state
// is 512 ( = 32 * (8 * 2) ) -bit wide
//
// See algorithm 2.6 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void diffusion_layer_8(uint32_t* const state) {
  // feistel round

  uint32_t tx = state[0] ^ state[2] ^ state[4] ^ state[6];
  uint32_t ty = state[1] ^ state[3] ^ state[5] ^ state[7];

  tx = std::rotl(tx ^ (tx << 16), 16);
  ty = std::rotl(ty ^ (ty << 16), 16);

  state[9] = state[9] ^ state[1] ^ tx;
  state[11] = state[11] ^ state[3] ^ tx;
  state[13] = state[13] ^ state[5] ^ tx;
  state[15] = state[15] ^ state[7] ^ tx;

  state[8] = state[8] ^ state[0] ^ ty;
  state[10] = state[10] ^ state[2] ^ ty;
  state[12] = state[12] ^ state[4] ^ ty;
  state[14] = state[14] ^ state[6] ^ ty;

  // branch permutation

  uint32_t t0 = state[8];
  uint32_t t1 = state[10];
  uint32_t t2 = state[12];
  uint32_t t3 = state[14];

  state[8] = state[0];
  state[10] = state[2];
  state[12] = state[4];
  state[14] = state[6];
  state[0] = t1;
  state[2] = t2;
  state[4] = t3;
  state[6] = t0;

  t0 = state[9];
  t1 = state[11];
  t2 = state[13];
  t3 = state[15];

  state[9] = state[1];
  state[11] = state[3];
  state[13] = state[5];
  state[15] = state[7];
  state[1] = t1;
  state[3] = t2;
  state[5] = t3;
  state[7] = t0;
}

// Generic Sparkle Permutation Implementation, parameterized with # -of branches
// ( i.e. in Sparkle256 it is 4, in Sparkle384 it is 6 & in Sparkle512 it is 8 )
// and # -of steps ( i.e. whether slim/ big variant )
//
// See section 2.1 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
//
// For implementation specific details, I suggest going through
// algorithm 2.1, 2.2 & 2.3 of above linked document.
template <const size_t nb, const size_t ns>
static inline void sparkle(uint32_t* const state) {
  for (size_t i = 0; i < ns; i++) {
    state[1] = state[1] ^ CONST[i & 7ul];
    state[3] = state[3] ^ static_cast<uint32_t>(i);

    if constexpr (nb == 4ul) {
#if defined __clang__
#pragma unroll 4
#elif defined __GNUG__
#pragma GCC unroll 4
#endif
      for (size_t i = 0; i < 4; i++) {
        const size_t x_idx = i << 1;
        const size_t y_idx = x_idx ^ 1ul;

        const auto p = alzette(state[x_idx], state[y_idx], CONST[i]);

        state[x_idx] = p.first;
        state[y_idx] = p.second;
      }

      diffusion_layer_4(state);
    } else if constexpr (nb == 6ul) {
#if defined __clang__
#pragma unroll 4
#elif defined __GNUG__
#pragma GCC unroll 4
#endif
      for (size_t i = 0; i < 4; i++) {
        const size_t x_idx = i << 1;
        const size_t y_idx = x_idx ^ 1ul;

        const auto p = alzette(state[x_idx], state[y_idx], CONST[i]);

        state[x_idx] = p.first;
        state[y_idx] = p.second;
      }

#if defined __clang__
#pragma unroll 2
#elif defined __GNUG__
#pragma GCC unroll 2
#endif
      for (size_t i = 0; i < 2; i++) {
        const size_t x_idx = 8ul ^ (i << 1);
        const size_t y_idx = x_idx ^ 1ul;

        const auto p = alzette(state[x_idx], state[y_idx], CONST[4ul ^ i]);

        state[x_idx] = p.first;
        state[y_idx] = p.second;
      }

      diffusion_layer_6(state);
    } else if constexpr (nb == 8ul) {
#if defined __clang__
#pragma unroll 4
#elif defined __GNUG__
#pragma GCC unroll 4
#endif
      for (size_t i = 0; i < 8; i++) {
        const size_t x_idx = i << 1;
        const size_t y_idx = x_idx ^ 1ul;

        const auto p = alzette(state[x_idx], state[y_idx], CONST[i]);

        state[x_idx] = p.first;
        state[y_idx] = p.second;
      }

      diffusion_layer_8(state);
    }
  }
}

}  // namespace sparkle
