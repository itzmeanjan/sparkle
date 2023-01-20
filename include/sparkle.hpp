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
constexpr uint32_t CONST[]{
  0xB7E15162u, 0xBF715880u, 0x38B4DA56u, 0x324E7738u,
  0xBB1185EBu, 0x4F7C7B57u, 0xCFBFA1C8u, 0xC2B3293Du
};

// ARX-box Alzette is a 64 -bit block cipher used as one building block of
// Sparkle Permutation
//
// See section 2.1.1 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline std::pair<uint32_t, uint32_t>
alzette(const uint32_t x, const uint32_t y, const uint32_t c)
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

  state[5] ^= state[1] ^ tx;
  state[7] ^= state[3] ^ tx;

  state[4] ^= state[0] ^ ty;
  state[6] ^= state[2] ^ ty;

  // branch permutation

  const auto t0 = state[4];
  const auto t1 = state[6];

  state[4] = state[0];
  state[6] = state[2];
  state[0] = t1;
  state[2] = t0;

  const auto t2 = state[5];
  const auto t3 = state[7];

  state[5] = state[1];
  state[7] = state[3];
  state[1] = t3;
  state[3] = t2;
}

// Diffusion Layer `ℒ6`, used when branch count = 6 i.e. permutation state
// is 384 ( = 32 * (6 * 2) ) -bit wide
//
// See algorithm 2.6 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
diffusion_layer_6(uint32_t* const state)
{
  // feistel round

  uint32_t tx = state[0] ^ state[2] ^ state[4];
  uint32_t ty = state[1] ^ state[3] ^ state[5];

  tx = std::rotl(tx ^ (tx << 16), 16);
  ty = std::rotl(ty ^ (ty << 16), 16);

  state[7] ^= state[1] ^ tx;
  state[9] ^= state[3] ^ tx;
  state[11] ^= state[5] ^ tx;

  state[6] ^= state[0] ^ ty;
  state[8] ^= state[2] ^ ty;
  state[10] ^= state[4] ^ ty;

  // branch permutation

  const auto t0 = state[6];
  const auto t1 = state[8];
  const auto t2 = state[10];

  state[6] = state[0];
  state[8] = state[2];
  state[10] = state[4];
  state[0] = t1;
  state[2] = t2;
  state[4] = t0;

  const auto t3 = state[7];
  const auto t4 = state[9];
  const auto t5 = state[11];

  state[7] = state[1];
  state[9] = state[3];
  state[11] = state[5];
  state[1] = t4;
  state[3] = t5;
  state[5] = t3;
}

// Diffusion Layer `ℒ8`, used when branch count = 8 i.e. permutation state
// is 512 ( = 32 * (8 * 2) ) -bit wide
//
// See algorithm 2.6 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
diffusion_layer_8(uint32_t* const state)
{
  // feistel round

  uint32_t tx = state[0] ^ state[2] ^ state[4] ^ state[6];
  uint32_t ty = state[1] ^ state[3] ^ state[5] ^ state[7];

  tx = std::rotl(tx ^ (tx << 16), 16);
  ty = std::rotl(ty ^ (ty << 16), 16);

  state[9] ^= state[1] ^ tx;
  state[11] ^= state[3] ^ tx;
  state[13] ^= state[5] ^ tx;
  state[15] ^= state[7] ^ tx;

  state[8] ^= state[0] ^ ty;
  state[10] ^= state[2] ^ ty;
  state[12] ^= state[4] ^ ty;
  state[14] ^= state[6] ^ ty;

  // branch permutation

  const auto t0 = state[8];
  const auto t1 = state[10];
  const auto t2 = state[12];
  const auto t3 = state[14];

  state[8] = state[0];
  state[10] = state[2];
  state[12] = state[4];
  state[14] = state[6];
  state[0] = t1;
  state[2] = t2;
  state[4] = t3;
  state[6] = t0;

  const auto t4 = state[9];
  const auto t5 = state[11];
  const auto t6 = state[13];
  const auto t7 = state[15];

  state[9] = state[1];
  state[11] = state[3];
  state[13] = state[5];
  state[15] = state[7];
  state[1] = t5;
  state[3] = t6;
  state[5] = t7;
  state[7] = t4;
}

// Compile-time check to ensure that # -of branches and # -of steps, for Sparkle
// permutation, are conformant i.e. as provided in table 2.1 of the Sparkle
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
consteval bool
check_nb_ns(const size_t nb, const size_t ns)
{
  return ((nb == 4) && ((ns == 7) || (ns == 10))) ||
         ((nb == 6) && ((ns == 7) || (ns == 11))) ||
         ((nb == 8) && ((ns == 8) || (ns == 12)));
}

// Generic Sparkle Permutation Implementation, parameterized with # -of branches
// ( i.e. in Sparkle256 it is 4, in Sparkle384 it is 6 & in Sparkle512 it is 8 )
// and # -of steps ( i.e. whether slim/ big variant ), over state size of
// 32 * (2 * nb) -bits.
//
// See section 2.1 of Sparkle specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
//
// For implementation specific details, I suggest going through
// algorithm 2.1, 2.2 & 2.3 of above linked document.
template<const size_t nb, const size_t ns>
static inline void
sparkle(uint32_t* const state // 32 * (nb * 2) -bit wide state
        )
  requires(check_nb_ns(nb, ns))
{
  for (size_t i = 0; i < ns; i++) {
    state[1] = state[1] ^ CONST[i & 7ul];
    state[3] = state[3] ^ static_cast<uint32_t>(i);

    if constexpr (nb == 4ul) {
      static_assert(nb == 4ul, "# -of branches must be = 4");

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
      for (size_t i = 0; i < nb; i++) {
        const size_t x_idx = i * 2;
        const size_t y_idx = x_idx + 1ul;

        const auto p = alzette(state[x_idx], state[y_idx], CONST[i]);

        state[x_idx] = p.first;
        state[y_idx] = p.second;
      }

      diffusion_layer_4(state);
    } else if constexpr (nb == 6ul) {
      static_assert(nb == 6ul, "# -of branches must be = 6");

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
      for (size_t i = 0; i < nb; i++) {
        const size_t x_idx = i * 2;
        const size_t y_idx = x_idx + 1ul;

        const auto p = alzette(state[x_idx], state[y_idx], CONST[i]);

        state[x_idx] = p.first;
        state[y_idx] = p.second;
      }

      diffusion_layer_6(state);
    } else if constexpr (nb == 8ul) {
      static_assert(nb == 8ul, "# -of branches must be = 8");

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
      for (size_t i = 0; i < nb; i++) {
        const size_t x_idx = i * 2;
        const size_t y_idx = x_idx + 1ul;

        const auto p = alzette(state[x_idx], state[y_idx], CONST[i]);

        state[x_idx] = p.first;
        state[y_idx] = p.second;
      }

      diffusion_layer_8(state);
    }
  }
}

} // namespace sparkle
