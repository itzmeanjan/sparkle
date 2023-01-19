#pragma once
#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

// Utility routines used in Sparkle Cipher Suite
namespace sparkle_utils {

// Given a 32 -bit unsigned integer word, this routine swaps byte order and
// returns byte swapped 32 -bit word.
//
// Taken from
// https://github.com/itzmeanjan/xoodyak/blob/89b3427/include/utils.hpp#L14-L28
static inline constexpr uint32_t
bswap32(const uint32_t a)
{
#if defined __GNUG__
  return __builtin_bswap32(a);
#else
  return ((a & 0x000000ffu) << 24) | ((a & 0x0000ff00u) << 0x08) |
         ((a & 0x00ff0000u) >> 0x08) | ((a & 0xff000000u) >> 24);
#endif
}

consteval static inline bool
is_little_endian()
{
  return std::endian::native == std::endian::little;
}

// This routine copies `blen` -many bytes from the source byte array to the
// destination array of unsigned 32 -bit words, following little-endian
// byte-order. Ensure that to be copied bytes i.e. blen is evenly divisible
// by 4.
template<const size_t blen>
static inline void
copy_le_bytes_to_words(const uint8_t* const __restrict bytes,
                       uint32_t* const __restrict words)
{
  static_assert(blen % 4 == 0, "Must be blen/4 -many full words");
  std::memcpy(words, bytes, blen);

  if constexpr (!is_little_endian()) {
    constexpr size_t wlen = blen / 4;

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
    for (size_t i = 0; i < wlen; i++) {
      words[i] = bswap32(words[i]);
    }
  }
}

// This routine copies `blen` -many bytes from the source byte array to the
// destination array of unsigned 32 -bit words, following little-endian
// byte-order. `blen` can be any non-zero value, it doesn't necessarily need to
// be divisible by 4.
//
// If you know how many bytes to copy and it's properly divisible by 4, consider
// using above templated function.
static inline void
copy_le_bytes_to_words(const uint8_t* const __restrict bytes,
                       uint32_t* const __restrict words,
                       const size_t blen)
{
  if constexpr (is_little_endian()) {
    std::memcpy(words, bytes, blen);
  } else {
    size_t off = 0;
    size_t widx = 0;
    while (off < blen) {
      const size_t read = std::min<size_t>(blen - off, 4);

      uint32_t word = 0;
      std::memcpy(&word, bytes + off, read);
      word = bswap32(word);
      words[widx] = word;

      off += read;
      widx += 1;
    }
  }
}

// This routine copies `blen` -many bytes from the source u32 word array to the
// destination byte array, following little-endian byte-order. Ensure that to be
// copied bytes i.e. blen is evenly divisible by 4.
template<const size_t blen>
static inline void
copy_words_to_le_bytes(const uint32_t* const __restrict words,
                       uint8_t* const __restrict bytes)
{
  static_assert(blen % 4 == 0, "Must be blen/4 -many full words");

  if constexpr (is_little_endian()) {
    std::memcpy(bytes, words, blen);
  } else {
    constexpr size_t wlen = blen / 4;

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
    for (size_t i = 0; i < wlen; i++) {
      const size_t off = i * 4;

      const auto word = bswap32(words[i]);
      std::memcpy(bytes + off, &word, 4);
    }
  }
}

// Given a bytearray of length N, this function converts it to human readable
// hex string of length N << 1
static inline const std::string
to_hex(const uint8_t* const bytes, const size_t len)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < len; i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }

  return ss.str();
}

// Generates len (>=0) -many random elements of type T | T = unsigned integral
template<typename T>
static inline void
random_data(T* const data, const size_t len)
  requires(std::is_unsigned_v<T>)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<T> dis;

  for (size_t i = 0; i < len; i++) {
    data[i] = dis(gen);
  }
}

}
