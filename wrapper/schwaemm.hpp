#pragma once
#include "schwaemm256_128.hpp"

// Thin C wrapper on top of underlying C++ implementation of Schwaemm256-128
// AEAD ( authenticated encryption with associated data ) function, which can be
// used for producing shared library object with C-ABI & used from other
// languages such as Rust, Python

// Function prototype
extern "C"
{
  void schwaemm256_128_encrypt(const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const size_t,
                               const uint8_t* const __restrict,
                               uint8_t* const __restrict,
                               const size_t,
                               uint8_t* const __restrict);

  bool schwaemm256_128_decrypt(const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const size_t,
                               const uint8_t* const __restrict,
                               uint8_t* const __restrict,
                               const size_t);
}

extern "C"
{

  // Given 16 -bytes secret key, 32 -bytes nonce, N -bytes plain text & M -bytes
  // associated data, this routine computes N -bytes cipher text & 16 -bytes
  // authentication tag | N, M >= 0
  void schwaemm256_128_encrypt(const uint8_t* const __restrict key,
                               const uint8_t* const __restrict nonce,
                               const uint8_t* const __restrict data,
                               const size_t d_len,
                               const uint8_t* const __restrict txt,
                               uint8_t* const __restrict enc,
                               const size_t ct_len,
                               uint8_t* const __restrict tag)
  {
    schwaemm256_128::encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
  }

  // Given 16 -bytes secret key, 32 -bytes nonce, 16 -bytes authentication tag,
  // N -bytes cipher text & M -bytes associated data, this routine computes N
  // -bytes deciphered text & a boolean verification flag | N, M >= 0
  //
  // Before consuming decrypted bytes ensure presence of truth value in returned
  // boolean flag !
  bool schwaemm256_128_decrypt(const uint8_t* const __restrict key,
                               const uint8_t* const __restrict nonce,
                               const uint8_t* const __restrict tag,
                               const uint8_t* const __restrict data,
                               const size_t d_len,
                               const uint8_t* const __restrict enc,
                               uint8_t* const __restrict dec,
                               const size_t ct_len)
  {
    using namespace schwaemm256_128;
    return decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);
  }
}
