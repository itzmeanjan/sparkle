#pragma once
#include "schwaemm128_128.hpp"
#include "schwaemm192_192.hpp"
#include "schwaemm256_128.hpp"
#include "schwaemm256_256.hpp"

// Thin C wrapper on top of underlying C++ implementation of Schwaemm256-128,
// Schwaemm192-192, Schwaemm128-128, Schwaemm256-256 AEAD ( authenticated
// encryption with associated data ) function, which can be used for producing
// shared library object with C-ABI & used from other languages such as Rust,
// Python

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

  void schwaemm192_192_encrypt(const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const size_t,
                               const uint8_t* const __restrict,
                               uint8_t* const __restrict,
                               const size_t,
                               uint8_t* const __restrict);

  bool schwaemm192_192_decrypt(const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const size_t,
                               const uint8_t* const __restrict,
                               uint8_t* const __restrict,
                               const size_t);

  void schwaemm128_128_encrypt(const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const size_t,
                               const uint8_t* const __restrict,
                               uint8_t* const __restrict,
                               const size_t,
                               uint8_t* const __restrict);

  bool schwaemm128_128_decrypt(const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const size_t,
                               const uint8_t* const __restrict,
                               uint8_t* const __restrict,
                               const size_t);

  void schwaemm256_256_encrypt(const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const uint8_t* const __restrict,
                               const size_t,
                               const uint8_t* const __restrict,
                               uint8_t* const __restrict,
                               const size_t,
                               uint8_t* const __restrict);

  bool schwaemm256_256_decrypt(const uint8_t* const __restrict,
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

  // Given 24 -bytes secret key, 24 -bytes nonce, N -bytes plain text & M -bytes
  // associated data, this routine computes N -bytes cipher text & 24 -bytes
  // authentication tag | N, M >= 0
  void schwaemm192_192_encrypt(const uint8_t* const __restrict key,
                               const uint8_t* const __restrict nonce,
                               const uint8_t* const __restrict data,
                               const size_t d_len,
                               const uint8_t* const __restrict txt,
                               uint8_t* const __restrict enc,
                               const size_t ct_len,
                               uint8_t* const __restrict tag)
  {
    schwaemm192_192::encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
  }

  // Given 24 -bytes secret key, 24 -bytes nonce, 24 -bytes authentication tag,
  // N -bytes cipher text & M -bytes associated data, this routine computes N
  // -bytes deciphered text & a boolean verification flag | N, M >= 0
  //
  // Before consuming decrypted bytes ensure presence of truth value in returned
  // boolean flag !
  bool schwaemm192_192_decrypt(const uint8_t* const __restrict key,
                               const uint8_t* const __restrict nonce,
                               const uint8_t* const __restrict tag,
                               const uint8_t* const __restrict data,
                               const size_t d_len,
                               const uint8_t* const __restrict enc,
                               uint8_t* const __restrict dec,
                               const size_t ct_len)
  {
    using namespace schwaemm192_192;
    return decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, N -bytes plain text & M -bytes
  // associated data, this routine computes N -bytes cipher text & 16 -bytes
  // authentication tag | N, M >= 0
  void schwaemm128_128_encrypt(const uint8_t* const __restrict key,
                               const uint8_t* const __restrict nonce,
                               const uint8_t* const __restrict data,
                               const size_t d_len,
                               const uint8_t* const __restrict txt,
                               uint8_t* const __restrict enc,
                               const size_t ct_len,
                               uint8_t* const __restrict tag)
  {
    schwaemm128_128::encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, 16 -bytes authentication tag,
  // N -bytes cipher text & M -bytes associated data, this routine computes N
  // -bytes deciphered text & a boolean verification flag | N, M >= 0
  //
  // Before consuming decrypted bytes ensure presence of truth value in returned
  // boolean flag !
  bool schwaemm128_128_decrypt(const uint8_t* const __restrict key,
                               const uint8_t* const __restrict nonce,
                               const uint8_t* const __restrict tag,
                               const uint8_t* const __restrict data,
                               const size_t d_len,
                               const uint8_t* const __restrict enc,
                               uint8_t* const __restrict dec,
                               const size_t ct_len)
  {
    using namespace schwaemm128_128;
    return decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);
  }

  // Given 32 -bytes secret key, 32 -bytes nonce, N -bytes plain text & M -bytes
  // associated data, this routine computes N -bytes cipher text & 32 -bytes
  // authentication tag | N, M >= 0
  void schwaemm256_256_encrypt(const uint8_t* const __restrict key,
                               const uint8_t* const __restrict nonce,
                               const uint8_t* const __restrict data,
                               const size_t d_len,
                               const uint8_t* const __restrict txt,
                               uint8_t* const __restrict enc,
                               const size_t ct_len,
                               uint8_t* const __restrict tag)
  {
    schwaemm256_256::encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
  }

  // Given 32 -bytes secret key, 32 -bytes nonce, 32 -bytes authentication tag,
  // N -bytes cipher text & M -bytes associated data, this routine computes N
  // -bytes deciphered text & a boolean verification flag | N, M >= 0
  //
  // Before consuming decrypted bytes ensure presence of truth value in returned
  // boolean flag !
  bool schwaemm256_256_decrypt(const uint8_t* const __restrict key,
                               const uint8_t* const __restrict nonce,
                               const uint8_t* const __restrict tag,
                               const uint8_t* const __restrict data,
                               const size_t d_len,
                               const uint8_t* const __restrict enc,
                               uint8_t* const __restrict dec,
                               const size_t ct_len)
  {
    using namespace schwaemm256_256;
    return decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);
  }
}
