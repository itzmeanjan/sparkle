#pragma once
#include "aead.hpp"

// Schwaemm256-256 Authenticated Encryption with Associated Data ( AEAD ) Scheme
namespace schwaemm256_256 {

// Rate width of permutation state, in bytes
constexpr size_t R = 32ul;

// Capacity width of permutation state, in bytes
constexpr size_t C = 32ul;

// # -of branches in permutation state; each branch is a tuple of two 32 -bit
// unsigned words
constexpr size_t BR = ((R + C) >> 2) >> 1;

// # -of steps in slim variant of sparkle permutation
constexpr size_t S = 8ul;

// # -of steps in big variant of sparkle permutation
constexpr size_t B = 12ul;

// To distinguish padded associated data block from non-padded one, this
// constant is XORed into inner part of permutation state, when processing last
// associated data block
constexpr uint32_t A0 = (0u ^ (1u << 4)) << 24;

// To distinguish non-padded associated data block from padded one, this
// constant is XORed into inner part of permutation state, when processing last
// associated data block
constexpr uint32_t A1 = (1u ^ (1u << 4)) << 24;

// To distinguish padded plain text block from non-padded one, this constant is
// XORed into inner part of permutation state, when processing last plain text
// block
constexpr uint32_t M0 = (2u ^ (1u << 4)) << 24;

// To distinguish non-padded plain text block from padded one, this constant is
// XORed into inner part of permutation state, when processing last plain text
// block
constexpr uint32_t M1 = (3u ^ (1u << 4)) << 24;

// Schwaemm256-256 authenticated encryption, which computes N (>=0) -bytes of
// cipher text from equal many bytes of plain text, given 32 -bytes secret key,
// 32 -bytes public message nonce & M (>=0 ) -bytes associated data ( never
// encrypted )
//
// Schwaemm256-256 AEAD scheme provides confidentiality ( only for plain text ),
// authenticity & integrity ( for both plain text & associated data ), which
// results into generation of 32 -bytes authentication tag ( during encryption
// ), which must be checked for equality ( during decryption ) before consuming
// decrypted bytes !
//
// See algorithm 2.19 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
encrypt(const uint8_t* const __restrict key,   // 32 -bytes secret key
        const uint8_t* const __restrict nonce, // 32 -bytes nonce
        const uint8_t* const __restrict data,  // N (>=0) -bytes associated data
        const size_t d_len,                    // len(data) = N | N >= 0
        const uint8_t* const __restrict txt,   // N (>=0) -bytes plain text
        uint8_t* const __restrict enc,         // N (>=0) -bytes cipher text
        const size_t ct_len,                   // len(txt) = len(enc) = N | >= 0
        uint8_t* const __restrict tag          // 32 -bytes authentication tag
)
{
  aead::encrypt<R, C, A0, A1, M0, M1, BR, S, B>(
    key, nonce, data, d_len, txt, enc, ct_len, tag);
}

// Schwaemm256-256 verified decryption, which computes N (>=0) -bytes of
// deciphered text from equal many bytes of encrypted text, given 32 -bytes
// secret key, 32 -bytes public message nonce, 32 -bytes authentication tag &
// M (>=0) -bytes associated data ( never encrypted )
//
// Schwaemm256-256 AEAD scheme provides confidentiality ( only for plain text ),
// authenticity & integrity ( for both plain text & associated data ), which
// results into generation of 32 -bytes authentication tag ( during encryption
// ), which is checked for equality during decryption & equality test result is
// returned from this function
//
// Note, before consuming decrypted bytes ( pointed to by `dec` ), one must
// check for truth value of this function's return value.
//
// See algorithm 2.20 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline bool
decrypt(const uint8_t* const __restrict key,   // 32 -bytes secret key
        const uint8_t* const __restrict nonce, // 32 -bytes nonce
        const uint8_t* const __restrict tag,   // 32 -bytes authentication tag
        const uint8_t* const __restrict data,  // N (>=0) -bytes associated data
        const size_t d_len,                    // len(data) = N | N >= 0
        const uint8_t* const __restrict enc,   // N (>=0) -bytes encrypted text
        uint8_t* const __restrict dec,         // N (>=0) -bytes decrypted text
        const size_t ct_len                    // len(enc) = len(dec) = N | >= 0
)
{
  return aead::decrypt<R, C, A0, A1, M0, M1, BR, S, B>(
    key, nonce, tag, data, d_len, enc, dec, ct_len);
}

} // namespace schwaemm256_256
