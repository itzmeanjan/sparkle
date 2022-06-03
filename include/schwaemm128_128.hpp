#pragma once
#include "aead.hpp"

// Schwaemm128-128 Authenticated Encryption with Associated Data ( AEAD ) Scheme
namespace schwaemm128_128 {

// To distinguish padded associated data block from non-padded one, this
// constant is XORed into inner part of permutation state, when processing last
// associated data block
constexpr uint32_t A0 = (0u ^ (1u << 2)) << 24;

// To distinguish non-padded associated data block from padded one, this
// constant is XORed into inner part of permutation state, when processing last
// associated data block
constexpr uint32_t A1 = (1u ^ (1u << 2)) << 24;

// To distinguish padded plain text block from non-padded one, this constant is
// XORed into inner part of permutation state, when processing last plain text
// block
constexpr uint32_t M0 = (2u ^ (1u << 2)) << 24;

// To distinguish non-padded plain text block from padded one, this constant is
// XORed into inner part of permutation state, when processing last plain text
// block
constexpr uint32_t M1 = (3u ^ (1u << 2)) << 24;

// Schwaemm128-128 authenticated encryption, which computes N (>=0) -bytes of
// cipher text from equal many bytes of plain text, given 16 -bytes secret key,
// 16 -bytes public message nonce & M (>=0 ) -bytes associated data ( never
// encrypted )
//
// Schwaemm128-128 AEAD scheme provides confidentiality ( only for plain text ),
// authenticity & integrity ( for both plain text & associated data ), which
// results into generation of 16 -bytes authentication tag ( during encryption
// ), which must be checked for equality ( during decryption ) before consuming
// decrypted bytes !
//
// See algorithm 2.17 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
encrypt(const uint8_t* const __restrict key,   // 16 -bytes secret key
        const uint8_t* const __restrict nonce, // 16 -bytes nonce
        const uint8_t* const __restrict data,  // N (>=0) -bytes associated data
        const size_t d_len,                    // len(data) = N | N >= 0
        const uint8_t* const __restrict txt,   // N (>=0) -bytes plain text
        uint8_t* const __restrict enc,         // N (>=0) -bytes cipher text
        const size_t ct_len,                   // len(txt) = len(enc) = N | >= 0
        uint8_t* const __restrict tag          // 16 -bytes authentication tag
)
{
  using namespace aead;

  uint32_t state[8];

  initialize<16ul, 16ul, 4ul, 10ul>(state, key, nonce);

  if (d_len > 0) {
    process_data<16ul, 16ul, A0, A1, 4ul, 7ul, 10ul>(state, data, d_len);
  }
  if (ct_len > 0) {
    process_text<16ul, 16ul, M0, M1, 4ul, 7ul, 10ul>(state, txt, enc, ct_len);
  }

  finalize<16ul, 16ul>(state, key, tag);
}

// Schwaemm128-128 verified decryption, which computes N (>=0) -bytes of
// deciphered text from equal many bytes of encrypted text, given 16 -bytes
// secret key, 16 -bytes public message nonce, 16 -bytes authentication tag &
// M (>=0) -bytes associated data ( never encrypted )
//
// Schwaemm128-128 AEAD scheme provides confidentiality ( only for plain text ),
// authenticity & integrity ( for both plain text & associated data ), which
// results into generation of 16 -bytes authentication tag ( during encryption
// ), which is checked for equality during decryption & equality test result is
// returned from this function
//
// Note, before consuming decrypted bytes ( pointed to by `dec` ), one must
// check for truth value of this function's return value.
//
// See algorithm 2.18 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline bool
decrypt(const uint8_t* const __restrict key,   // 16 -bytes secret key
        const uint8_t* const __restrict nonce, // 16 -bytes nonce
        const uint8_t* const __restrict tag,   // 16 -bytes authentication tag
        const uint8_t* const __restrict data,  // N (>=0) -bytes associated data
        const size_t d_len,                    // len(data) = N | N >= 0
        const uint8_t* const __restrict enc,   // N (>=0) -bytes encrypted text
        uint8_t* const __restrict dec,         // N (>=0) -bytes decrypted text
        const size_t ct_len                    // len(enc) = len(dec) = N | >= 0
)
{
  using namespace aead;

  uint32_t state[8];
  uint8_t tag_[16];

  initialize<16ul, 16ul, 4ul, 10ul>(state, key, nonce);

  if (d_len > 0) {
    process_data<16ul, 16ul, A0, A1, 4ul, 7ul, 10ul>(state, data, d_len);
  }
  if (ct_len > 0) {
    process_cipher<16ul, 16ul, M0, M1, 4ul, 7ul, 10ul>(state, enc, dec, ct_len);
  }

  finalize<16ul, 16ul>(state, key, tag_);

  bool flag = false;
  for (size_t i = 0; i < 16; i++) {
    flag |= (tag[i] ^ tag_[i]);
  }
  return !flag;
}

}
