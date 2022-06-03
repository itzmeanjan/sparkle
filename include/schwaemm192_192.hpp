#pragma once
#include "aead.hpp"

// Schwaemm192-192 Authenticated Encryption with Associated Data ( AEAD ) Scheme
namespace schwaemm192_192 {

// To distinguish padded associated data block from non-padded one, this
// constant is XORed into inner part of permutation state, when processing last
// associated data block
constexpr uint32_t A0 = (0u ^ (1u << 3)) << 24;

// To distinguish non-padded associated data block from padded one, this
// constant is XORed into inner part of permutation state, when processing last
// associated data block
constexpr uint32_t A1 = (1u ^ (1u << 3)) << 24;

// To distinguish padded plain text block from non-padded one, this constant is
// XORed into inner part of permutation state, when processing last plain text
// block
constexpr uint32_t M0 = (2u ^ (1u << 3)) << 24;

// To distinguish non-padded plain text block from padded one, this constant is
// XORed into inner part of permutation state, when processing last plain text
// block
constexpr uint32_t M1 = (3u ^ (1u << 3)) << 24;

// Schwaemm192-192 authenticated encryption, which computes N (>=0) -bytes of
// cipher text from equal many bytes of plain text, given 24 -bytes secret key,
// 24 -bytes public message nonce & M (>=0 ) -bytes associated data ( never
// encrypted )
//
// Schwaemm192-192 AEAD scheme provides confidentiality ( only for plain text ),
// authenticity & integrity ( for both plain text & associated data ), which
// results into generation of 24 -bytes authentication tag ( during encryption
// ), which must be checked for equality ( during decryption ) before consuming
// decrypted bytes !
//
// See algorithm 2.15 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline void
encrypt(const uint8_t* const __restrict key,   // 24 -bytes secret key
        const uint8_t* const __restrict nonce, // 24 -bytes nonce
        const uint8_t* const __restrict data,  // N (>=0) -bytes associated data
        const size_t d_len,                    // len(data) = N | N >= 0
        const uint8_t* const __restrict txt,   // N (>=0) -bytes plain text
        uint8_t* const __restrict enc,         // N (>=0) -bytes cipher text
        const size_t ct_len,                   // len(txt) = len(enc) = N | >= 0
        uint8_t* const __restrict tag          // 24 -bytes authentication tag
)
{
  using namespace aead;

  uint32_t state[12];

  initialize<24ul, 24ul, 6ul, 11ul>(state, key, nonce);

  if (d_len > 0) {
    process_data<24ul, 24ul, A0, A1, 6ul, 7ul, 11ul>(state, data, d_len);
  }
  if (ct_len > 0) {
    process_text<24ul, 24ul, M0, M1, 6ul, 7ul, 11ul>(state, txt, enc, ct_len);
  }

  finalize<24ul, 24ul>(state, key, tag);
}

// Schwaemm192-192 verified decryption, which computes N (>=0) -bytes of
// deciphered text from equal many bytes of encrypted text, given 24 -bytes
// secret key, 24 -bytes public message nonce, 24 -bytes authentication tag &
// M (>=0) -bytes associated data ( never encrypted )
//
// Schwaemm192-192 AEAD scheme provides confidentiality ( only for plain text ),
// authenticity & integrity ( for both plain text & associated data ), which
// results into generation of 24 -bytes authentication tag ( during encryption
// ), which is checked for equality during decryption & equality test result is
// returned from this function
//
// Note, before consuming decrypted bytes ( pointed to by `dec` ), one must
// check for truth value of this function's return value.
//
// See algorithm 2.16 of Sparkle Specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
static inline bool
decrypt(const uint8_t* const __restrict key,   // 24 -bytes secret key
        const uint8_t* const __restrict nonce, // 24 -bytes nonce
        const uint8_t* const __restrict tag,   // 24 -bytes authentication tag
        const uint8_t* const __restrict data,  // N (>=0) -bytes associated data
        const size_t d_len,                    // len(data) = N | N >= 0
        const uint8_t* const __restrict enc,   // N (>=0) -bytes encrypted text
        uint8_t* const __restrict dec,         // N (>=0) -bytes decrypted text
        const size_t ct_len                    // len(enc) = len(dec) = N | >= 0
)
{
  using namespace aead;

  uint32_t state[12];
  uint8_t tag_[24];

  initialize<24ul, 24ul, 6ul, 11ul>(state, key, nonce);

  if (d_len > 0) {
    process_data<24ul, 24ul, A0, A1, 6ul, 7ul, 11ul>(state, data, d_len);
  }
  if (ct_len > 0) {
    process_cipher<24ul, 24ul, M0, M1, 6ul, 7ul, 11ul>(state, enc, dec, ct_len);
  }

  finalize<24ul, 24ul>(state, key, tag_);

  bool flag = false;
  for (size_t i = 0; i < 24; i++) {
    flag |= (tag[i] ^ tag_[i]);
  }
  return !flag;
}

}
