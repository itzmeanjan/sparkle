#include <cassert>
#include <iostream>

#include "schwaemm128_128.hpp"
#include "schwaemm192_192.hpp"
#include "schwaemm256_128.hpp"
#include "schwaemm256_256.hpp"

// Compile it with
//
// g++ -std=c++20 -Wall -O3 -I ./include example/aead.cpp
int
main()
{
  constexpr size_t d_len = 32ul;  // associate data byte length
  constexpr size_t ct_len = 32ul; // plain/ cipher text byte length

  uint8_t data[d_len];
  uint8_t txt[ct_len];
  uint8_t enc[ct_len];
  uint8_t dec[ct_len];

  sparkle_utils::random_data(data, d_len); // generate random associated data
  sparkle_utils::random_data(txt, d_len);  // generate random plain text

  std::cout << "data = " << sparkle_utils::to_hex(data, sizeof(data)) << "\n";
  std::cout << "text = " << sparkle_utils::to_hex(txt, sizeof(txt)) << "\n";

  {
    std::cout << "\nSchwaemm128-128 AEAD\n"
              << "\n";

    uint8_t key[schwaemm128_128::C];
    uint8_t nonce[schwaemm128_128::R];
    uint8_t tag[schwaemm128_128::C];

    sparkle_utils::random_data(key, sizeof(key));
    sparkle_utils::random_data(nonce, sizeof(nonce));

    std::memset(enc, 0, sizeof(enc));
    std::memset(dec, 0, sizeof(dec));

    using namespace schwaemm128_128;

    // authenticated encryption with Schwaemm128-128 AEAD
    encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
    // verified decryption with Schwaemm128-128 AEAD
    const bool f = decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);

    assert(f);

    bool cmp = false;
    for (size_t i = 0; i < ct_len; i++) {
      cmp |= dec[i] ^ txt[i];
    }

    assert(!cmp);

    using namespace sparkle_utils;
    std::cout << "key           = " << to_hex(key, sizeof(key)) << "\n";
    std::cout << "nonce         = " << to_hex(nonce, sizeof(nonce)) << "\n";
    std::cout << "cipher        = " << to_hex(enc, sizeof(enc)) << "\n";
    std::cout << "decrypted     = " << to_hex(dec, sizeof(dec)) << "\n";
  }

  {
    std::cout << "\nSchwaemm192-192 AEAD\n"
              << "\n";

    uint8_t key[schwaemm192_192::C];
    uint8_t nonce[schwaemm192_192::R];
    uint8_t tag[schwaemm192_192::C];

    sparkle_utils::random_data(key, sizeof(key));
    sparkle_utils::random_data(nonce, sizeof(nonce));

    std::memset(enc, 0, sizeof(enc));
    std::memset(dec, 0, sizeof(dec));

    using namespace schwaemm192_192;

    // authenticated encryption with Schwaemm192-192 AEAD
    encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
    // verified decryption with Schwaemm192-192 AEAD
    const bool f = decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);

    assert(f);

    bool cmp = false;
    for (size_t i = 0; i < ct_len; i++) {
      cmp |= dec[i] ^ txt[i];
    }

    assert(!cmp);

    using namespace sparkle_utils;
    std::cout << "key           = " << to_hex(key, sizeof(key)) << "\n";
    std::cout << "nonce         = " << to_hex(nonce, sizeof(nonce)) << "\n";
    std::cout << "cipher        = " << to_hex(enc, sizeof(enc)) << "\n";
    std::cout << "decrypted     = " << to_hex(dec, sizeof(dec)) << "\n";
  }

  {
    std::cout << "\nSchwaemm256-128 AEAD\n"
              << "\n";

    uint8_t key[schwaemm256_128::C];
    uint8_t nonce[schwaemm256_128::R];
    uint8_t tag[schwaemm256_128::C];

    sparkle_utils::random_data(key, sizeof(key));
    sparkle_utils::random_data(nonce, sizeof(nonce));

    std::memset(enc, 0, sizeof(enc));
    std::memset(dec, 0, sizeof(dec));

    using namespace schwaemm256_128;

    // authenticated encryption with Schwaemm256-128 AEAD
    encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
    // verified decryption with Schwaemm256-128 AEAD
    const bool f = decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);

    assert(f);

    bool cmp = false;
    for (size_t i = 0; i < ct_len; i++) {
      cmp |= dec[i] ^ txt[i];
    }

    assert(!cmp);

    using namespace sparkle_utils;
    std::cout << "key           = " << to_hex(key, sizeof(key)) << "\n";
    std::cout << "nonce         = " << to_hex(nonce, sizeof(nonce)) << "\n";
    std::cout << "cipher        = " << to_hex(enc, sizeof(enc)) << "\n";
    std::cout << "decrypted     = " << to_hex(dec, sizeof(dec)) << "\n";
  }

  {
    std::cout << "\nSchwaemm256-256 AEAD\n"
              << "\n";

    uint8_t key[schwaemm256_256::C];
    uint8_t nonce[schwaemm256_256::R];
    uint8_t tag[schwaemm256_256::C];

    sparkle_utils::random_data(key, sizeof(key));
    sparkle_utils::random_data(nonce, sizeof(nonce));

    std::memset(enc, 0, sizeof(enc));
    std::memset(dec, 0, sizeof(dec));

    using namespace schwaemm256_256;

    // authenticated encryption with Schwaemm256-256 AEAD
    encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
    // verified decryption with Schwaemm256-256 AEAD
    const bool f = decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);

    assert(f);

    bool cmp = false;
    for (size_t i = 0; i < ct_len; i++) {
      cmp |= dec[i] ^ txt[i];
    }

    assert(!cmp);

    using namespace sparkle_utils;
    std::cout << "key           = " << to_hex(key, sizeof(key)) << "\n";
    std::cout << "nonce         = " << to_hex(nonce, sizeof(nonce)) << "\n";
    std::cout << "cipher        = " << to_hex(enc, sizeof(enc)) << "\n";
    std::cout << "decrypted     = " << to_hex(dec, sizeof(dec)) << "\n";
  }

  return EXIT_SUCCESS;
}
