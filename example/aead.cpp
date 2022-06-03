#include <cassert>
#include <iostream>

#include "schwaemm128_128.hpp"
#include "schwaemm192_192.hpp"
#include "schwaemm256_128.hpp"
#include "schwaemm256_256.hpp"

int main() {
  constexpr size_t d_len = 32ul;
  constexpr size_t ct_len = 32ul;

  uint8_t data[d_len];
  uint8_t txt[ct_len];
  uint8_t enc[ct_len];
  uint8_t dec[ct_len];

  random_data(data, d_len);
  random_data(txt, d_len);

  std::cout << "data = " << to_hex(data, sizeof(data)) << std::endl;
  std::cout << "text = " << to_hex(txt, sizeof(txt)) << std::endl;

  {
    std::cout << "\nSchwaemm128-128 AEAD\n" << std::endl;

    uint8_t key[schwaemm128_128::C];
    uint8_t nonce[schwaemm128_128::R];
    uint8_t tag[schwaemm128_128::C];

    random_data(key, sizeof(key));
    random_data(nonce, sizeof(nonce));

    std::memset(enc, 0, sizeof(enc));
    std::memset(dec, 0, sizeof(dec));

    using namespace schwaemm128_128;

    encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
    const bool f = decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);

    assert(f);

    bool cmp = false;
    for (size_t i = 0; i < ct_len; i++) {
      cmp |= dec[i] ^ txt[i];
    }

    assert(!cmp);

    std::cout << "key           = " << to_hex(key, sizeof(key)) << std::endl;
    std::cout << "nonce         = " << to_hex(nonce, sizeof(nonce))
              << std::endl;
    std::cout << "cipher        = " << to_hex(enc, sizeof(enc)) << std::endl;
    std::cout << "decrypted     = " << to_hex(dec, sizeof(dec)) << std::endl;
  }

  {
    std::cout << "\nSchwaemm192-192 AEAD\n" << std::endl;

    uint8_t key[schwaemm192_192::C];
    uint8_t nonce[schwaemm192_192::R];
    uint8_t tag[schwaemm192_192::C];

    random_data(key, sizeof(key));
    random_data(nonce, sizeof(nonce));

    std::memset(enc, 0, sizeof(enc));
    std::memset(dec, 0, sizeof(dec));

    using namespace schwaemm192_192;

    encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
    const bool f = decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);

    assert(f);

    bool cmp = false;
    for (size_t i = 0; i < ct_len; i++) {
      cmp |= dec[i] ^ txt[i];
    }

    assert(!cmp);

    std::cout << "key           = " << to_hex(key, sizeof(key)) << std::endl;
    std::cout << "nonce         = " << to_hex(nonce, sizeof(nonce))
              << std::endl;
    std::cout << "cipher        = " << to_hex(enc, sizeof(enc)) << std::endl;
    std::cout << "decrypted     = " << to_hex(dec, sizeof(dec)) << std::endl;
  }

  {
    std::cout << "\nSchwaemm256-128 AEAD\n" << std::endl;

    uint8_t key[schwaemm256_128::C];
    uint8_t nonce[schwaemm256_128::R];
    uint8_t tag[schwaemm256_128::C];

    random_data(key, sizeof(key));
    random_data(nonce, sizeof(nonce));

    std::memset(enc, 0, sizeof(enc));
    std::memset(dec, 0, sizeof(dec));

    using namespace schwaemm256_128;

    encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
    const bool f = decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);

    assert(f);

    bool cmp = false;
    for (size_t i = 0; i < ct_len; i++) {
      cmp |= dec[i] ^ txt[i];
    }

    assert(!cmp);

    std::cout << "key           = " << to_hex(key, sizeof(key)) << std::endl;
    std::cout << "nonce         = " << to_hex(nonce, sizeof(nonce))
              << std::endl;
    std::cout << "cipher        = " << to_hex(enc, sizeof(enc)) << std::endl;
    std::cout << "decrypted     = " << to_hex(dec, sizeof(dec)) << std::endl;
  }

  {
    std::cout << "\nSchwaemm256-256 AEAD\n" << std::endl;

    uint8_t key[schwaemm256_256::C];
    uint8_t nonce[schwaemm256_256::R];
    uint8_t tag[schwaemm256_256::C];

    random_data(key, sizeof(key));
    random_data(nonce, sizeof(nonce));

    std::memset(enc, 0, sizeof(enc));
    std::memset(dec, 0, sizeof(dec));

    using namespace schwaemm256_256;

    encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
    const bool f = decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);

    assert(f);

    bool cmp = false;
    for (size_t i = 0; i < ct_len; i++) {
      cmp |= dec[i] ^ txt[i];
    }

    assert(!cmp);

    std::cout << "key           = " << to_hex(key, sizeof(key)) << std::endl;
    std::cout << "nonce         = " << to_hex(nonce, sizeof(nonce))
              << std::endl;
    std::cout << "cipher        = " << to_hex(enc, sizeof(enc)) << std::endl;
    std::cout << "decrypted     = " << to_hex(dec, sizeof(dec)) << std::endl;
  }

  return EXIT_SUCCESS;
}
