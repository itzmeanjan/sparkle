#include "esch.hpp"
#include <iostream>

// Compile it with
//
// g++ -std=c++20 -Wall -O3 -I ./include example/hash.cpp
int
main()
{
  constexpr size_t d_len = 32ul; // message length in bytes

  uint8_t data[d_len];
  uint8_t dig0[esch256::DIGEST_LEN];
  uint8_t dig1[esch384::DIGEST_LEN];

  // random message bytes
  sparkle_utils::random_data(data, d_len);

  std::memset(dig0, 0, sizeof(dig0));
  std::memset(dig1, 0, sizeof(dig1));

  // compute Esch256 digest
  esch256::hash(data, d_len, dig0);
  // compute Esch384 digest
  esch384::hash(data, d_len, dig1);

  using namespace sparkle_utils;
  std::cout << "esch256( " << to_hex(data, d_len)
            << " ) = " << to_hex(dig0, sizeof(dig0)) << std::endl;

  std::cout << "esch384( " << to_hex(data, d_len)
            << " ) = " << to_hex(dig1, sizeof(dig1)) << std::endl;

  return EXIT_SUCCESS;
}
