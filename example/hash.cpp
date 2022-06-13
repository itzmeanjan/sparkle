#include <iostream>

#include "esch256.hpp"
#include "esch384.hpp"

// Compile it with
//
// g++ -std=c++20 -Wall -I ./include example/hash.cpp
int
main()
{
  constexpr size_t d_len = 32ul; // message length in bytes

  uint8_t data[d_len];
  uint8_t dig0[32];
  uint8_t dig1[48];

  // random message bytes
  random_data(data, d_len);

  std::memset(dig0, 0, sizeof(dig0));
  std::memset(dig1, 0, sizeof(dig1));

  // compute Esch256 digest
  esch256::hash(data, d_len, dig0);
  // compute Esch384 digest
  esch384::hash(data, d_len, dig1);

  std::cout << "esch256( " << to_hex(data, d_len)
            << " ) = " << to_hex(dig0, sizeof(dig0)) << std::endl;

  std::cout << "esch384( " << to_hex(data, d_len)
            << " ) = " << to_hex(dig1, sizeof(dig1)) << std::endl;

  return EXIT_SUCCESS;
}
