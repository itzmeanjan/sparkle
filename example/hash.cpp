#include <iostream>

#include "esch256.hpp"
#include "esch384.hpp"

int main() {
  constexpr size_t d_len = 32ul;
  uint8_t data[d_len];

  random_data(data, d_len);

  uint8_t dig0[32];
  uint8_t dig1[48];

  esch256::hash(data, d_len, dig0);
  esch384::hash(data, d_len, dig1);

  std::cout << "esch256( " << to_hex(data, d_len)
            << " ) = " << to_hex(dig0, sizeof(dig0)) << std::endl;

  std::cout << "esch384( " << to_hex(data, d_len)
            << " ) = " << to_hex(dig1, sizeof(dig1)) << std::endl;

  return EXIT_SUCCESS;
}
