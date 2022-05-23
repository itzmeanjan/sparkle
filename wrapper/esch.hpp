#pragma once
#include "esch256.hpp"
#include "esch384.hpp"

// Thin C wrapper on top of underlying C++ implementation of Esch{256,384} hash
// function, which can be used for producing shared library object with C-ABI &
// used from other languages such as Rust, Python

// Function prototype
extern "C"
{
  void esch256_hash(const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict);

  void esch384_hash(const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict);
}

// Function implementation
extern "C"
{
  // Given N (>=0) -bytes input message, this routines computes 32 -bytes output
  // digest, using Esch256 hash algorithm
  void esch256_hash(const uint8_t* const __restrict in,
                    const size_t ilen,
                    uint8_t* const __restrict out)
  {
    esch256::hash(in, ilen, out);
  }

  // Given N (>=0) -bytes input message, this routines computes 48 -bytes output
  // digest, using Esch384 hash algorithm
  void esch384_hash(const uint8_t* const __restrict in,
                    const size_t ilen,
                    uint8_t* const __restrict out)
  {
    esch384::hash(in, ilen, out);
  }
}
