#pragma once
#include <benchmark/benchmark.h>

#include "esch256.hpp"
#include "esch384.hpp"
#include "utils.hpp"

// Benchmarks Esch256 cryptographic hash function implementation for random
// input of length N (>=0) -bytes | N is provided when setting up benchmark
static void esch256_hash(benchmark::State& state) {
  const size_t mlen = static_cast<size_t>(state.range(0));
  const size_t dlen = 32ul;

  uint8_t* msg = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* out = static_cast<uint8_t*>(std::malloc(dlen));

  random_data(msg, mlen);
  std::memset(out, 0, dlen);

  for (auto _ : state) {
    esch256::hash(msg, mlen, out);

    benchmark::DoNotOptimize(out);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(mlen * state.iterations()));

  std::free(msg);
  std::free(out);
}

// Benchmarks Esch384 cryptographic hash function implementation for random
// input of length N (>=0) -bytes | N is provided when setting up benchmark
static void esch384_hash(benchmark::State& state) {
  const size_t mlen = static_cast<size_t>(state.range(0));
  const size_t dlen = 48ul;

  uint8_t* msg = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* out = static_cast<uint8_t*>(std::malloc(dlen));

  random_data(msg, mlen);
  std::memset(out, 0, dlen);

  for (auto _ : state) {
    esch384::hash(msg, mlen, out);

    benchmark::DoNotOptimize(out);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(mlen * state.iterations()));

  std::free(msg);
  std::free(out);
}
