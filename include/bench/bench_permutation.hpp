#pragma once
#include "sparkle.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmark Sparkle Cipher Suite on CPU
namespace bench_sparkle {

// Benchmark slim/ big variant of Sparkle{256, 384, 512} permutation
template<const size_t nb, const size_t ns>
void
sparkle(benchmark::State& state)
{
  uint32_t st[2 * nb];
  sparkle_utils::random_data(st, 2 * nb);

  for (auto _ : state) {
    sparkle::sparkle<nb, ns>(st);
    benchmark::DoNotOptimize(st);
  }

  const size_t total_bytes = sizeof(st) * state.iterations();
  state.SetBytesProcessed(total_bytes);
}

} // namespace bench_sparkle
