#include "bench_hash.hpp"

// registering Esch{256,384} functions for benchmark
BENCHMARK(esch256_hash)->Arg(64);
BENCHMARK(esch256_hash)->Arg(128);
BENCHMARK(esch256_hash)->Arg(256);
BENCHMARK(esch256_hash)->Arg(512);
BENCHMARK(esch256_hash)->Arg(1024);

BENCHMARK(esch384_hash)->Arg(64);
BENCHMARK(esch384_hash)->Arg(128);
BENCHMARK(esch384_hash)->Arg(256);
BENCHMARK(esch384_hash)->Arg(512);
BENCHMARK(esch384_hash)->Arg(1024);

// main function to drive execution of benchmark
BENCHMARK_MAIN();
