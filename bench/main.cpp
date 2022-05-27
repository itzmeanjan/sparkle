#include "bench_aead.hpp"
#include "bench_hash.hpp"

// registering Esch{256,384} functions for benchmark
BENCHMARK(esch256_hash)->Arg(64);
BENCHMARK(esch256_hash)->Arg(128);
BENCHMARK(esch256_hash)->Arg(256);
BENCHMARK(esch256_hash)->Arg(512);
BENCHMARK(esch256_hash)->Arg(1024);
BENCHMARK(esch256_hash)->Arg(2048);
BENCHMARK(esch256_hash)->Arg(4096);

BENCHMARK(esch384_hash)->Arg(64);
BENCHMARK(esch384_hash)->Arg(128);
BENCHMARK(esch384_hash)->Arg(256);
BENCHMARK(esch384_hash)->Arg(512);
BENCHMARK(esch384_hash)->Arg(1024);
BENCHMARK(esch384_hash)->Arg(2048);
BENCHMARK(esch384_hash)->Arg(4096);

// registering Schwaemm256-128 AEAD encrypt/ decrypt routines for benchmark
//
// note, associated data size is set to be 32 -bytes for all cases
BENCHMARK(schwaemm256_128_encrypt)->Args({ 64, 32 });
BENCHMARK(schwaemm256_128_decrypt)->Args({ 64, 32 });
BENCHMARK(schwaemm256_128_encrypt)->Args({ 128, 32 });
BENCHMARK(schwaemm256_128_decrypt)->Args({ 128, 32 });
BENCHMARK(schwaemm256_128_encrypt)->Args({ 256, 32 });
BENCHMARK(schwaemm256_128_decrypt)->Args({ 256, 32 });
BENCHMARK(schwaemm256_128_encrypt)->Args({ 512, 32 });
BENCHMARK(schwaemm256_128_decrypt)->Args({ 512, 32 });
BENCHMARK(schwaemm256_128_encrypt)->Args({ 1024, 32 });
BENCHMARK(schwaemm256_128_decrypt)->Args({ 1024, 32 });
BENCHMARK(schwaemm256_128_encrypt)->Args({ 2048, 32 });
BENCHMARK(schwaemm256_128_decrypt)->Args({ 2048, 32 });
BENCHMARK(schwaemm256_128_encrypt)->Args({ 4096, 32 });
BENCHMARK(schwaemm256_128_decrypt)->Args({ 4096, 32 });

// registering Schwaemm192-192 AEAD encrypt/ decrypt routines for benchmark
//
// note, associated data size is set to be 32 -bytes for all cases
BENCHMARK(schwaemm192_192_encrypt)->Args({ 64, 32 });
BENCHMARK(schwaemm192_192_decrypt)->Args({ 64, 32 });
BENCHMARK(schwaemm192_192_encrypt)->Args({ 128, 32 });
BENCHMARK(schwaemm192_192_decrypt)->Args({ 128, 32 });
BENCHMARK(schwaemm192_192_encrypt)->Args({ 256, 32 });
BENCHMARK(schwaemm192_192_decrypt)->Args({ 256, 32 });
BENCHMARK(schwaemm192_192_encrypt)->Args({ 512, 32 });
BENCHMARK(schwaemm192_192_decrypt)->Args({ 512, 32 });
BENCHMARK(schwaemm192_192_encrypt)->Args({ 1024, 32 });
BENCHMARK(schwaemm192_192_decrypt)->Args({ 1024, 32 });
BENCHMARK(schwaemm192_192_encrypt)->Args({ 2048, 32 });
BENCHMARK(schwaemm192_192_decrypt)->Args({ 2048, 32 });
BENCHMARK(schwaemm192_192_encrypt)->Args({ 4096, 32 });
BENCHMARK(schwaemm192_192_decrypt)->Args({ 4096, 32 });

// registering Schwaemm128-128 AEAD encrypt/ decrypt routines for benchmark
//
// note, associated data size is set to be 32 -bytes for all cases
BENCHMARK(schwaemm128_128_encrypt)->Args({ 64, 32 });
BENCHMARK(schwaemm128_128_decrypt)->Args({ 64, 32 });
BENCHMARK(schwaemm128_128_encrypt)->Args({ 128, 32 });
BENCHMARK(schwaemm128_128_decrypt)->Args({ 128, 32 });
BENCHMARK(schwaemm128_128_encrypt)->Args({ 256, 32 });
BENCHMARK(schwaemm128_128_decrypt)->Args({ 256, 32 });
BENCHMARK(schwaemm128_128_encrypt)->Args({ 512, 32 });
BENCHMARK(schwaemm128_128_decrypt)->Args({ 512, 32 });
BENCHMARK(schwaemm128_128_encrypt)->Args({ 1024, 32 });
BENCHMARK(schwaemm128_128_decrypt)->Args({ 1024, 32 });
BENCHMARK(schwaemm128_128_encrypt)->Args({ 2048, 32 });
BENCHMARK(schwaemm128_128_decrypt)->Args({ 2048, 32 });
BENCHMARK(schwaemm128_128_encrypt)->Args({ 4096, 32 });
BENCHMARK(schwaemm128_128_decrypt)->Args({ 4096, 32 });

// main function to drive execution of benchmark
BENCHMARK_MAIN();
