#pragma once
#include <benchmark/benchmark.h>

#include "schwaemm128_128.hpp"
#include "schwaemm192_192.hpp"
#include "schwaemm256_128.hpp"
#include "schwaemm256_256.hpp"
#include "utils.hpp"

// Benchmark Schwaemm256-128 Authenticated Encryption Scheme on CPU
static void schwaemm256_128_encrypt(benchmark::State& state) {
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(32));
  uint8_t* tag = static_cast<uint8_t*>(malloc(16));

  // random plain text bytes
  random_data(text, ct_len);
  // random associated data bytes
  random_data(data, dt_len);
  // random secret key ( = 128 -bit )
  random_data(key, 16);
  // random public message nonce ( = 256 -bit )
  random_data(nonce, 32);

  memset(enc, 0, ct_len);
  memset(tag, 0, 16);

  for (auto _ : state) {
    schwaemm256_128::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
  }

  const size_t per_itr_data = dt_len + ct_len;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  // deallocate all resources
  free(text);
  free(enc);
  free(data);
  free(key);
  free(nonce);
  free(tag);
}

// Benchmark Schwaemm256-128 Verified Decryption Scheme on CPU
static void schwaemm256_128_decrypt(benchmark::State& state) {
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(32));
  uint8_t* tag = static_cast<uint8_t*>(malloc(16));

  // random plain text bytes
  random_data(text, ct_len);
  // random associated data bytes
  random_data(data, dt_len);
  // random secret key ( = 128 -bit )
  random_data(key, 16);
  // random public message nonce ( = 256 -bit )
  random_data(nonce, 32);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);
  memset(tag, 0, 16);

  schwaemm256_128::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  for (auto _ : state) {
    using namespace schwaemm256_128;
    using namespace benchmark;

    DoNotOptimize(decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len));
    DoNotOptimize(dec);
  }

  const size_t per_itr_data = dt_len + ct_len;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  // deallocate all resources
  free(text);
  free(enc);
  free(dec);
  free(data);
  free(key);
  free(nonce);
  free(tag);
}

// Benchmark Schwaemm192-192 Authenticated Encryption Scheme on CPU
static void schwaemm192_192_encrypt(benchmark::State& state) {
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);
  constexpr size_t KNT_LEN = 24;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  random_data(text, ct_len);
  // random associated data bytes
  random_data(data, dt_len);
  // random secret key ( = 192 -bit )
  random_data(key, KNT_LEN);
  // random public message nonce ( = 192 -bit )
  random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  for (auto _ : state) {
    schwaemm192_192::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
  }

  const size_t per_itr_data = dt_len + ct_len;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  // deallocate all resources
  free(text);
  free(enc);
  free(data);
  free(key);
  free(nonce);
  free(tag);
}

// Benchmark Schwaemm192-192 Verified Decryption Scheme on CPU
static void schwaemm192_192_decrypt(benchmark::State& state) {
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);
  constexpr size_t KNT_LEN = 24;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  random_data(text, ct_len);
  // random associated data bytes
  random_data(data, dt_len);
  // random secret key ( = 192 -bit )
  random_data(key, KNT_LEN);
  // random public message nonce ( = 192 -bit )
  random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  schwaemm192_192::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  for (auto _ : state) {
    using namespace schwaemm192_192;
    using namespace benchmark;

    DoNotOptimize(decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len));
    DoNotOptimize(dec);
  }

  const size_t per_itr_data = dt_len + ct_len;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  // deallocate all resources
  free(text);
  free(enc);
  free(dec);
  free(data);
  free(key);
  free(nonce);
  free(tag);
}

// Benchmark Schwaemm128-128 Authenticated Encryption Scheme on CPU
static void schwaemm128_128_encrypt(benchmark::State& state) {
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);
  constexpr size_t KNT_LEN = 16;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  random_data(text, ct_len);
  // random associated data bytes
  random_data(data, dt_len);
  // random secret key ( = 128 -bit )
  random_data(key, KNT_LEN);
  // random public message nonce ( = 128 -bit )
  random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  for (auto _ : state) {
    schwaemm128_128::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
  }

  const size_t per_itr_data = dt_len + ct_len;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  // deallocate all resources
  free(text);
  free(enc);
  free(data);
  free(key);
  free(nonce);
  free(tag);
}

// Benchmark Schwaemm128-128 Verified Decryption Scheme on CPU
static void schwaemm128_128_decrypt(benchmark::State& state) {
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);
  constexpr size_t KNT_LEN = 16;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  random_data(text, ct_len);
  // random associated data bytes
  random_data(data, dt_len);
  // random secret key ( = 128 -bit )
  random_data(key, KNT_LEN);
  // random public message nonce ( = 128 -bit )
  random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  schwaemm128_128::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  for (auto _ : state) {
    using namespace schwaemm128_128;
    using namespace benchmark;

    DoNotOptimize(decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len));
    DoNotOptimize(dec);
  }

  const size_t per_itr_data = dt_len + ct_len;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  // deallocate all resources
  free(text);
  free(enc);
  free(dec);
  free(data);
  free(key);
  free(nonce);
  free(tag);
}

// Benchmark Schwaemm256-256 Authenticated Encryption Scheme on CPU
static void schwaemm256_256_encrypt(benchmark::State& state) {
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  constexpr size_t KNT_LEN = schwaemm256_256::RATE;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  random_data(text, ct_len);
  // random associated data bytes
  random_data(data, dt_len);
  // random secret key ( = 256 -bit )
  random_data(key, KNT_LEN);
  // random public message nonce ( = 256 -bit )
  random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  for (auto _ : state) {
    schwaemm256_256::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
  }

  const size_t per_itr_data = dt_len + ct_len;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  // deallocate all resources
  free(text);
  free(enc);
  free(data);
  free(key);
  free(nonce);
  free(tag);
}

// Benchmark Schwaemm256-256 Verified Decryption Scheme on CPU
static void schwaemm256_256_decrypt(benchmark::State& state) {
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  constexpr size_t KNT_LEN = schwaemm256_256::RATE;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  random_data(text, ct_len);
  // random associated data bytes
  random_data(data, dt_len);
  // random secret key ( = 256 -bit )
  random_data(key, KNT_LEN);
  // random public message nonce ( = 256 -bit )
  random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  schwaemm256_256::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  for (auto _ : state) {
    using namespace schwaemm256_256;
    using namespace benchmark;

    DoNotOptimize(decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len));
    DoNotOptimize(dec);
  }

  const size_t per_itr_data = dt_len + ct_len;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  // deallocate all resources
  free(text);
  free(enc);
  free(dec);
  free(data);
  free(key);
  free(nonce);
  free(tag);
}
