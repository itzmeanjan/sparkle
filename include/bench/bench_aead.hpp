#pragma once
#include "schwaemm.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>
#include <cassert>

// Benchmark Schwaemm256-128 Authenticated Encryption Scheme on CPU
void
schwaemm256_128_encrypt(benchmark::State& state)
{
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(schwaemm256_128::C));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(schwaemm256_128::R));
  uint8_t* tag = static_cast<uint8_t*>(malloc(schwaemm256_128::C));

  // random plain text bytes
  sparkle_utils::random_data(text, ct_len);
  // random associated data bytes
  sparkle_utils::random_data(data, dt_len);
  // random secret key ( = 128 -bit )
  sparkle_utils::random_data(key, schwaemm256_128::C);
  // random public message nonce ( = 256 -bit )
  sparkle_utils::random_data(nonce, schwaemm256_128::R);

  memset(enc, 0, ct_len);
  memset(tag, 0, schwaemm256_128::C);

  for (auto _ : state) {
    schwaemm256_128::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(dt_len);
    benchmark::DoNotOptimize(text);
    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(ct_len);
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
void
schwaemm256_128_decrypt(benchmark::State& state)
{
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(schwaemm256_128::C));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(schwaemm256_128::R));
  uint8_t* tag = static_cast<uint8_t*>(malloc(schwaemm256_128::C));

  // random plain text bytes
  sparkle_utils::random_data(text, ct_len);
  // random associated data bytes
  sparkle_utils::random_data(data, dt_len);
  // random secret key ( = 128 -bit )
  sparkle_utils::random_data(key, schwaemm256_128::C);
  // random public message nonce ( = 256 -bit )
  sparkle_utils::random_data(nonce, schwaemm256_128::R);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);
  memset(tag, 0, schwaemm256_128::C);

  schwaemm256_128::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  for (auto _ : state) {
    using namespace schwaemm256_128;
    using namespace benchmark;

    bool flg = decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len);

    DoNotOptimize(flg);
    assert(flg);
    DoNotOptimize(key);
    DoNotOptimize(nonce);
    DoNotOptimize(tag);
    DoNotOptimize(data);
    DoNotOptimize(dt_len);
    DoNotOptimize(enc);
    DoNotOptimize(dec);
    DoNotOptimize(ct_len);
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
void
schwaemm192_192_encrypt(benchmark::State& state)
{
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  constexpr size_t KNT_LEN = schwaemm192_192::R;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  sparkle_utils::random_data(text, ct_len);
  // random associated data bytes
  sparkle_utils::random_data(data, dt_len);
  // random secret key ( = 192 -bit )
  sparkle_utils::random_data(key, KNT_LEN);
  // random public message nonce ( = 192 -bit )
  sparkle_utils::random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  for (auto _ : state) {
    schwaemm192_192::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(dt_len);
    benchmark::DoNotOptimize(text);
    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(ct_len);
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
void
schwaemm192_192_decrypt(benchmark::State& state)
{
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  constexpr size_t KNT_LEN = schwaemm192_192::R;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  sparkle_utils::random_data(text, ct_len);
  // random associated data bytes
  sparkle_utils::random_data(data, dt_len);
  // random secret key ( = 192 -bit )
  sparkle_utils::random_data(key, KNT_LEN);
  // random public message nonce ( = 192 -bit )
  sparkle_utils::random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  schwaemm192_192::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  for (auto _ : state) {
    using namespace schwaemm192_192;
    using namespace benchmark;

    bool flg = decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len);

    DoNotOptimize(flg);
    assert(flg);
    DoNotOptimize(key);
    DoNotOptimize(nonce);
    DoNotOptimize(tag);
    DoNotOptimize(data);
    DoNotOptimize(dt_len);
    DoNotOptimize(enc);
    DoNotOptimize(dec);
    DoNotOptimize(ct_len);
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
void
schwaemm128_128_encrypt(benchmark::State& state)
{
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  constexpr size_t KNT_LEN = schwaemm128_128::R;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  sparkle_utils::random_data(text, ct_len);
  // random associated data bytes
  sparkle_utils::random_data(data, dt_len);
  // random secret key ( = 128 -bit )
  sparkle_utils::random_data(key, KNT_LEN);
  // random public message nonce ( = 128 -bit )
  sparkle_utils::random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  for (auto _ : state) {
    schwaemm128_128::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(dt_len);
    benchmark::DoNotOptimize(text);
    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(ct_len);
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
void
schwaemm128_128_decrypt(benchmark::State& state)
{
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  constexpr size_t KNT_LEN = schwaemm128_128::R;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  sparkle_utils::random_data(text, ct_len);
  // random associated data bytes
  sparkle_utils::random_data(data, dt_len);
  // random secret key ( = 128 -bit )
  sparkle_utils::random_data(key, KNT_LEN);
  // random public message nonce ( = 128 -bit )
  sparkle_utils::random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  schwaemm128_128::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  for (auto _ : state) {
    using namespace schwaemm128_128;
    using namespace benchmark;

    bool flg = decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len);

    DoNotOptimize(flg);
    assert(flg);
    DoNotOptimize(key);
    DoNotOptimize(nonce);
    DoNotOptimize(tag);
    DoNotOptimize(data);
    DoNotOptimize(dt_len);
    DoNotOptimize(enc);
    DoNotOptimize(dec);
    DoNotOptimize(ct_len);
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
void
schwaemm256_256_encrypt(benchmark::State& state)
{
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  constexpr size_t KNT_LEN = schwaemm256_256::R;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  sparkle_utils::random_data(text, ct_len);
  // random associated data bytes
  sparkle_utils::random_data(data, dt_len);
  // random secret key ( = 256 -bit )
  sparkle_utils::random_data(key, KNT_LEN);
  // random public message nonce ( = 256 -bit )
  sparkle_utils::random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  for (auto _ : state) {
    schwaemm256_256::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(dt_len);
    benchmark::DoNotOptimize(text);
    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(ct_len);
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
void
schwaemm256_256_decrypt(benchmark::State& state)
{
  const size_t ct_len = state.range(0);
  const size_t dt_len = state.range(1);

  constexpr size_t KNT_LEN = schwaemm256_256::R;

  // acquire memory resources
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* data = static_cast<uint8_t*>(malloc(dt_len));
  uint8_t* key = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(KNT_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(KNT_LEN));

  // random plain text bytes
  sparkle_utils::random_data(text, ct_len);
  // random associated data bytes
  sparkle_utils::random_data(data, dt_len);
  // random secret key ( = 256 -bit )
  sparkle_utils::random_data(key, KNT_LEN);
  // random public message nonce ( = 256 -bit )
  sparkle_utils::random_data(nonce, KNT_LEN);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);
  memset(tag, 0, KNT_LEN);

  schwaemm256_256::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  for (auto _ : state) {
    using namespace schwaemm256_256;
    using namespace benchmark;

    bool flg = decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len);

    DoNotOptimize(flg);
    assert(flg);
    DoNotOptimize(key);
    DoNotOptimize(nonce);
    DoNotOptimize(tag);
    DoNotOptimize(data);
    DoNotOptimize(dt_len);
    DoNotOptimize(enc);
    DoNotOptimize(dec);
    DoNotOptimize(ct_len);
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
