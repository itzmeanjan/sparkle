# sparkle
Accelerated Sparkle - Lightweight Authenticated Encryption &amp; Hashing

## Overview

After implementing `ascon`, `tinyjambu` & `xoodyak`, I've picked up `sparkle` --- another NIST Light Weight Cryptography ( LWC ) final round candidate, which offers following functions

- Esch{256, 384}: Lightweight, cryptographic secure Hash function, producing 256/ 384 -bit output digest, when provided with N -bytes input | N >= 0
- Schwaemm256-{128, 256}/ Schwaemm128-128/ Schwaemm192-192: Authenticated encryption with associated data ( AEAD ) scheme, which takes 128/ 192/ 256 -bit secret key, 128/ 192/ 256 -bit public message nonce, N -bytes associated data, M -bytes plain text | N, M >= 0 and computes M -bytes encrypted data along with 128/ 192/ 256 -bit authentication tag. During verified decryption step, one needs to provide secret key, public message nonce, authentication tag, associated data & encrypted bytes to decrypt routine, which produces equal many decrypted data bytes & boolean verification flag. Before consuming decrypted bytes, one **must** check presence of truth value in boolean verification flag. Note, that associated data is never encrypted.

> Sparkle AEAD schemes provide confidentiality for only plain text, though it provides integrity & authenticity for both plain text & associated data. Read Sparkle [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf) for better understanding.

In this repository, I'm keeping one zero-dependency, header-only, easy-to-use C++ library, implementing Sparkle Hash & AEAD specification, while using C++20 features ( note for compilation step ). Using it's as easy as including header files in your C++ project. I've also kept C-ABI compliant wrapper functions, which can be interfaces from other languages such as Python, Rust ( using FFI; [more](https://en.wikipedia.org/wiki/Foreign_function_interface) ).

> Learn more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> If interested in my work on Ascon, [see](https://github.com/itzmeanjan/ascon)

> If interested in my work on TinyJambu, [see](https://github.com/itzmeanjan/tinyjambu)


> If interested in my work on Xoodyak, [see](https://github.com/itzmeanjan/xoodyak)

While writing this implementation, I followed [this](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf) specification, which was submitted to NIST LWC, see [here](https://csrc.nist.gov/projects/lightweight-cryptography/finalists).

# Prerequisites

- C++ compiler like `g++`/ `clang++`, with C++20 standard library support

> I'm using

```bash
$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0
```

- System development utilities such as `make`/ `cmake`

> I'm using

```bash
$ make --version
GNU Make 4.3

$ cmake --version
cmake version 3.22.1
```

- For testing functional correctness of Sparkle Hash & AEAD schemes, you'll need to have `wget`, `unzip`, `python3`.

- For installing `python3` dependencies, issue

```bash
python3 -m pip install -r wrapper/python/requirements.txt --user
```

- For benchmarking Sparkle Hash & AEAD implementations on CPU, you'll need `google-benchmark` library globally installed; see [here](https://github.com/google/benchmark/tree/60b16f1#installation)

## Testing

For ensuring functional correctness & compatibility with Sparkle specification, I excute Sparkle Hash & AEAD functions on input provided with NIST LWC submission package of Sparkle & check computed results against provided ones.

Issue following command to test

```bash
make
```

## Benchmarking

For benchmarking Sparkle Hash & AEAD functions on CPU, I'm using `google-benchmark` library; issue

```bash
make benchmark
```

> If you've CPU scaling enabled, you may want to disable that; see [this](https://github.com/google/benchmark/blob/60b16f11a30146ac825b7d99be0b9887c24b254a/docs/user_guide.md#disabling-cpu-frequency-scaling) guide

### On ARM Cortex-A72

```bash
2022-05-23T03:05:31+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.08, 0.02, 0.01
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                        881 ns          881 ns       794249 bytes_per_second=69.2735M/s
esch256_hash/128                      1513 ns         1513 ns       462588 bytes_per_second=80.6717M/s
esch256_hash/256                      2763 ns         2763 ns       253372 bytes_per_second=88.3704M/s
esch256_hash/512                      5262 ns         5262 ns       133023 bytes_per_second=92.7964M/s
esch256_hash/1024                    10260 ns        10260 ns        68224 bytes_per_second=95.181M/s
esch256_hash/2048                    20257 ns        20257 ns        34556 bytes_per_second=96.4171M/s
esch256_hash/4096                    40251 ns        40250 ns        17391 bytes_per_second=97.0488M/s
esch384_hash/64                       2616 ns         2616 ns       267140 bytes_per_second=23.33M/s
esch384_hash/128                      4213 ns         4213 ns       166156 bytes_per_second=28.9722M/s
esch384_hash/256                      7404 ns         7404 ns        94532 bytes_per_second=32.9731M/s
esch384_hash/512                     13788 ns        13788 ns        50769 bytes_per_second=35.414M/s
esch384_hash/1024                    26558 ns        26558 ns        26358 bytes_per_second=36.7715M/s
esch384_hash/2048                    52092 ns        52092 ns        13437 bytes_per_second=37.4941M/s
esch384_hash/4096                   103175 ns       103174 ns         6784 bytes_per_second=37.8607M/s
schwaemm256_128_encrypt/64/32         1218 ns         1218 ns       574663 bytes_per_second=75.1652M/s
schwaemm256_128_decrypt/64/32         1211 ns         1211 ns       577705 bytes_per_second=75.5946M/s
schwaemm256_128_encrypt/128/32        1667 ns         1667 ns       419746 bytes_per_second=91.5324M/s
schwaemm256_128_decrypt/128/32        1658 ns         1658 ns       422066 bytes_per_second=92.0044M/s
schwaemm256_128_encrypt/256/32        2574 ns         2574 ns       271901 bytes_per_second=106.691M/s
schwaemm256_128_decrypt/256/32        2564 ns         2563 ns       273069 bytes_per_second=107.143M/s
schwaemm256_128_encrypt/512/32        4371 ns         4371 ns       160140 bytes_per_second=118.687M/s
schwaemm256_128_decrypt/512/32        4357 ns         4357 ns       160667 bytes_per_second=119.081M/s
schwaemm256_128_encrypt/1024/32       7964 ns         7964 ns        87902 bytes_per_second=126.455M/s
schwaemm256_128_decrypt/1024/32       7941 ns         7941 ns        88141 bytes_per_second=126.815M/s
schwaemm256_128_encrypt/2048/32      15151 ns        15151 ns        46201 bytes_per_second=130.927M/s
schwaemm256_128_decrypt/2048/32      15113 ns        15112 ns        46317 bytes_per_second=131.259M/s
schwaemm256_128_encrypt/4096/32      29526 ns        29525 ns        23709 bytes_per_second=133.335M/s
schwaemm256_128_decrypt/4096/32      29503 ns        29503 ns        23721 bytes_per_second=133.438M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-05-23T07:06:57+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.68, 2.07, 1.95
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                        939 ns          938 ns       716736 bytes_per_second=65.0594M/s
esch256_hash/128                      1612 ns         1609 ns       430621 bytes_per_second=75.8489M/s
esch256_hash/256                      2951 ns         2948 ns       237012 bytes_per_second=82.8129M/s
esch256_hash/512                      5887 ns         5835 ns       119603 bytes_per_second=83.6799M/s
esch256_hash/1024                    10983 ns        10973 ns        60503 bytes_per_second=88.997M/s
esch256_hash/2048                    21654 ns        21638 ns        31526 bytes_per_second=90.2653M/s
esch256_hash/4096                    43045 ns        43017 ns        16231 bytes_per_second=90.808M/s
esch384_hash/64                       1245 ns         1244 ns       550414 bytes_per_second=49.0605M/s
esch384_hash/128                      2156 ns         2154 ns       344637 bytes_per_second=56.6727M/s
esch384_hash/256                      3705 ns         3703 ns       187342 bytes_per_second=65.9374M/s
esch384_hash/512                      6749 ns         6746 ns       101830 bytes_per_second=72.3803M/s
esch384_hash/1024                    12936 ns        12925 ns        51548 bytes_per_second=75.5564M/s
esch384_hash/2048                    25143 ns        25134 ns        27553 bytes_per_second=77.7088M/s
esch384_hash/4096                    49900 ns        49866 ns        13268 bytes_per_second=78.3347M/s
schwaemm256_128_encrypt/64/32          998 ns          995 ns       703122 bytes_per_second=92.0351M/s
schwaemm256_128_decrypt/64/32          972 ns          971 ns       711512 bytes_per_second=94.2929M/s
schwaemm256_128_encrypt/128/32        1328 ns         1327 ns       518311 bytes_per_second=114.983M/s
schwaemm256_128_decrypt/128/32        1320 ns         1320 ns       510975 bytes_per_second=115.623M/s
schwaemm256_128_encrypt/256/32        2028 ns         2026 ns       340442 bytes_per_second=135.564M/s
schwaemm256_128_decrypt/256/32        2025 ns         2024 ns       342016 bytes_per_second=135.728M/s
schwaemm256_128_encrypt/512/32        3439 ns         3436 ns       203302 bytes_per_second=150.979M/s
schwaemm256_128_decrypt/512/32        3424 ns         3423 ns       203513 bytes_per_second=151.564M/s
schwaemm256_128_encrypt/1024/32       6344 ns         6340 ns       107744 bytes_per_second=158.836M/s
schwaemm256_128_decrypt/1024/32       6265 ns         6257 ns       109472 bytes_per_second=160.962M/s
schwaemm256_128_encrypt/2048/32      11881 ns        11873 ns        57751 bytes_per_second=167.074M/s
schwaemm256_128_decrypt/2048/32      11859 ns        11852 ns        57528 bytes_per_second=167.374M/s
schwaemm256_128_encrypt/4096/32      23032 ns        23022 ns        29890 bytes_per_second=171.002M/s
schwaemm256_128_decrypt/4096/32      23331 ns        23313 ns        29942 bytes_per_second=168.864M/s
```
