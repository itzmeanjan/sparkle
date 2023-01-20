# sparkle
Accelerated Sparkle - Lightweight Authenticated Encryption &amp; Hashing

## Overview

After implementing `ascon`, `tinyjambu` & `xoodyak`, I've picked up `sparkle` --- another NIST Light Weight Cryptography ( LWC ) final round candidate, which offers following functions

Functionality | What does it offer ?
:-- | --:
Esch{256, 384} | Lightweight, cryptographic secure Hash function, producing 256/ 384 -bit output digest, when provided with N -bytes input s.t. N >= 0
Schwaemm256-{128, 256}/ Schwaemm128-128/ Schwaemm192-192 | Authenticated encryption with associated data ( AEAD ) scheme, which takes 128/ 192/ 256 -bit secret key, 128/ 192/ 256 -bit public message nonce, N -bytes associated data, M -bytes plain text s.t. N, M >= 0 and computes M -bytes encrypted data along with 128/ 192/ 256 -bit authentication tag. During verified decryption step, one needs to provide secret key, public message nonce, authentication tag, associated data & encrypted bytes to decrypt routine, which produces equal many decrypted data bytes & boolean verification flag. **If tag verification fails during decryption, no unverified plain text is released**.

> **Warning** Sparkle AEAD schemes provide confidentiality only for plain text, though it provides integrity & authenticity for both plain text & associated data. Read Sparkle [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf) for better understanding.

In this repository, I'm maintaining one zero-dependency, header-only, easy-to-use C++ library, implementing Sparkle Hash & AEAD specification, while using C++20 features ( note this when you're compiling your project ). Using it is as easy as including proper header files ( generally [esch.hpp](./include/esch.hpp) or [schwaemm.hpp](./include/schwaemm.hpp) ) in your C++ project and letting compiler know where it can find these headers. I've also kept C-ABI compliant wrapper functions, which can be interfaced from other languages such as Python, Rust ( using FFI; [more](https://en.wikipedia.org/wiki/Foreign_function_interface) ).

> **Note** Learn more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> **Note** If interested in my work on other NIST LWC finalists such as

- Ascon, [see](https://github.com/itzmeanjan/ascon)
- TinyJambu, [see](https://github.com/itzmeanjan/tinyjambu)
- Xoodyak, [see](https://github.com/itzmeanjan/xoodyak)

While writing this implementation of Sparkle, I followed [this](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf) specification, which was submitted to NIST LWC, see [here](https://csrc.nist.gov/projects/lightweight-cryptography/finalists).

## Prerequisites

- C++ compiler like `g++`/ `clang++`, with C++20 standard library support

```bash
$ g++ --version
g++ (Homebrew GCC 12.2.0) 12.2.0

$ clang++ --version
Apple clang version 14.0.0 (clang-1400.0.29.202)
```

- System development utilities such as `make`, `cmake`, `git`, `unzip`, `wget` and `python3`

```bash
$ make --version
GNU Make 3.81

$ cmake --version
cmake version 3.25.1

$ git --version
git version 2.39.1

$ unzip -v
UnZip 6.00 of 20 April 2009, by Info-ZIP

$ wget --version
GNU Wget 1.21.3 built on darwin22.1.0

$ python3 --version
Python 3.10.9
```

- For installing `python3` dependencies, issue

```bash
# ensure you've pip
python3 -m pip install -r wrapper/python/requirements.txt --user

# On Ubuntu you may, if pip is not available
sudo apt-get install python3-pip
```

- For benchmarking Sparkle Hash & AEAD implementations on CPU, you'll need `google-benchmark` library globally installed; follow [this](https://github.com/google/benchmark/tree/60b16f1#installation) document.

## Testing

For ensuring functional correctness & compatibility with Sparkle specification, I excute Sparkle Hash & AEAD functions on test vectors ( KATs ) provided with NIST LWC submission package of Sparkle & check computed results against provided ones.

Issue following command to test

```bash
make
```

## Benchmarking

For benchmarking Sparkle Hash & AEAD functions on CPU, I'm using `google-benchmark` library; issue

```bash
make benchmark
```

> **Warning** If you've CPU scaling enabled, you may want to disable that; see [this](https://github.com/google/benchmark/blob/60b16f11a30146ac825b7d99be0b9887c24b254a/docs/user_guide.md#disabling-cpu-frequency-scaling) guide

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz ( compiled using Clang )

```bash
2023-01-20T12:29:38+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.33, 1.42, 1.53
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
bench_sparkle::sparkle<4, 7>          56.8 ns         56.8 ns     12045083 bytes_per_second=537.669M/s
bench_sparkle::sparkle<4, 10>         80.4 ns         80.4 ns      8572653 bytes_per_second=379.803M/s
bench_sparkle::sparkle<6, 7>           120 ns          120 ns      5667236 bytes_per_second=381.158M/s
bench_sparkle::sparkle<6, 11>          188 ns          188 ns      3683590 bytes_per_second=243.318M/s
bench_sparkle::sparkle<8, 8>           181 ns          181 ns      3833642 bytes_per_second=336.992M/s
bench_sparkle::sparkle<8, 12>          274 ns          274 ns      2555575 bytes_per_second=223.071M/s
esch256_hash/64                        693 ns          692 ns       979007 bytes_per_second=88.1581M/s
esch256_hash/128                      1183 ns         1182 ns       584434 bytes_per_second=103.314M/s
esch256_hash/256                      2207 ns         2205 ns       313259 bytes_per_second=110.719M/s
esch256_hash/512                      4208 ns         4190 ns       167479 bytes_per_second=116.529M/s
esch256_hash/1024                     8106 ns         8098 ns        82031 bytes_per_second=120.6M/s
esch256_hash/2048                    16029 ns        16006 ns        43802 bytes_per_second=122.024M/s
esch256_hash/4096                    31538 ns        31506 ns        22182 bytes_per_second=123.986M/s
esch384_hash/64                       1195 ns         1194 ns       565360 bytes_per_second=51.119M/s
esch384_hash/128                      1951 ns         1948 ns       360229 bytes_per_second=62.6669M/s
esch384_hash/256                      3443 ns         3440 ns       205665 bytes_per_second=70.9704M/s
esch384_hash/512                      6339 ns         6332 ns       108202 bytes_per_second=77.1115M/s
esch384_hash/1024                    12206 ns        12192 ns        56750 bytes_per_second=80.0994M/s
esch384_hash/2048                    23965 ns        23929 ns        28942 bytes_per_second=81.6202M/s
esch384_hash/4096                    47392 ns        47339 ns        14746 bytes_per_second=82.5159M/s
schwaemm256_128_encrypt/64/32          739 ns          736 ns       944058 bytes_per_second=124.41M/s
schwaemm256_128_decrypt/64/32          745 ns          744 ns       924996 bytes_per_second=123.063M/s
schwaemm256_128_encrypt/128/32        1012 ns         1011 ns       699196 bytes_per_second=150.913M/s
schwaemm256_128_decrypt/128/32        1077 ns         1077 ns       636856 bytes_per_second=141.721M/s
schwaemm256_128_encrypt/256/32        1492 ns         1491 ns       464878 bytes_per_second=184.197M/s
schwaemm256_128_decrypt/256/32        1517 ns         1516 ns       457681 bytes_per_second=181.167M/s
schwaemm256_128_encrypt/512/32        2535 ns         2533 ns       275825 bytes_per_second=204.788M/s
schwaemm256_128_decrypt/512/32        2535 ns         2532 ns       272598 bytes_per_second=204.86M/s
schwaemm256_128_encrypt/1024/32       4532 ns         4528 ns       154314 bytes_per_second=222.4M/s
schwaemm256_128_decrypt/1024/32       4601 ns         4596 ns       151337 bytes_per_second=219.126M/s
schwaemm256_128_encrypt/2048/32       8555 ns         8550 ns        79427 bytes_per_second=232.006M/s
schwaemm256_128_decrypt/2048/32       8734 ns         8726 ns        78770 bytes_per_second=227.338M/s
schwaemm256_128_encrypt/4096/32      16657 ns        16644 ns        41507 bytes_per_second=236.527M/s
schwaemm256_128_decrypt/4096/32      16910 ns        16898 ns        40713 bytes_per_second=232.967M/s
schwaemm192_192_encrypt/64/32          988 ns          988 ns       703397 bytes_per_second=92.7009M/s
schwaemm192_192_decrypt/64/32          994 ns          993 ns       696254 bytes_per_second=92.1954M/s
schwaemm192_192_encrypt/128/32        1378 ns         1377 ns       502556 bytes_per_second=110.802M/s
schwaemm192_192_decrypt/128/32        1389 ns         1388 ns       491680 bytes_per_second=109.905M/s
schwaemm192_192_encrypt/256/32        2021 ns         2019 ns       340792 bytes_per_second=136.015M/s
schwaemm192_192_decrypt/256/32        2031 ns         2029 ns       341537 bytes_per_second=135.365M/s
schwaemm192_192_encrypt/512/32        3461 ns         3458 ns       198437 bytes_per_second=150.026M/s
schwaemm192_192_decrypt/512/32        3452 ns         3448 ns       203055 bytes_per_second=150.464M/s
schwaemm192_192_encrypt/1024/32       6170 ns         6165 ns       111187 bytes_per_second=163.365M/s
schwaemm192_192_decrypt/1024/32       6179 ns         6171 ns       113269 bytes_per_second=163.192M/s
schwaemm192_192_encrypt/2048/32      11742 ns        11734 ns        59098 bytes_per_second=169.051M/s
schwaemm192_192_decrypt/2048/32      11638 ns        11632 ns        58482 bytes_per_second=170.535M/s
schwaemm192_192_encrypt/4096/32      22709 ns        22689 ns        30435 bytes_per_second=173.511M/s
schwaemm192_192_decrypt/4096/32      22625 ns        22608 ns        30917 bytes_per_second=174.134M/s
schwaemm128_128_encrypt/64/32          612 ns          612 ns      1108595 bytes_per_second=149.604M/s
schwaemm128_128_decrypt/64/32          595 ns          594 ns      1146507 bytes_per_second=154.076M/s
schwaemm128_128_encrypt/128/32         857 ns          856 ns       782936 bytes_per_second=178.211M/s
schwaemm128_128_decrypt/128/32         828 ns          827 ns       833552 bytes_per_second=184.454M/s
schwaemm128_128_encrypt/256/32        1353 ns         1352 ns       512138 bytes_per_second=203.193M/s
schwaemm128_128_decrypt/256/32        1323 ns         1322 ns       528605 bytes_per_second=207.786M/s
schwaemm128_128_encrypt/512/32        2344 ns         2341 ns       298139 bytes_per_second=221.633M/s
schwaemm128_128_decrypt/512/32        2266 ns         2264 ns       303380 bytes_per_second=229.112M/s
schwaemm128_128_encrypt/1024/32       4330 ns         4308 ns       159806 bytes_per_second=233.751M/s
schwaemm128_128_decrypt/1024/32       4175 ns         4170 ns       166537 bytes_per_second=241.493M/s
schwaemm128_128_encrypt/2048/32       8211 ns         8201 ns        82849 bytes_per_second=241.881M/s
schwaemm128_128_decrypt/2048/32       8022 ns         8013 ns        85426 bytes_per_second=247.55M/s
schwaemm128_128_encrypt/4096/32      16029 ns        16010 ns        42385 bytes_per_second=245.897M/s
schwaemm128_128_decrypt/4096/32      15724 ns        15701 ns        44363 bytes_per_second=250.728M/s
schwaemm256_256_encrypt/64/32         1035 ns         1034 ns       670440 bytes_per_second=88.5618M/s
schwaemm256_256_decrypt/64/32         1055 ns         1054 ns       643276 bytes_per_second=86.8737M/s
schwaemm256_256_encrypt/128/32        1409 ns         1407 ns       496817 bytes_per_second=108.443M/s
schwaemm256_256_decrypt/128/32        1443 ns         1436 ns       480443 bytes_per_second=106.286M/s
schwaemm256_256_encrypt/256/32        2162 ns         2160 ns       322889 bytes_per_second=127.144M/s
schwaemm256_256_decrypt/256/32        2175 ns         2174 ns       319302 bytes_per_second=126.359M/s
schwaemm256_256_encrypt/512/32        3656 ns         3651 ns       192493 bytes_per_second=142.105M/s
schwaemm256_256_decrypt/512/32        3662 ns         3658 ns       191939 bytes_per_second=141.821M/s
schwaemm256_256_encrypt/1024/32       6618 ns         6612 ns       102796 bytes_per_second=152.31M/s
schwaemm256_256_decrypt/1024/32       6717 ns         6705 ns       103986 bytes_per_second=150.196M/s
schwaemm256_256_encrypt/2048/32      12644 ns        12630 ns        54997 bytes_per_second=157.054M/s
schwaemm256_256_decrypt/2048/32      12607 ns        12593 ns        53943 bytes_per_second=157.521M/s
schwaemm256_256_encrypt/4096/32      24526 ns        24492 ns        28538 bytes_per_second=160.74M/s
schwaemm256_256_decrypt/4096/32      24752 ns        24706 ns        28401 bytes_per_second=159.342M/s
```

## Usage

Using Sparkle C++ API is as easy as including proper header files & letting compiler know where it can find these header files, which is `./include` directory.

If you're interested in

- Esch256 Hash, import `./include/esch256.hpp`
- Esch384 Hash, import `./include/esch384.hpp`

> Or just include `./include/esch.hpp` for Esch hashing

- Schwaemm128-128 AEAD, import `./include/schwaemm128_128.hpp`
- Schwaemm192-192 AEAD, import `./include/schwaemm192_192.hpp`
- Schwaemm256-128 AEAD, import `./include/schwaemm256_128.hpp`
- Schwaemm256-256 AEAD, import `./include/schwaemm256_256.hpp`

> Or just include `./include/schwaemm.hpp` for Schwaemm AEAD

I strongly advise you to go through following examples, where I demonstrate usage of Sparkle C++ API.

- For Esch{256, 384} Hash, see [here](./example/hash.cpp)
- For Schwaemm{128, 192, 256}-{128, 192, 256} AEAD, see [here](./example/aead.cpp)
