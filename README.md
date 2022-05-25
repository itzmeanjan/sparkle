# sparkle
Accelerated Sparkle - Lightweight Authenticated Encryption &amp; Hashing

## Overview

After implementing `ascon`, `tinyjambu` & `xoodyak`, I've picked up `sparkle` --- another NIST Light Weight Cryptography ( LWC ) final round candidate, which offers following functions

- Esch{256, 384}: Lightweight, cryptographic secure Hash function, producing 256/ 384 -bit output digest, when provided with N -bytes input | N >= 0
- Schwaemm256-{128, 256}/ Schwaemm128-128/ Schwaemm192-192: Authenticated encryption with associated data ( AEAD ) scheme, which takes 128/ 192/ 256 -bit secret key, 128/ 192/ 256 -bit public message nonce, N -bytes associated data, M -bytes plain text | N, M >= 0 and computes M -bytes encrypted data along with 128/ 192/ 256 -bit authentication tag. During verified decryption step, one needs to provide secret key, public message nonce, authentication tag, associated data & encrypted bytes to decrypt routine, which produces equal many decrypted data bytes & boolean verification flag. Before consuming decrypted bytes, one **must** check presence of truth value in boolean verification flag. Note, that associated data is never encrypted.

> Sparkle AEAD schemes provide confidentiality only for plain text, though it provides integrity & authenticity for both plain text & associated data. Read Sparkle [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf) for better understanding.

In this repository, I'm keeping one zero-dependency, header-only, easy-to-use C++ library, implementing Sparkle Hash & AEAD specification, while using C++20 features ( note for compilation step ). Using it's as easy as including header files in your C++ project. I've also kept C-ABI compliant wrapper functions, which can be interfaced from other languages such as Python, Rust ( using FFI; [more](https://en.wikipedia.org/wiki/Foreign_function_interface) ).

> Learn more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> If interested in my work on Ascon, [see](https://github.com/itzmeanjan/ascon)

> If interested in my work on TinyJambu, [see](https://github.com/itzmeanjan/tinyjambu)


> If interested in my work on Xoodyak, [see](https://github.com/itzmeanjan/xoodyak)

While writing this implementation of Sparkle, I followed [this](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf) specification, which was submitted to NIST LWC, see [here](https://csrc.nist.gov/projects/lightweight-cryptography/finalists).

## Prerequisites

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

For ensuring functional correctness & compatibility with Sparkle specification, I excute Sparkle Hash & AEAD functions on Known Answer Tests ( KATs ) provided with NIST LWC submission package of Sparkle & check computed results against provided ones.

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
2022-05-25T05:19:03+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.15, 0.03, 0.01
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                        881 ns          881 ns       794001 bytes_per_second=69.2729M/s
esch256_hash/128                      1513 ns         1513 ns       462583 bytes_per_second=80.6699M/s
esch256_hash/256                      2763 ns         2763 ns       253369 bytes_per_second=88.3682M/s
esch256_hash/512                      5262 ns         5262 ns       133024 bytes_per_second=92.7974M/s
esch256_hash/1024                    10261 ns        10260 ns        68222 bytes_per_second=95.179M/s
esch256_hash/2048                    20257 ns        20257 ns        34557 bytes_per_second=96.4195M/s
esch256_hash/4096                    40250 ns        40250 ns        17391 bytes_per_second=97.049M/s
esch384_hash/64                       2622 ns         2622 ns       266982 bytes_per_second=23.2801M/s
esch384_hash/128                      4208 ns         4208 ns       166389 bytes_per_second=29.0099M/s
esch384_hash/256                      7387 ns         7387 ns        94752 bytes_per_second=33.0496M/s
esch384_hash/512                     13751 ns        13751 ns        50907 bytes_per_second=35.5098M/s
esch384_hash/1024                    26476 ns        26476 ns        26438 bytes_per_second=36.8848M/s
esch384_hash/2048                    51927 ns        51927 ns        13478 bytes_per_second=37.6129M/s
esch384_hash/4096                   102833 ns       102832 ns         6807 bytes_per_second=37.9868M/s
schwaemm256_128_encrypt/64/32         1217 ns         1217 ns       575040 bytes_per_second=75.2128M/s
schwaemm256_128_decrypt/64/32         1211 ns         1211 ns       578018 bytes_per_second=75.6004M/s
schwaemm256_128_encrypt/128/32        1667 ns         1667 ns       419937 bytes_per_second=91.5401M/s
schwaemm256_128_decrypt/128/32        1659 ns         1659 ns       421998 bytes_per_second=91.9782M/s
schwaemm256_128_encrypt/256/32        2574 ns         2574 ns       271968 bytes_per_second=106.713M/s
schwaemm256_128_decrypt/256/32        2564 ns         2564 ns       272961 bytes_per_second=107.105M/s
schwaemm256_128_encrypt/512/32        4371 ns         4371 ns       160151 bytes_per_second=118.7M/s
schwaemm256_128_decrypt/512/32        4357 ns         4357 ns       160657 bytes_per_second=119.071M/s
schwaemm256_128_encrypt/1024/32       7965 ns         7965 ns        87877 bytes_per_second=126.442M/s
schwaemm256_128_decrypt/1024/32       7942 ns         7942 ns        88125 bytes_per_second=126.797M/s
schwaemm256_128_encrypt/2048/32      15152 ns        15152 ns        46196 bytes_per_second=130.92M/s
schwaemm256_128_decrypt/2048/32      15114 ns        15114 ns        46315 bytes_per_second=131.249M/s
schwaemm256_128_encrypt/4096/32      29529 ns        29528 ns        23699 bytes_per_second=133.323M/s
schwaemm256_128_decrypt/4096/32      29457 ns        29456 ns        23763 bytes_per_second=133.648M/s
schwaemm192_192_encrypt/64/32         1602 ns         1602 ns       436916 bytes_per_second=57.1477M/s
schwaemm192_192_decrypt/64/32         1656 ns         1656 ns       422575 bytes_per_second=55.2699M/s
schwaemm192_192_encrypt/128/32        2238 ns         2238 ns       312715 bytes_per_second=68.1742M/s
schwaemm192_192_decrypt/128/32        2284 ns         2284 ns       306416 bytes_per_second=66.8003M/s
schwaemm192_192_encrypt/256/32        3296 ns         3296 ns       212353 bytes_per_second=83.3223M/s
schwaemm192_192_decrypt/256/32        3357 ns         3356 ns       208546 bytes_per_second=81.8307M/s
schwaemm192_192_encrypt/512/32        5606 ns         5606 ns       124843 bytes_per_second=92.5364M/s
schwaemm192_192_decrypt/512/32        5676 ns         5676 ns       123316 bytes_per_second=91.3981M/s
schwaemm192_192_encrypt/1024/32      10035 ns        10035 ns        69751 bytes_per_second=100.354M/s
schwaemm192_192_decrypt/1024/32      10123 ns        10123 ns        69145 bytes_per_second=99.482M/s
schwaemm192_192_encrypt/2048/32      19094 ns        19094 ns        36679 bytes_per_second=103.889M/s
schwaemm192_192_decrypt/2048/32      19211 ns        19211 ns        36437 bytes_per_second=103.257M/s
schwaemm192_192_encrypt/4096/32      37002 ns        37002 ns        18912 bytes_per_second=106.393M/s
schwaemm192_192_decrypt/4096/32      37192 ns        37191 ns        18822 bytes_per_second=105.852M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-05-25T09:14:50+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.44, 2.99, 3.07
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                       1023 ns         1019 ns       686773 bytes_per_second=59.8979M/s
esch256_hash/128                      1741 ns         1734 ns       398615 bytes_per_second=70.4087M/s
esch256_hash/256                      3170 ns         3159 ns       215057 bytes_per_second=77.2799M/s
esch256_hash/512                      6112 ns         6085 ns       113749 bytes_per_second=80.2416M/s
esch256_hash/1024                    11856 ns        11818 ns        58298 bytes_per_second=82.6355M/s
esch256_hash/2048                    23527 ns        23417 ns        30085 bytes_per_second=83.4066M/s
esch256_hash/4096                    46682 ns        46425 ns        14846 bytes_per_second=84.1418M/s
esch384_hash/64                       1363 ns         1356 ns       514827 bytes_per_second=45.0102M/s
esch384_hash/128                      2211 ns         2196 ns       321483 bytes_per_second=55.5943M/s
esch384_hash/256                      3853 ns         3831 ns       181496 bytes_per_second=63.7291M/s
esch384_hash/512                      7142 ns         7099 ns        97712 bytes_per_second=68.785M/s
esch384_hash/1024                    13771 ns        13692 ns        50575 bytes_per_second=71.3229M/s
esch384_hash/2048                    26988 ns        26840 ns        25878 bytes_per_second=72.7681M/s
esch384_hash/4096                    53581 ns        53324 ns        12812 bytes_per_second=73.2549M/s
schwaemm256_128_encrypt/64/32         1043 ns         1038 ns       658805 bytes_per_second=88.2212M/s
schwaemm256_128_decrypt/64/32         1054 ns         1048 ns       664546 bytes_per_second=87.3344M/s
schwaemm256_128_encrypt/128/32        1428 ns         1420 ns       487859 bytes_per_second=107.432M/s
schwaemm256_128_decrypt/128/32        1437 ns         1429 ns       484969 bytes_per_second=106.747M/s
schwaemm256_128_encrypt/256/32        2178 ns         2168 ns       320690 bytes_per_second=126.688M/s
schwaemm256_128_decrypt/256/32        2190 ns         2179 ns       320839 bytes_per_second=126.025M/s
schwaemm256_128_encrypt/512/32        3689 ns         3670 ns       189309 bytes_per_second=141.359M/s
schwaemm256_128_decrypt/512/32        3729 ns         3710 ns       189284 bytes_per_second=139.838M/s
schwaemm256_128_encrypt/1024/32       6770 ns         6739 ns       103161 bytes_per_second=149.431M/s
schwaemm256_128_decrypt/1024/32       6788 ns         6756 ns       100805 bytes_per_second=149.074M/s
schwaemm256_128_encrypt/2048/32      12880 ns        12820 ns        54377 bytes_per_second=154.73M/s
schwaemm256_128_decrypt/2048/32      12864 ns        12803 ns        54418 bytes_per_second=154.935M/s
schwaemm256_128_encrypt/4096/32      24974 ns        24854 ns        27887 bytes_per_second=158.399M/s
schwaemm256_128_decrypt/4096/32      24998 ns        24886 ns        28146 bytes_per_second=158.192M/s
schwaemm192_192_encrypt/64/32         1407 ns         1401 ns       493834 bytes_per_second=65.3657M/s
schwaemm192_192_decrypt/64/32         1419 ns         1413 ns       493702 bytes_per_second=64.8064M/s
schwaemm192_192_encrypt/128/32        1963 ns         1955 ns       356957 bytes_per_second=78.0656M/s
schwaemm192_192_decrypt/128/32        1979 ns         1969 ns       355279 bytes_per_second=77.4823M/s
schwaemm192_192_encrypt/256/32        2877 ns         2863 ns       242796 bytes_per_second=95.9467M/s
schwaemm192_192_decrypt/256/32        2899 ns         2886 ns       240556 bytes_per_second=95.1812M/s
schwaemm192_192_encrypt/512/32        4945 ns         4922 ns       142583 bytes_per_second=105.396M/s
schwaemm192_192_decrypt/512/32        4971 ns         4932 ns       135391 bytes_per_second=105.189M/s
schwaemm192_192_encrypt/1024/32       8963 ns         8908 ns        78629 bytes_per_second=113.057M/s
schwaemm192_192_decrypt/1024/32       8804 ns         8747 ns        76745 bytes_per_second=115.139M/s
schwaemm192_192_encrypt/2048/32      16962 ns        16834 ns        41582 bytes_per_second=117.838M/s
schwaemm192_192_decrypt/2048/32      16906 ns        16807 ns        41489 bytes_per_second=118.027M/s
schwaemm192_192_encrypt/4096/32      32459 ns        32306 ns        21397 bytes_per_second=121.858M/s
schwaemm192_192_decrypt/4096/32      33325 ns        33103 ns        21832 bytes_per_second=118.926M/s
```
