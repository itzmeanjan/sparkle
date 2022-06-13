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
2022-05-30T08:10:37+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.26, 0.06, 0.02
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                        879 ns          879 ns       795737 bytes_per_second=69.4144M/s
esch256_hash/128                      1488 ns         1488 ns       470564 bytes_per_second=82.0623M/s
esch256_hash/256                      2688 ns         2688 ns       260385 bytes_per_second=90.8156M/s
esch256_hash/512                      5090 ns         5090 ns       137520 bytes_per_second=95.9291M/s
esch256_hash/1024                     9893 ns         9893 ns        70752 bytes_per_second=98.7122M/s
esch256_hash/2048                    19500 ns        19500 ns        35897 bytes_per_second=100.163M/s
esch256_hash/4096                    38713 ns        38713 ns        18082 bytes_per_second=100.904M/s
esch384_hash/64                       2587 ns         2587 ns       271018 bytes_per_second=23.5962M/s
esch384_hash/128                      4132 ns         4132 ns       169352 bytes_per_second=29.5404M/s
esch384_hash/256                      7241 ns         7241 ns        96679 bytes_per_second=33.7153M/s
esch384_hash/512                     13460 ns        13460 ns        52010 bytes_per_second=36.2773M/s
esch384_hash/1024                    25898 ns        25897 ns        27030 bytes_per_second=37.7094M/s
esch384_hash/2048                    50763 ns        50763 ns        13788 bytes_per_second=38.4754M/s
esch384_hash/4096                   100503 ns       100499 ns         6965 bytes_per_second=38.8686M/s
schwaemm256_128_encrypt/64/32         1120 ns         1120 ns       625034 bytes_per_second=81.7501M/s
schwaemm256_128_decrypt/64/32         1147 ns         1147 ns       610513 bytes_per_second=79.8481M/s
schwaemm256_128_encrypt/128/32        1519 ns         1519 ns       460700 bytes_per_second=100.43M/s
schwaemm256_128_decrypt/128/32        1545 ns         1545 ns       453014 bytes_per_second=98.7519M/s
schwaemm256_128_encrypt/256/32        2327 ns         2327 ns       299629 bytes_per_second=118.041M/s
schwaemm256_128_decrypt/256/32        2350 ns         2350 ns       297862 bytes_per_second=116.872M/s
schwaemm256_128_encrypt/512/32        3923 ns         3923 ns       178431 bytes_per_second=132.238M/s
schwaemm256_128_decrypt/512/32        3944 ns         3944 ns       177469 bytes_per_second=131.529M/s
schwaemm256_128_encrypt/1024/32       7118 ns         7118 ns        98328 bytes_per_second=141.477M/s
schwaemm256_128_decrypt/1024/32       7133 ns         7133 ns        98132 bytes_per_second=141.19M/s
schwaemm256_128_encrypt/2048/32      13510 ns        13509 ns        51816 bytes_per_second=146.835M/s
schwaemm256_128_decrypt/2048/32      13511 ns        13510 ns        51812 bytes_per_second=146.826M/s
schwaemm256_128_encrypt/4096/32      26292 ns        26291 ns        26625 bytes_per_second=149.737M/s
schwaemm256_128_decrypt/4096/32      26276 ns        26275 ns        26641 bytes_per_second=149.827M/s
schwaemm192_192_encrypt/64/32         1495 ns         1495 ns       468214 bytes_per_second=61.24M/s
schwaemm192_192_decrypt/64/32         1554 ns         1554 ns       450350 bytes_per_second=58.9061M/s
schwaemm192_192_encrypt/128/32        2071 ns         2071 ns       335520 bytes_per_second=73.6829M/s
schwaemm192_192_decrypt/128/32        2121 ns         2121 ns       327122 bytes_per_second=71.9501M/s
schwaemm192_192_encrypt/256/32        3014 ns         3014 ns       232225 bytes_per_second=91.1157M/s
schwaemm192_192_decrypt/256/32        3074 ns         3074 ns       227747 bytes_per_second=89.3623M/s
schwaemm192_192_encrypt/512/32        5090 ns         5090 ns       137502 bytes_per_second=101.922M/s
schwaemm192_192_decrypt/512/32        5150 ns         5149 ns       135903 bytes_per_second=100.749M/s
schwaemm192_192_encrypt/1024/32       9057 ns         9057 ns        77285 bytes_per_second=111.194M/s
schwaemm192_192_decrypt/1024/32       9116 ns         9116 ns        76786 bytes_per_second=110.472M/s
schwaemm192_192_encrypt/2048/32      17176 ns        17176 ns        40754 bytes_per_second=115.49M/s
schwaemm192_192_decrypt/2048/32      17235 ns        17235 ns        40614 bytes_per_second=115.093M/s
schwaemm192_192_encrypt/4096/32      33229 ns        33229 ns        21066 bytes_per_second=118.475M/s
schwaemm192_192_decrypt/4096/32      33298 ns        33298 ns        21018 bytes_per_second=118.228M/s
schwaemm128_128_encrypt/64/32         1127 ns         1127 ns       620875 bytes_per_second=81.2045M/s
schwaemm128_128_decrypt/64/32         1134 ns         1134 ns       617326 bytes_per_second=80.7393M/s
schwaemm128_128_encrypt/128/32        1678 ns         1678 ns       417056 bytes_per_second=90.9174M/s
schwaemm128_128_decrypt/128/32        1667 ns         1667 ns       419818 bytes_per_second=91.5156M/s
schwaemm128_128_encrypt/256/32        2765 ns         2764 ns       253231 bytes_per_second=99.3551M/s
schwaemm128_128_decrypt/256/32        2719 ns         2719 ns       257486 bytes_per_second=101.026M/s
schwaemm128_128_encrypt/512/32        4936 ns         4936 ns       141816 bytes_per_second=105.105M/s
schwaemm128_128_decrypt/512/32        4821 ns         4821 ns       145197 bytes_per_second=107.61M/s
schwaemm128_128_encrypt/1024/32       9281 ns         9281 ns        75422 bytes_per_second=108.513M/s
schwaemm128_128_decrypt/1024/32       9026 ns         9026 ns        77542 bytes_per_second=111.575M/s
schwaemm128_128_encrypt/2048/32      17969 ns        17969 ns        38955 bytes_per_second=110.393M/s
schwaemm128_128_decrypt/2048/32      17436 ns        17436 ns        40146 bytes_per_second=113.766M/s
schwaemm128_128_encrypt/4096/32      35347 ns        35346 ns        19804 bytes_per_second=111.377M/s
schwaemm128_128_decrypt/4096/32      34268 ns        34268 ns        20427 bytes_per_second=114.882M/s
schwaemm256_256_encrypt/64/32         2295 ns         2295 ns       305004 bytes_per_second=39.8946M/s
schwaemm256_256_decrypt/64/32         2371 ns         2371 ns       295050 bytes_per_second=38.6162M/s
schwaemm256_256_encrypt/128/32        3115 ns         3115 ns       225002 bytes_per_second=48.9783M/s
schwaemm256_256_decrypt/128/32        3221 ns         3221 ns       217152 bytes_per_second=47.3688M/s
schwaemm256_256_encrypt/256/32        4734 ns         4734 ns       147934 bytes_per_second=58.0167M/s
schwaemm256_256_decrypt/256/32        4915 ns         4915 ns       142568 bytes_per_second=55.8786M/s
schwaemm256_256_encrypt/512/32        7979 ns         7979 ns        87756 bytes_per_second=65.0199M/s
schwaemm256_256_decrypt/512/32        8295 ns         8295 ns        84383 bytes_per_second=62.5439M/s
schwaemm256_256_encrypt/1024/32      14455 ns        14455 ns        48433 bytes_per_second=69.6691M/s
schwaemm256_256_decrypt/1024/32      15049 ns        15049 ns        46514 bytes_per_second=66.9196M/s
schwaemm256_256_encrypt/2048/32      27429 ns        27429 ns        25526 bytes_per_second=72.3199M/s
schwaemm256_256_decrypt/2048/32      28570 ns        28569 ns        24503 bytes_per_second=69.4329M/s
schwaemm256_256_encrypt/4096/32      53352 ns        53352 ns        13120 bytes_per_second=73.7892M/s
schwaemm256_256_decrypt/4096/32      55628 ns        55627 ns        12583 bytes_per_second=70.7712M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-05-30T11:47:55+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.86, 2.21, 2.21
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                        976 ns          973 ns       673453 bytes_per_second=62.7573M/s
esch256_hash/128                      1916 ns         1709 ns       433864 bytes_per_second=71.4076M/s
esch256_hash/256                      3003 ns         2990 ns       235881 bytes_per_second=81.6467M/s
esch256_hash/512                      6269 ns         5945 ns       121099 bytes_per_second=82.1263M/s
esch256_hash/1024                    11746 ns        11649 ns        58407 bytes_per_second=83.8289M/s
esch256_hash/2048                    23122 ns        22919 ns        30301 bytes_per_second=85.2189M/s
esch256_hash/4096                    48235 ns        47647 ns        15792 bytes_per_second=81.9836M/s
esch384_hash/64                       1282 ns         1278 ns       535537 bytes_per_second=47.7524M/s
esch384_hash/128                      2228 ns         2205 ns       317092 bytes_per_second=55.3636M/s
esch384_hash/256                      3915 ns         3873 ns       188784 bytes_per_second=63.039M/s
esch384_hash/512                      7104 ns         7035 ns       103762 bytes_per_second=69.411M/s
esch384_hash/1024                    13174 ns        13121 ns        50675 bytes_per_second=74.4262M/s
esch384_hash/2048                    27419 ns        27090 ns        26228 bytes_per_second=72.0967M/s
esch384_hash/4096                    52529 ns        52223 ns        12809 bytes_per_second=74.7998M/s
schwaemm256_128_encrypt/64/32         1026 ns         1016 ns       703843 bytes_per_second=90.0907M/s
schwaemm256_128_decrypt/64/32         1010 ns         1004 ns       660764 bytes_per_second=91.1863M/s
schwaemm256_128_encrypt/128/32        1468 ns         1413 ns       491853 bytes_per_second=107.973M/s
schwaemm256_128_decrypt/128/32        1395 ns         1381 ns       517556 bytes_per_second=110.506M/s
schwaemm256_128_encrypt/256/32        2143 ns         2121 ns       306018 bytes_per_second=129.499M/s
schwaemm256_128_decrypt/256/32        2034 ns         2026 ns       327564 bytes_per_second=135.551M/s
schwaemm256_128_encrypt/512/32        3488 ns         3472 ns       205165 bytes_per_second=149.429M/s
schwaemm256_128_decrypt/512/32        3577 ns         3535 ns       193651 bytes_per_second=146.765M/s
schwaemm256_128_encrypt/1024/32       6207 ns         6188 ns       111231 bytes_per_second=162.734M/s
schwaemm256_128_decrypt/1024/32       6374 ns         6306 ns       107176 bytes_per_second=159.692M/s
schwaemm256_128_encrypt/2048/32      12223 ns        12115 ns        57263 bytes_per_second=163.731M/s
schwaemm256_128_decrypt/2048/32      11490 ns        11451 ns        59898 bytes_per_second=173.232M/s
schwaemm256_128_encrypt/4096/32      23329 ns        23227 ns        28865 bytes_per_second=169.489M/s
schwaemm256_128_decrypt/4096/32      22630 ns        22582 ns        30772 bytes_per_second=174.329M/s
schwaemm192_192_encrypt/64/32         1355 ns         1352 ns       509269 bytes_per_second=67.7147M/s
schwaemm192_192_decrypt/64/32         1352 ns         1348 ns       515111 bytes_per_second=67.8931M/s
schwaemm192_192_encrypt/128/32        2046 ns         2021 ns       369082 bytes_per_second=75.515M/s
schwaemm192_192_decrypt/128/32        2063 ns         2028 ns       360758 bytes_per_second=75.2323M/s
schwaemm192_192_encrypt/256/32        2769 ns         2762 ns       250239 bytes_per_second=99.4353M/s
schwaemm192_192_decrypt/256/32        2714 ns         2710 ns       257102 bytes_per_second=101.342M/s
schwaemm192_192_encrypt/512/32        5248 ns         5193 ns       100000 bytes_per_second=99.8998M/s
schwaemm192_192_decrypt/512/32        5004 ns         4948 ns       111025 bytes_per_second=104.855M/s
schwaemm192_192_encrypt/1024/32       8340 ns         8335 ns        79186 bytes_per_second=120.826M/s
schwaemm192_192_decrypt/1024/32       8240 ns         8225 ns        83401 bytes_per_second=122.437M/s
schwaemm192_192_encrypt/2048/32      16242 ns        16212 ns        42986 bytes_per_second=122.354M/s
schwaemm192_192_decrypt/2048/32      15870 ns        15839 ns        43615 bytes_per_second=125.235M/s
schwaemm192_192_encrypt/4096/32      33149 ns        31301 ns        22707 bytes_per_second=125.772M/s
schwaemm192_192_decrypt/4096/32      30205 ns        30124 ns        23063 bytes_per_second=130.684M/s
schwaemm128_128_encrypt/64/32          697 ns          696 ns       944071 bytes_per_second=131.483M/s
schwaemm128_128_decrypt/64/32          695 ns          694 ns       990744 bytes_per_second=132.006M/s
schwaemm128_128_encrypt/128/32         985 ns          984 ns       689546 bytes_per_second=155.124M/s
schwaemm128_128_decrypt/128/32         974 ns          972 ns       708144 bytes_per_second=156.967M/s
schwaemm128_128_encrypt/256/32        1558 ns         1557 ns       445712 bytes_per_second=176.388M/s
schwaemm128_128_decrypt/256/32        1610 ns         1599 ns       399054 bytes_per_second=171.774M/s
schwaemm128_128_encrypt/512/32        2714 ns         2710 ns       254258 bytes_per_second=191.445M/s
schwaemm128_128_decrypt/512/32        2674 ns         2673 ns       260062 bytes_per_second=194.12M/s
schwaemm128_128_encrypt/1024/32       5005 ns         4998 ns       134613 bytes_per_second=201.479M/s
schwaemm128_128_decrypt/1024/32       4941 ns         4938 ns       135885 bytes_per_second=203.958M/s
schwaemm128_128_encrypt/2048/32       9647 ns         9622 ns        71580 bytes_per_second=206.158M/s
schwaemm128_128_decrypt/2048/32       9511 ns         9498 ns        72574 bytes_per_second=208.85M/s
schwaemm128_128_encrypt/4096/32      18675 ns        18661 ns        36524 bytes_per_second=210.958M/s
schwaemm128_128_decrypt/4096/32      18713 ns        18685 ns        36764 bytes_per_second=210.688M/s
schwaemm256_256_encrypt/64/32         1077 ns         1076 ns       646138 bytes_per_second=85.1143M/s
schwaemm256_256_decrypt/64/32         1084 ns         1083 ns       628530 bytes_per_second=84.5404M/s
schwaemm256_256_encrypt/128/32        1469 ns         1466 ns       472973 bytes_per_second=104.049M/s
schwaemm256_256_decrypt/128/32        1478 ns         1476 ns       466107 bytes_per_second=103.355M/s
schwaemm256_256_encrypt/256/32        2260 ns         2258 ns       310427 bytes_per_second=121.611M/s
schwaemm256_256_decrypt/256/32        2253 ns         2250 ns       307887 bytes_per_second=122.047M/s
schwaemm256_256_encrypt/512/32        3815 ns         3811 ns       183769 bytes_per_second=136.136M/s
schwaemm256_256_decrypt/512/32        3814 ns         3811 ns       184620 bytes_per_second=136.145M/s
schwaemm256_256_encrypt/1024/32       6911 ns         6906 ns        95233 bytes_per_second=145.832M/s
schwaemm256_256_decrypt/1024/32       6877 ns         6873 ns        98464 bytes_per_second=146.529M/s
schwaemm256_256_encrypt/2048/32      13371 ns        13358 ns        52871 bytes_per_second=148.494M/s
schwaemm256_256_decrypt/2048/32      13063 ns        13053 ns        52986 bytes_per_second=151.972M/s
schwaemm256_256_encrypt/4096/32      25616 ns        25599 ns        27289 bytes_per_second=153.784M/s
schwaemm256_256_decrypt/4096/32      25325 ns        25310 ns        27221 bytes_per_second=155.543M/s
```

## Usage

Using Sparkle C++ API is as easy as including proper header files & letting compiler know where it can find these header files, which is `./include` directory.

If you're interested in

- Esch256 Hash, import `./include/esch256.hpp`
- Esch384 Hash, import `./include/esch384.hpp`
- Schwaemm128-128 AEAD, import `./include/schwaemm128_128.hpp`
- Schwaemm192-192 AEAD, import `./include/schwaemm192_192.hpp`
- Schwaemm256-128 AEAD, import `./include/schwaemm256_128.hpp`
- Schwaemm256-256 AEAD, import `./include/schwaemm256_256.hpp`

I'm maintaining following examples for practically demonstrating usage of Sparkle C++ API.

- For Esch{256, 384} Hash, see [here](https://github.com/itzmeanjan/sparkle/blob/96c33f8/example/hash.cpp)
- For Schwaemm{128, 192, 256}-{128, 192, 256} AEAD, see [here](https://github.com/itzmeanjan/sparkle/blob/96c33f8/example/aead.cpp)
