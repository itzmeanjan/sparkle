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
2022-05-27T06:22:02+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.62, 0.34, 0.13
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                        881 ns          881 ns       794284 bytes_per_second=69.2739M/s
esch256_hash/128                      1513 ns         1513 ns       462592 bytes_per_second=80.6682M/s
esch256_hash/256                      2763 ns         2763 ns       253373 bytes_per_second=88.3682M/s
esch256_hash/512                      5262 ns         5262 ns       133016 bytes_per_second=92.796M/s
esch256_hash/1024                    10260 ns        10260 ns        68226 bytes_per_second=95.1832M/s
esch256_hash/2048                    20257 ns        20257 ns        34553 bytes_per_second=96.4194M/s
esch256_hash/4096                    40250 ns        40250 ns        17391 bytes_per_second=97.0508M/s
esch384_hash/64                       2610 ns         2610 ns       268271 bytes_per_second=23.3881M/s
esch384_hash/128                      4198 ns         4198 ns       166739 bytes_per_second=29.08M/s
esch384_hash/256                      7377 ns         7377 ns        94903 bytes_per_second=33.0957M/s
esch384_hash/512                     13737 ns        13737 ns        50951 bytes_per_second=35.5456M/s
esch384_hash/1024                    26463 ns        26463 ns        26451 bytes_per_second=36.9027M/s
esch384_hash/2048                    51917 ns        51915 ns        13483 bytes_per_second=37.6218M/s
esch384_hash/4096                   102818 ns       102816 ns         6808 bytes_per_second=37.9925M/s
schwaemm256_128_encrypt/64/32         1219 ns         1219 ns       574333 bytes_per_second=75.1268M/s
schwaemm256_128_decrypt/64/32         1211 ns         1211 ns       578014 bytes_per_second=75.6014M/s
schwaemm256_128_encrypt/128/32        1668 ns         1668 ns       419637 bytes_per_second=91.4938M/s
schwaemm256_128_decrypt/128/32        1659 ns         1659 ns       421978 bytes_per_second=91.9898M/s
schwaemm256_128_encrypt/256/32        2575 ns         2575 ns       271801 bytes_per_second=106.653M/s
schwaemm256_128_decrypt/256/32        2564 ns         2564 ns       272968 bytes_per_second=107.112M/s
schwaemm256_128_encrypt/512/32        4372 ns         4372 ns       160105 bytes_per_second=118.656M/s
schwaemm256_128_decrypt/512/32        4357 ns         4357 ns       160671 bytes_per_second=119.084M/s
schwaemm256_128_encrypt/1024/32       7965 ns         7965 ns        87885 bytes_per_second=126.439M/s
schwaemm256_128_decrypt/1024/32       7943 ns         7942 ns        88133 bytes_per_second=126.799M/s
schwaemm256_128_encrypt/2048/32      15152 ns        15152 ns        46192 bytes_per_second=130.917M/s
schwaemm256_128_decrypt/2048/32      15132 ns        15132 ns        46264 bytes_per_second=131.092M/s
schwaemm256_128_encrypt/4096/32      29529 ns        29528 ns        23706 bytes_per_second=133.323M/s
schwaemm256_128_decrypt/4096/32      29455 ns        29453 ns        23767 bytes_per_second=133.661M/s
schwaemm192_192_encrypt/64/32         1492 ns         1492 ns       469185 bytes_per_second=61.3649M/s
schwaemm192_192_decrypt/64/32         1569 ns         1569 ns       445845 bytes_per_second=58.3449M/s
schwaemm192_192_encrypt/128/32        2041 ns         2041 ns       342887 bytes_per_second=74.7453M/s
schwaemm192_192_decrypt/128/32        2142 ns         2142 ns       326846 bytes_per_second=71.2445M/s
schwaemm192_192_encrypt/256/32        2967 ns         2967 ns       235905 bytes_per_second=92.5608M/s
schwaemm192_192_decrypt/256/32        3103 ns         3103 ns       225606 bytes_per_second=88.5175M/s
schwaemm192_192_encrypt/512/32        4986 ns         4986 ns       140390 bytes_per_second=104.047M/s
schwaemm192_192_decrypt/512/32        5201 ns         5200 ns       134607 bytes_per_second=99.7633M/s
schwaemm192_192_encrypt/1024/32       8843 ns         8843 ns        79158 bytes_per_second=113.886M/s
schwaemm192_192_decrypt/1024/32       9204 ns         9204 ns        76046 bytes_per_second=109.419M/s
schwaemm192_192_encrypt/2048/32      16738 ns        16737 ns        41820 bytes_per_second=118.515M/s
schwaemm192_192_decrypt/2048/32      17405 ns        17405 ns        40217 bytes_per_second=113.972M/s
schwaemm192_192_encrypt/4096/32      32348 ns        32348 ns        21640 bytes_per_second=121.702M/s
schwaemm192_192_decrypt/4096/32      33615 ns        33615 ns        20824 bytes_per_second=117.113M/s
schwaemm128_128_encrypt/64/32         1127 ns         1127 ns       620904 bytes_per_second=81.2091M/s
schwaemm128_128_decrypt/64/32         1135 ns         1135 ns       616643 bytes_per_second=80.6505M/s
schwaemm128_128_encrypt/128/32        1678 ns         1678 ns       417103 bytes_per_second=90.9229M/s
schwaemm128_128_decrypt/128/32        1669 ns         1669 ns       419498 bytes_per_second=91.446M/s
schwaemm128_128_encrypt/256/32        2764 ns         2764 ns       253219 bytes_per_second=99.3607M/s
schwaemm128_128_decrypt/256/32        2720 ns         2720 ns       257373 bytes_per_second=100.983M/s
schwaemm128_128_encrypt/512/32        4936 ns         4936 ns       141827 bytes_per_second=105.111M/s
schwaemm128_128_decrypt/512/32        4823 ns         4822 ns       145158 bytes_per_second=107.58M/s
schwaemm128_128_encrypt/1024/32       9281 ns         9280 ns        75429 bytes_per_second=108.519M/s
schwaemm128_128_decrypt/1024/32       9027 ns         9027 ns        77545 bytes_per_second=111.562M/s
schwaemm128_128_encrypt/2048/32      17969 ns        17968 ns        38958 bytes_per_second=110.396M/s
schwaemm128_128_decrypt/2048/32      17437 ns        17437 ns        40145 bytes_per_second=113.76M/s
schwaemm128_128_encrypt/4096/32      35346 ns        35345 ns        19806 bytes_per_second=111.382M/s
schwaemm128_128_decrypt/4096/32      34259 ns        34257 ns        20430 bytes_per_second=114.918M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-05-27T10:11:27+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.73, 2.54, 2.55
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                        992 ns          990 ns       692514 bytes_per_second=61.6207M/s
esch256_hash/128                      1730 ns         1723 ns       411830 bytes_per_second=70.8442M/s
esch256_hash/256                      3149 ns         3140 ns       225098 bytes_per_second=77.7551M/s
esch256_hash/512                      6037 ns         6009 ns       117853 bytes_per_second=81.2524M/s
esch256_hash/1024                    11964 ns        11905 ns        59393 bytes_per_second=82.0304M/s
esch256_hash/2048                    23526 ns        23415 ns        29018 bytes_per_second=83.4135M/s
esch256_hash/4096                    46541 ns        46429 ns        14996 bytes_per_second=84.1335M/s
esch384_hash/64                       1351 ns         1346 ns       521163 bytes_per_second=45.3583M/s
esch384_hash/128                      2175 ns         2166 ns       322887 bytes_per_second=56.3623M/s
esch384_hash/256                      3844 ns         3826 ns       183756 bytes_per_second=63.8155M/s
esch384_hash/512                      7159 ns         7130 ns        97508 bytes_per_second=68.4854M/s
esch384_hash/1024                    13746 ns        13691 ns        50634 bytes_per_second=71.3282M/s
esch384_hash/2048                    27007 ns        26899 ns        25732 bytes_per_second=72.6102M/s
esch384_hash/4096                    53726 ns        53523 ns        13182 bytes_per_second=72.9826M/s
schwaemm256_128_encrypt/64/32         1047 ns         1042 ns       674992 bytes_per_second=87.8223M/s
schwaemm256_128_decrypt/64/32         1053 ns         1047 ns       671624 bytes_per_second=87.4128M/s
schwaemm256_128_encrypt/128/32        1429 ns         1423 ns       492438 bytes_per_second=107.201M/s
schwaemm256_128_decrypt/128/32        1434 ns         1429 ns       492015 bytes_per_second=106.774M/s
schwaemm256_128_encrypt/256/32        2179 ns         2170 ns       319895 bytes_per_second=126.544M/s
schwaemm256_128_decrypt/256/32        2182 ns         2173 ns       320979 bytes_per_second=126.383M/s
schwaemm256_128_encrypt/512/32        3709 ns         3692 ns       192167 bytes_per_second=140.53M/s
schwaemm256_128_decrypt/512/32        3694 ns         3677 ns       188569 bytes_per_second=141.109M/s
schwaemm256_128_encrypt/1024/32       6652 ns         6634 ns       106922 bytes_per_second=151.803M/s
schwaemm256_128_decrypt/1024/32       6798 ns         6767 ns       104232 bytes_per_second=148.82M/s
schwaemm256_128_encrypt/2048/32      12874 ns        12809 ns        54467 bytes_per_second=154.859M/s
schwaemm256_128_decrypt/2048/32      12937 ns        12868 ns        54244 bytes_per_second=154.148M/s
schwaemm256_128_encrypt/4096/32      25089 ns        24973 ns        27831 bytes_per_second=157.642M/s
schwaemm256_128_decrypt/4096/32      24963 ns        24865 ns        27931 bytes_per_second=158.326M/s
schwaemm192_192_encrypt/64/32         1415 ns         1409 ns       497541 bytes_per_second=64.9908M/s
schwaemm192_192_decrypt/64/32         1412 ns         1407 ns       497293 bytes_per_second=65.078M/s
schwaemm192_192_encrypt/128/32        1979 ns         1968 ns       355011 bytes_per_second=77.5191M/s
schwaemm192_192_decrypt/128/32        1986 ns         1977 ns       356256 bytes_per_second=77.1994M/s
schwaemm192_192_encrypt/256/32        2934 ns         2917 ns       242843 bytes_per_second=94.1428M/s
schwaemm192_192_decrypt/256/32        2887 ns         2876 ns       242969 bytes_per_second=95.5117M/s
schwaemm192_192_encrypt/512/32        4964 ns         4941 ns       141144 bytes_per_second=105.009M/s
schwaemm192_192_decrypt/512/32        4786 ns         4778 ns       138694 bytes_per_second=108.57M/s
schwaemm192_192_encrypt/1024/32       8753 ns         8741 ns        79798 bytes_per_second=115.219M/s
schwaemm192_192_decrypt/1024/32       8618 ns         8588 ns        81978 bytes_per_second=117.259M/s
schwaemm192_192_encrypt/2048/32      16773 ns        16735 ns        41170 bytes_per_second=118.534M/s
schwaemm192_192_decrypt/2048/32      16523 ns        16436 ns        42380 bytes_per_second=120.691M/s
schwaemm192_192_encrypt/4096/32      32102 ns        32036 ns        21511 bytes_per_second=122.885M/s
schwaemm192_192_decrypt/4096/32      31871 ns        31789 ns        21853 bytes_per_second=123.839M/s
schwaemm128_128_encrypt/64/32          776 ns          771 ns       909800 bytes_per_second=118.793M/s
schwaemm128_128_decrypt/64/32          715 ns          714 ns       953847 bytes_per_second=128.259M/s
schwaemm128_128_encrypt/128/32        1033 ns         1032 ns       669856 bytes_per_second=147.916M/s
schwaemm128_128_decrypt/128/32        1012 ns         1010 ns       698882 bytes_per_second=151.073M/s
schwaemm128_128_encrypt/256/32        1658 ns         1653 ns       425276 bytes_per_second=166.191M/s
schwaemm128_128_decrypt/256/32        1636 ns         1629 ns       429206 bytes_per_second=168.563M/s
schwaemm128_128_encrypt/512/32        2839 ns         2828 ns       248414 bytes_per_second=183.473M/s
schwaemm128_128_decrypt/512/32        2796 ns         2793 ns       248462 bytes_per_second=185.741M/s
schwaemm128_128_encrypt/1024/32       5230 ns         5225 ns       130709 bytes_per_second=192.743M/s
schwaemm128_128_decrypt/1024/32       5152 ns         5144 ns       129735 bytes_per_second=195.77M/s
schwaemm128_128_encrypt/2048/32      10091 ns        10076 ns        69131 bytes_per_second=196.877M/s
schwaemm128_128_decrypt/2048/32      10010 ns         9994 ns        69599 bytes_per_second=198.492M/s
schwaemm128_128_encrypt/4096/32      20217 ns        20034 ns        34591 bytes_per_second=196.506M/s
schwaemm128_128_decrypt/4096/32      20409 ns        20148 ns        34599 bytes_per_second=195.395M/s
```
