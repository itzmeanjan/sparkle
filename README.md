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
2022-05-28T12:49:22+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.30, 0.07, 0.02
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                        881 ns          881 ns       793925 bytes_per_second=69.2759M/s
esch256_hash/128                      1513 ns         1513 ns       462561 bytes_per_second=80.6669M/s
esch256_hash/256                      2763 ns         2763 ns       253359 bytes_per_second=88.3645M/s
esch256_hash/512                      5262 ns         5262 ns       133019 bytes_per_second=92.7978M/s
esch256_hash/1024                    10260 ns        10260 ns        68224 bytes_per_second=95.1813M/s
esch256_hash/2048                    20257 ns        20256 ns        34556 bytes_per_second=96.4201M/s
esch256_hash/4096                    40251 ns        40250 ns        17391 bytes_per_second=97.0487M/s
esch384_hash/64                       2612 ns         2612 ns       267763 bytes_per_second=23.37M/s
esch384_hash/128                      4204 ns         4204 ns       166514 bytes_per_second=29.0393M/s
esch384_hash/256                      7383 ns         7382 ns        94815 bytes_per_second=33.0704M/s
esch384_hash/512                     13749 ns        13749 ns        50917 bytes_per_second=35.515M/s
esch384_hash/1024                    26468 ns        26468 ns        26446 bytes_per_second=36.8956M/s
esch384_hash/2048                    51920 ns        51920 ns        13480 bytes_per_second=37.6179M/s
esch384_hash/4096                   102823 ns       102822 ns         6807 bytes_per_second=37.9903M/s
schwaemm256_128_encrypt/64/32         1189 ns         1189 ns       588654 bytes_per_second=76.9925M/s
schwaemm256_128_decrypt/64/32         1192 ns         1192 ns       587163 bytes_per_second=76.7918M/s
schwaemm256_128_encrypt/128/32        1634 ns         1634 ns       428609 bytes_per_second=93.4006M/s
schwaemm256_128_decrypt/128/32        1641 ns         1641 ns       426424 bytes_per_second=92.9614M/s
schwaemm256_128_encrypt/256/32        2522 ns         2522 ns       277575 bytes_per_second=108.915M/s
schwaemm256_128_decrypt/256/32        2551 ns         2551 ns       273686 bytes_per_second=107.666M/s
schwaemm256_128_encrypt/512/32        4290 ns         4290 ns       163165 bytes_per_second=120.931M/s
schwaemm256_128_decrypt/512/32        4350 ns         4350 ns       160927 bytes_per_second=119.271M/s
schwaemm256_128_encrypt/1024/32       7829 ns         7829 ns        89432 bytes_per_second=128.641M/s
schwaemm256_128_decrypt/1024/32       7953 ns         7953 ns        88014 bytes_per_second=126.633M/s
schwaemm256_128_encrypt/2048/32      14900 ns        14899 ns        46982 bytes_per_second=133.135M/s
schwaemm256_128_decrypt/2048/32      15161 ns        15161 ns        46172 bytes_per_second=130.843M/s
schwaemm256_128_encrypt/4096/32      29045 ns        29045 ns        24100 bytes_per_second=135.54M/s
schwaemm256_128_decrypt/4096/32      29569 ns        29569 ns        23674 bytes_per_second=133.139M/s
schwaemm192_192_encrypt/64/32         1495 ns         1495 ns       468089 bytes_per_second=61.2235M/s
schwaemm192_192_decrypt/64/32         1571 ns         1571 ns       445558 bytes_per_second=58.2635M/s
schwaemm192_192_encrypt/128/32        2071 ns         2071 ns       337916 bytes_per_second=73.6894M/s
schwaemm192_192_decrypt/128/32        2162 ns         2162 ns       323751 bytes_per_second=70.5726M/s
schwaemm192_192_encrypt/256/32        3015 ns         3015 ns       232192 bytes_per_second=91.1051M/s
schwaemm192_192_decrypt/256/32        3156 ns         3156 ns       221793 bytes_per_second=87.0406M/s
schwaemm192_192_encrypt/512/32        5090 ns         5090 ns       137502 bytes_per_second=101.917M/s
schwaemm192_192_decrypt/512/32        5322 ns         5322 ns       131506 bytes_per_second=97.4742M/s
schwaemm192_192_encrypt/1024/32       9057 ns         9057 ns        77282 bytes_per_second=111.192M/s
schwaemm192_192_decrypt/1024/32       9462 ns         9462 ns        73981 bytes_per_second=106.434M/s
schwaemm192_192_encrypt/2048/32      17176 ns        17176 ns        40756 bytes_per_second=115.491M/s
schwaemm192_192_decrypt/2048/32      17935 ns        17935 ns        39029 bytes_per_second=110.605M/s
schwaemm192_192_encrypt/4096/32      33229 ns        33228 ns        21067 bytes_per_second=118.477M/s
schwaemm192_192_decrypt/4096/32      34687 ns        34687 ns        20181 bytes_per_second=113.495M/s
schwaemm128_128_encrypt/64/32         1129 ns         1129 ns       619947 bytes_per_second=81.0857M/s
schwaemm128_128_decrypt/64/32         1134 ns         1134 ns       617088 bytes_per_second=80.7116M/s
schwaemm128_128_encrypt/128/32        1679 ns         1679 ns       416793 bytes_per_second=90.8546M/s
schwaemm128_128_decrypt/128/32        1668 ns         1668 ns       419705 bytes_per_second=91.4914M/s
schwaemm128_128_encrypt/256/32        2766 ns         2765 ns       253105 bytes_per_second=99.3169M/s
schwaemm128_128_decrypt/256/32        2719 ns         2719 ns       257436 bytes_per_second=101.015M/s
schwaemm128_128_encrypt/512/32        4938 ns         4938 ns       141772 bytes_per_second=105.072M/s
schwaemm128_128_decrypt/512/32        4822 ns         4821 ns       145186 bytes_per_second=107.602M/s
schwaemm128_128_encrypt/1024/32       9282 ns         9282 ns        75418 bytes_per_second=108.503M/s
schwaemm128_128_decrypt/1024/32       9026 ns         9026 ns        77548 bytes_per_second=111.572M/s
schwaemm128_128_encrypt/2048/32      17969 ns        17969 ns        38954 bytes_per_second=110.391M/s
schwaemm128_128_decrypt/2048/32      17437 ns        17437 ns        40146 bytes_per_second=113.763M/s
schwaemm128_128_encrypt/4096/32      35136 ns        35135 ns        19922 bytes_per_second=112.045M/s
schwaemm128_128_decrypt/4096/32      34257 ns        34256 ns        20433 bytes_per_second=114.921M/s
schwaemm256_256_encrypt/64/32         2288 ns         2288 ns       305929 bytes_per_second=40.0081M/s
schwaemm256_256_decrypt/64/32         2372 ns         2372 ns       294924 bytes_per_second=38.5973M/s
schwaemm256_256_encrypt/128/32        3114 ns         3114 ns       224872 bytes_per_second=48.9992M/s
schwaemm256_256_decrypt/128/32        3222 ns         3222 ns       217095 bytes_per_second=47.356M/s
schwaemm256_256_encrypt/256/32        4741 ns         4741 ns       147522 bytes_per_second=57.9291M/s
schwaemm256_256_decrypt/256/32        4912 ns         4912 ns       142479 bytes_per_second=55.9205M/s
schwaemm256_256_encrypt/512/32        8002 ns         8001 ns        87452 bytes_per_second=64.8382M/s
schwaemm256_256_decrypt/512/32        8293 ns         8293 ns        84376 bytes_per_second=62.5598M/s
schwaemm256_256_encrypt/1024/32      14518 ns        14517 ns        48207 bytes_per_second=69.371M/s
schwaemm256_256_decrypt/1024/32      15057 ns        15057 ns        46478 bytes_per_second=66.8853M/s
schwaemm256_256_encrypt/2048/32      27536 ns        27536 ns        25418 bytes_per_second=72.0392M/s
schwaemm256_256_decrypt/2048/32      28568 ns        28567 ns        24505 bytes_per_second=69.4383M/s
schwaemm256_256_encrypt/4096/32      53598 ns        53597 ns        13060 bytes_per_second=73.4511M/s
schwaemm256_256_decrypt/4096/32      55611 ns        55610 ns        12587 bytes_per_second=70.7924M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-05-28T16:44:26+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 3.13, 3.46, 3.10
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                       1117 ns         1036 ns       683500 bytes_per_second=58.9166M/s
esch256_hash/128                      1785 ns         1761 ns       401712 bytes_per_second=69.3208M/s
esch256_hash/256                      3254 ns         3216 ns       217531 bytes_per_second=75.9241M/s
esch256_hash/512                      6217 ns         6141 ns       115986 bytes_per_second=79.5092M/s
esch256_hash/1024                    12041 ns        11951 ns        58297 bytes_per_second=81.7153M/s
esch256_hash/2048                    23785 ns        23579 ns        29391 bytes_per_second=82.8336M/s
esch256_hash/4096                    47793 ns        47245 ns        15017 bytes_per_second=82.6803M/s
esch384_hash/64                       1395 ns         1379 ns       502004 bytes_per_second=44.2687M/s
esch384_hash/128                      2243 ns         2220 ns       316595 bytes_per_second=54.9959M/s
esch384_hash/256                      4137 ns         4059 ns       176567 bytes_per_second=60.1463M/s
esch384_hash/512                      7833 ns         7706 ns        96751 bytes_per_second=63.3623M/s
esch384_hash/1024                    14619 ns        14396 ns        35221 bytes_per_second=67.8349M/s
esch384_hash/2048                    28334 ns        28079 ns        25199 bytes_per_second=69.5574M/s
esch384_hash/4096                    55606 ns        55035 ns        12673 bytes_per_second=70.9778M/s
schwaemm256_128_encrypt/64/32         1075 ns         1063 ns       644995 bytes_per_second=86.1231M/s
schwaemm256_128_decrypt/64/32         1087 ns         1074 ns       654132 bytes_per_second=85.2757M/s
schwaemm256_128_encrypt/128/32        1463 ns         1448 ns       473966 bytes_per_second=105.366M/s
schwaemm256_128_decrypt/128/32        1471 ns         1458 ns       482942 bytes_per_second=104.656M/s
schwaemm256_128_encrypt/256/32        2253 ns         2235 ns       315173 bytes_per_second=122.88M/s
schwaemm256_128_decrypt/256/32        2218 ns         2202 ns       317676 bytes_per_second=124.73M/s
schwaemm256_128_encrypt/512/32        3891 ns         3826 ns       140786 bytes_per_second=135.599M/s
schwaemm256_128_decrypt/512/32        3758 ns         3730 ns       186354 bytes_per_second=139.077M/s
schwaemm256_128_encrypt/1024/32       6789 ns         6744 ns       101800 bytes_per_second=149.322M/s
schwaemm256_128_decrypt/1024/32       6851 ns         6797 ns       101457 bytes_per_second=148.164M/s
schwaemm256_128_encrypt/2048/32      12917 ns        12836 ns        54010 bytes_per_second=154.539M/s
schwaemm256_128_decrypt/2048/32      12925 ns        12850 ns        53394 bytes_per_second=154.371M/s
schwaemm256_128_encrypt/4096/32      25077 ns        24931 ns        27663 bytes_per_second=157.906M/s
schwaemm256_128_decrypt/4096/32      25190 ns        25026 ns        27956 bytes_per_second=157.308M/s
schwaemm192_192_encrypt/64/32         1425 ns         1415 ns       490832 bytes_per_second=64.6873M/s
schwaemm192_192_decrypt/64/32         1429 ns         1420 ns       487469 bytes_per_second=64.4903M/s
schwaemm192_192_encrypt/128/32        1987 ns         1974 ns       352503 bytes_per_second=77.2826M/s
schwaemm192_192_decrypt/128/32        1981 ns         1968 ns       353676 bytes_per_second=77.5358M/s
schwaemm192_192_encrypt/256/32        2933 ns         2914 ns       239054 bytes_per_second=94.2523M/s
schwaemm192_192_decrypt/256/32        2904 ns         2887 ns       240713 bytes_per_second=95.1495M/s
schwaemm192_192_encrypt/512/32        5036 ns         5005 ns       135344 bytes_per_second=103.652M/s
schwaemm192_192_decrypt/512/32        4942 ns         4916 ns       138864 bytes_per_second=105.536M/s
schwaemm192_192_encrypt/1024/32       9025 ns         8967 ns        77680 bytes_per_second=112.312M/s
schwaemm192_192_decrypt/1024/32       8908 ns         8811 ns        79361 bytes_per_second=114.303M/s
schwaemm192_192_encrypt/2048/32      17531 ns        17238 ns        40490 bytes_per_second=115.077M/s
schwaemm192_192_decrypt/2048/32      16942 ns        16712 ns        39723 bytes_per_second=118.698M/s
schwaemm192_192_encrypt/4096/32      33152 ns        32941 ns        21284 bytes_per_second=119.508M/s
schwaemm192_192_decrypt/4096/32      32496 ns        32305 ns        21680 bytes_per_second=121.863M/s
schwaemm128_128_encrypt/64/32          748 ns          744 ns       910711 bytes_per_second=123.084M/s
schwaemm128_128_decrypt/64/32          738 ns          733 ns       943422 bytes_per_second=124.846M/s
schwaemm128_128_encrypt/128/32        1056 ns         1050 ns       659221 bytes_per_second=145.311M/s
schwaemm128_128_decrypt/128/32        1048 ns         1042 ns       667137 bytes_per_second=146.441M/s
schwaemm128_128_encrypt/256/32        1683 ns         1672 ns       414864 bytes_per_second=164.247M/s
schwaemm128_128_decrypt/256/32        1668 ns         1657 ns       422198 bytes_per_second=165.762M/s
schwaemm128_128_encrypt/512/32        2909 ns         2889 ns       239623 bytes_per_second=179.597M/s
schwaemm128_128_decrypt/512/32        2912 ns         2891 ns       240238 bytes_per_second=179.423M/s
schwaemm128_128_encrypt/1024/32       5393 ns         5361 ns       125956 bytes_per_second=187.836M/s
schwaemm128_128_decrypt/1024/32       5363 ns         5331 ns       129142 bytes_per_second=188.922M/s
schwaemm128_128_encrypt/2048/32      10375 ns        10310 ns        67231 bytes_per_second=192.406M/s
schwaemm128_128_decrypt/2048/32      10288 ns        10221 ns        66252 bytes_per_second=194.084M/s
schwaemm128_128_encrypt/4096/32      20238 ns        20114 ns        34536 bytes_per_second=195.722M/s
schwaemm128_128_decrypt/4096/32      20145 ns        20024 ns        34703 bytes_per_second=196.606M/s
schwaemm256_256_encrypt/64/32         1151 ns         1144 ns       605610 bytes_per_second=80.0282M/s
schwaemm256_256_decrypt/64/32         1166 ns         1158 ns       600688 bytes_per_second=79.0722M/s
schwaemm256_256_encrypt/128/32        1565 ns         1555 ns       446480 bytes_per_second=98.1174M/s
schwaemm256_256_decrypt/128/32        1579 ns         1568 ns       437650 bytes_per_second=97.2996M/s
schwaemm256_256_encrypt/256/32        2409 ns         2394 ns       290874 bytes_per_second=114.733M/s
schwaemm256_256_decrypt/256/32        2426 ns         2410 ns       288443 bytes_per_second=113.982M/s
schwaemm256_256_encrypt/512/32        4101 ns         4075 ns       171628 bytes_per_second=127.299M/s
schwaemm256_256_decrypt/512/32        4092 ns         4065 ns       170793 bytes_per_second=127.637M/s
schwaemm256_256_encrypt/1024/32       7503 ns         7411 ns        92228 bytes_per_second=135.89M/s
schwaemm256_256_decrypt/1024/32       7443 ns         7396 ns        94020 bytes_per_second=136.169M/s
schwaemm256_256_encrypt/2048/32      14186 ns        14110 ns        49035 bytes_per_second=140.589M/s
schwaemm256_256_decrypt/2048/32      14159 ns        14076 ns        49448 bytes_per_second=140.923M/s
schwaemm256_256_encrypt/4096/32      27583 ns        27423 ns        25349 bytes_per_second=143.555M/s
schwaemm256_256_decrypt/4096/32      27458 ns        27304 ns        25487 bytes_per_second=144.184M/s
```
