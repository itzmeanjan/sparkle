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
2022-05-28T11:00:39+00:00
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
esch256_hash/64                        881 ns          881 ns       794077 bytes_per_second=69.2744M/s
esch256_hash/128                      1513 ns         1513 ns       462580 bytes_per_second=80.6695M/s
esch256_hash/256                      2763 ns         2763 ns       253372 bytes_per_second=88.3699M/s
esch256_hash/512                      5262 ns         5262 ns       133025 bytes_per_second=92.7993M/s
esch256_hash/1024                    10260 ns        10260 ns        68225 bytes_per_second=95.1851M/s
esch256_hash/2048                    20257 ns        20257 ns        34556 bytes_per_second=96.4179M/s
esch256_hash/4096                    40252 ns        40251 ns        17391 bytes_per_second=97.0473M/s
esch384_hash/64                       2615 ns         2615 ns       267711 bytes_per_second=23.3433M/s
esch384_hash/128                      4204 ns         4204 ns       166517 bytes_per_second=29.0383M/s
esch384_hash/256                      7385 ns         7385 ns        94778 bytes_per_second=33.0584M/s
esch384_hash/512                     13749 ns        13749 ns        50910 bytes_per_second=35.5147M/s
esch384_hash/1024                    26474 ns        26474 ns        26440 bytes_per_second=36.8878M/s
esch384_hash/2048                    51928 ns        51928 ns        13479 bytes_per_second=37.6125M/s
esch384_hash/4096                   102838 ns       102837 ns         6807 bytes_per_second=37.985M/s
schwaemm256_128_encrypt/64/32         1189 ns         1189 ns       588886 bytes_per_second=77.0213M/s
schwaemm256_128_decrypt/64/32         1199 ns         1199 ns       587113 bytes_per_second=76.3754M/s
schwaemm256_128_encrypt/128/32        1631 ns         1631 ns       429244 bytes_per_second=93.569M/s
schwaemm256_128_decrypt/128/32        1641 ns         1641 ns       426444 bytes_per_second=92.9598M/s
schwaemm256_128_encrypt/256/32        2522 ns         2521 ns       277602 bytes_per_second=108.927M/s
schwaemm256_128_decrypt/256/32        2557 ns         2557 ns       274392 bytes_per_second=107.399M/s
schwaemm256_128_encrypt/512/32        4290 ns         4290 ns       163183 bytes_per_second=120.943M/s
schwaemm256_128_decrypt/512/32        4350 ns         4350 ns       160921 bytes_per_second=119.268M/s
schwaemm256_128_encrypt/1024/32       7826 ns         7826 ns        89426 bytes_per_second=128.68M/s
schwaemm256_128_decrypt/1024/32       7960 ns         7960 ns        87937 bytes_per_second=126.521M/s
schwaemm256_128_encrypt/2048/32      14899 ns        14899 ns        46982 bytes_per_second=133.137M/s
schwaemm256_128_decrypt/2048/32      15155 ns        15154 ns        46190 bytes_per_second=130.896M/s
schwaemm256_128_encrypt/4096/32      29058 ns        29057 ns        24093 bytes_per_second=135.483M/s
schwaemm256_128_decrypt/4096/32      29578 ns        29578 ns        23666 bytes_per_second=133.097M/s
schwaemm192_192_encrypt/64/32         1495 ns         1495 ns       468243 bytes_per_second=61.2412M/s
schwaemm192_192_decrypt/64/32         1572 ns         1572 ns       445247 bytes_per_second=58.2505M/s
schwaemm192_192_encrypt/128/32        2069 ns         2069 ns       338169 bytes_per_second=73.7442M/s
schwaemm192_192_decrypt/128/32        2162 ns         2162 ns       323745 bytes_per_second=70.572M/s
schwaemm192_192_encrypt/256/32        3014 ns         3014 ns       232223 bytes_per_second=91.1208M/s
schwaemm192_192_decrypt/256/32        3154 ns         3154 ns       221953 bytes_per_second=87.0744M/s
schwaemm192_192_encrypt/512/32        5090 ns         5090 ns       137520 bytes_per_second=101.926M/s
schwaemm192_192_decrypt/512/32        5317 ns         5317 ns       131653 bytes_per_second=97.5678M/s
schwaemm192_192_encrypt/1024/32       9057 ns         9057 ns        77289 bytes_per_second=111.197M/s
schwaemm192_192_decrypt/1024/32       9449 ns         9449 ns        74076 bytes_per_second=106.577M/s
schwaemm192_192_encrypt/2048/32      17175 ns        17175 ns        40757 bytes_per_second=115.495M/s
schwaemm192_192_decrypt/2048/32      17908 ns        17908 ns        39086 bytes_per_second=110.766M/s
schwaemm192_192_encrypt/4096/32      33228 ns        33227 ns        21066 bytes_per_second=118.479M/s
schwaemm192_192_decrypt/4096/32      34632 ns        34632 ns        20212 bytes_per_second=113.675M/s
schwaemm128_128_encrypt/64/32         1129 ns         1129 ns       619957 bytes_per_second=81.0856M/s
schwaemm128_128_decrypt/64/32         1134 ns         1134 ns       617329 bytes_per_second=80.7463M/s
schwaemm128_128_encrypt/128/32        1680 ns         1679 ns       416764 bytes_per_second=90.8538M/s
schwaemm128_128_decrypt/128/32        1667 ns         1667 ns       419831 bytes_per_second=91.5203M/s
schwaemm128_128_encrypt/256/32        2766 ns         2766 ns       253116 bytes_per_second=99.315M/s
schwaemm128_128_decrypt/256/32        2718 ns         2718 ns       257499 bytes_per_second=101.036M/s
schwaemm128_128_encrypt/512/32        4938 ns         4937 ns       141771 bytes_per_second=105.074M/s
schwaemm128_128_decrypt/512/32        4821 ns         4821 ns       145204 bytes_per_second=107.617M/s
schwaemm128_128_encrypt/1024/32       9281 ns         9281 ns        75417 bytes_per_second=108.505M/s
schwaemm128_128_decrypt/1024/32       9026 ns         9026 ns        77553 bytes_per_second=111.579M/s
schwaemm128_128_encrypt/2048/32      17970 ns        17970 ns        38955 bytes_per_second=110.388M/s
schwaemm128_128_decrypt/2048/32      17436 ns        17435 ns        40148 bytes_per_second=113.772M/s
schwaemm128_128_encrypt/4096/32      35346 ns        35346 ns        19805 bytes_per_second=111.379M/s
schwaemm128_128_decrypt/4096/32      34255 ns        34255 ns        20435 bytes_per_second=114.927M/s
schwaemm256_256_encrypt/64/32         2301 ns         2301 ns       303988 bytes_per_second=39.7957M/s
schwaemm256_256_decrypt/64/32         2444 ns         2444 ns       287094 bytes_per_second=37.4673M/s
schwaemm256_256_encrypt/128/32        3170 ns         3170 ns       220785 bytes_per_second=48.1369M/s
schwaemm256_256_decrypt/128/32        3343 ns         3343 ns       209417 bytes_per_second=45.6407M/s
schwaemm256_256_encrypt/256/32        4891 ns         4891 ns       143089 bytes_per_second=56.1615M/s
schwaemm256_256_decrypt/256/32        5145 ns         5145 ns       135982 bytes_per_second=53.3864M/s
schwaemm256_256_encrypt/512/32        8325 ns         8325 ns        84054 bytes_per_second=62.3191M/s
schwaemm256_256_decrypt/512/32        8742 ns         8742 ns        80071 bytes_per_second=59.3466M/s
schwaemm256_256_encrypt/1024/32      15202 ns        15202 ns        46043 bytes_per_second=66.247M/s
schwaemm256_256_decrypt/1024/32      15944 ns        15944 ns        43898 bytes_per_second=63.1627M/s
schwaemm256_256_encrypt/2048/32      28953 ns        28952 ns        24180 bytes_per_second=68.5145M/s
schwaemm256_256_decrypt/2048/32      30346 ns        30346 ns        23065 bytes_per_second=65.3677M/s
schwaemm256_256_encrypt/4096/32      56444 ns        56444 ns        12401 bytes_per_second=69.7469M/s
schwaemm256_256_decrypt/4096/32      59156 ns        59155 ns        11833 bytes_per_second=66.5495M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-05-28T14:57:38+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.25, 2.37, 2.42
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
esch256_hash/64                        981 ns          980 ns       696088 bytes_per_second=62.2502M/s
esch256_hash/128                      1673 ns         1670 ns       413829 bytes_per_second=73.1062M/s
esch256_hash/256                      3098 ns         3091 ns       225622 bytes_per_second=78.9755M/s
esch256_hash/512                      5914 ns         5900 ns       115911 bytes_per_second=82.7642M/s
esch256_hash/1024                    11424 ns        11409 ns        60730 bytes_per_second=85.5922M/s
esch256_hash/2048                    22615 ns        22591 ns        30629 bytes_per_second=86.4552M/s
esch256_hash/4096                    44702 ns        44647 ns        15593 bytes_per_second=87.4917M/s
esch384_hash/64                       1302 ns         1302 ns       525636 bytes_per_second=46.8958M/s
esch384_hash/128                      2132 ns         2128 ns       327817 bytes_per_second=57.3707M/s
esch384_hash/256                      3740 ns         3737 ns       185153 bytes_per_second=65.3294M/s
esch384_hash/512                      6967 ns         6959 ns        97421 bytes_per_second=70.17M/s
esch384_hash/1024                    13526 ns        13508 ns        51680 bytes_per_second=72.2935M/s
esch384_hash/2048                    26380 ns        26357 ns        26427 bytes_per_second=74.1038M/s
esch384_hash/4096                    52586 ns        52487 ns        13018 bytes_per_second=74.4238M/s
schwaemm256_128_encrypt/64/32         1014 ns         1011 ns       679381 bytes_per_second=90.5243M/s
schwaemm256_128_decrypt/64/32         1019 ns         1017 ns       685569 bytes_per_second=89.9866M/s
schwaemm256_128_encrypt/128/32        1378 ns         1376 ns       497127 bytes_per_second=110.895M/s
schwaemm256_128_decrypt/128/32        1388 ns         1385 ns       499272 bytes_per_second=110.173M/s
schwaemm256_128_encrypt/256/32        2119 ns         2115 ns       329182 bytes_per_second=129.842M/s
schwaemm256_128_decrypt/256/32        2125 ns         2122 ns       323191 bytes_per_second=129.462M/s
schwaemm256_128_encrypt/512/32        3583 ns         3577 ns       195106 bytes_per_second=145.019M/s
schwaemm256_128_decrypt/512/32        3582 ns         3577 ns       194647 bytes_per_second=145.032M/s
schwaemm256_128_encrypt/1024/32       6525 ns         6518 ns       103458 bytes_per_second=154.514M/s
schwaemm256_128_decrypt/1024/32       6535 ns         6526 ns       105366 bytes_per_second=154.321M/s
schwaemm256_128_encrypt/2048/32      12402 ns        12302 ns        56072 bytes_per_second=161.25M/s
schwaemm256_128_decrypt/2048/32      12453 ns        12429 ns        55146 bytes_per_second=159.592M/s
schwaemm256_128_encrypt/4096/32      24134 ns        24104 ns        28739 bytes_per_second=163.328M/s
schwaemm256_128_decrypt/4096/32      23997 ns        23968 ns        28825 bytes_per_second=164.249M/s
schwaemm192_192_encrypt/64/32         1366 ns         1364 ns       504639 bytes_per_second=67.0965M/s
schwaemm192_192_decrypt/64/32         1380 ns         1376 ns       500225 bytes_per_second=66.5192M/s
schwaemm192_192_encrypt/128/32        1921 ns         1918 ns       363754 bytes_per_second=79.5373M/s
schwaemm192_192_decrypt/128/32        1910 ns         1907 ns       364595 bytes_per_second=80.0018M/s
schwaemm192_192_encrypt/256/32        2834 ns         2830 ns       247511 bytes_per_second=97.0639M/s
schwaemm192_192_decrypt/256/32        2782 ns         2776 ns       249497 bytes_per_second=98.9241M/s
schwaemm192_192_encrypt/512/32        4863 ns         4856 ns       139654 bytes_per_second=106.836M/s
schwaemm192_192_decrypt/512/32        4764 ns         4759 ns       138859 bytes_per_second=109.02M/s
schwaemm192_192_encrypt/1024/32       8621 ns         8612 ns        79429 bytes_per_second=116.946M/s
schwaemm192_192_decrypt/1024/32       8513 ns         8502 ns        80828 bytes_per_second=118.446M/s
schwaemm192_192_encrypt/2048/32      16309 ns        16289 ns        42469 bytes_per_second=121.779M/s
schwaemm192_192_decrypt/2048/32      16130 ns        16111 ns        43164 bytes_per_second=123.124M/s
schwaemm192_192_encrypt/4096/32      32324 ns        32271 ns        21905 bytes_per_second=121.991M/s
schwaemm192_192_decrypt/4096/32      31166 ns        31124 ns        22347 bytes_per_second=126.488M/s
schwaemm128_128_encrypt/64/32          731 ns          730 ns       947919 bytes_per_second=125.449M/s
schwaemm128_128_decrypt/64/32          705 ns          704 ns       969731 bytes_per_second=130.074M/s
schwaemm128_128_encrypt/128/32        1019 ns         1018 ns       685979 bytes_per_second=149.906M/s
schwaemm128_128_decrypt/128/32         999 ns          998 ns       691802 bytes_per_second=152.959M/s
schwaemm128_128_encrypt/256/32        1618 ns         1616 ns       423204 bytes_per_second=169.976M/s
schwaemm128_128_decrypt/256/32        1600 ns         1595 ns       431630 bytes_per_second=172.148M/s
schwaemm128_128_encrypt/512/32        2822 ns         2817 ns       247895 bytes_per_second=184.178M/s
schwaemm128_128_decrypt/512/32        2777 ns         2774 ns       250593 bytes_per_second=187.042M/s
schwaemm128_128_encrypt/1024/32       5239 ns         5180 ns       128710 bytes_per_second=194.402M/s
schwaemm128_128_decrypt/1024/32       5269 ns         5253 ns       127917 bytes_per_second=191.698M/s
schwaemm128_128_encrypt/2048/32      10181 ns        10165 ns        68182 bytes_per_second=195.14M/s
schwaemm128_128_decrypt/2048/32       9906 ns         9895 ns        67259 bytes_per_second=200.462M/s
schwaemm128_128_encrypt/4096/32      19361 ns        19332 ns        35794 bytes_per_second=203.638M/s
schwaemm128_128_decrypt/4096/32      19177 ns        19148 ns        35670 bytes_per_second=205.598M/s
schwaemm256_256_encrypt/64/32         1123 ns         1121 ns       606071 bytes_per_second=81.6603M/s
schwaemm256_256_decrypt/64/32         1156 ns         1154 ns       599100 bytes_per_second=79.3127M/s
schwaemm256_256_encrypt/128/32        1543 ns         1541 ns       444292 bytes_per_second=99.0226M/s
schwaemm256_256_decrypt/128/32        1593 ns         1591 ns       432355 bytes_per_second=95.9311M/s
schwaemm256_256_encrypt/256/32        2432 ns         2428 ns       288471 bytes_per_second=113.129M/s
schwaemm256_256_decrypt/256/32        2469 ns         2465 ns       280758 bytes_per_second=111.435M/s
schwaemm256_256_encrypt/512/32        4143 ns         4139 ns       169630 bytes_per_second=125.351M/s
schwaemm256_256_decrypt/512/32        4203 ns         4197 ns       166741 bytes_per_second=123.614M/s
schwaemm256_256_encrypt/1024/32       7556 ns         7546 ns        90326 bytes_per_second=133.465M/s
schwaemm256_256_decrypt/1024/32       7771 ns         7753 ns        89368 bytes_per_second=129.896M/s
schwaemm256_256_encrypt/2048/32      14401 ns        14374 ns        47784 bytes_per_second=138.001M/s
schwaemm256_256_decrypt/2048/32      14602 ns        14577 ns        46918 bytes_per_second=136.08M/s
schwaemm256_256_encrypt/4096/32      28707 ns        28208 ns        24614 bytes_per_second=139.561M/s
schwaemm256_256_decrypt/4096/32      28520 ns        28489 ns        24008 bytes_per_second=138.187M/s
```
