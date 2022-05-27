#!/usr/bin/python3

import sparkle
import numpy as np

u8 = np.uint8


def test_esch256_hash_kat():
    """
    Test functional correctness of Esch256 cryptographic hash implementation,
    by comparing digests against NIST LWC submission package's Known Answer Tests

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_HASH_KAT_256.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs
                break

            msg = fd.readline()
            md = fd.readline()

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            msg = [i.strip() for i in msg.split("=")][-1]
            md = [i.strip() for i in md.split("=")][-1]

            msg = bytes([
                int(f"0x{msg[(i << 1): ((i+1) << 1)]}", base=16)
                for i in range(len(msg) >> 1)
            ])

            md = bytes([
                int(f"0x{md[(i << 1): ((i+1) << 1)]}", base=16)
                for i in range(len(md) >> 1)
            ])

            digest = sparkle.esch256_hash(msg)

            assert (
                md == digest
            ), f"[Esch256 Hash KAT {cnt}] expected {md}, found {digest} !"

            fd.readline()


def test_esch384_hash_kat():
    """
    Test functional correctness of Esch384 cryptographic hash implementation,
    by comparing digests against NIST LWC submission package's Known Answer Tests

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_HASH_KAT_384.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs
                break

            msg = fd.readline()
            md = fd.readline()

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            msg = [i.strip() for i in msg.split("=")][-1]
            md = [i.strip() for i in md.split("=")][-1]

            msg = bytes([
                int(f"0x{msg[(i << 1): ((i+1) << 1)]}", base=16)
                for i in range(len(msg) >> 1)
            ])

            md = bytes([
                int(f"0x{md[(i << 1): ((i+1) << 1)]}", base=16)
                for i in range(len(md) >> 1)
            ])

            digest = sparkle.esch384_hash(msg)

            assert (
                md == digest
            ), f"[Esch384 Hash KAT {cnt}] expected {md}, found {digest} !"

            fd.readline()


def test_schwaemm256_128_kat():
    """
    Tests functional correctness of Schwaemm256-128 AEAD implementation, using
    Known Answer Tests submitted along with final round submission of Sparkle in NIST LWC

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """

    from sparkle import schwaemm256_128_encrypt, schwaemm256_128_decrypt

    with open("LWC_AEAD_KAT_128_256.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(16, "big")
            # 256 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(32, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = schwaemm256_128_encrypt(key, nonce, ad, pt)
            flag, text = schwaemm256_128_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct
            ), f"[Schwaemm256-128 KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x${(cipher + tag).hex()} !"
            assert (
                pt == text and flag
            ), f"[Schwaemm256-128 KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def test_schwaemm192_192_kat():
    """
    Tests functional correctness of Schwaemm192-192 AEAD implementation, using
    Known Answer Tests submitted along with final round submission of Sparkle in NIST LWC

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """

    from sparkle import schwaemm192_192_encrypt, schwaemm192_192_decrypt

    with open("LWC_AEAD_KAT_192_192.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 192 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(24, "big")
            # 192 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(24, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = schwaemm192_192_encrypt(key, nonce, ad, pt)
            flag, text = schwaemm192_192_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct
            ), f"[Schwaemm192-192 KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x${(cipher + tag).hex()} !"
            assert (
                pt == text and flag
            ), f"[Schwaemm192-192 KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def test_schwaemm128_128_kat():
    """
    Tests functional correctness of Schwaemm128-128 AEAD implementation, using
    Known Answer Tests submitted along with final round submission of Sparkle in NIST LWC

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """

    from sparkle import schwaemm128_128_encrypt, schwaemm128_128_decrypt

    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(16, "big")
            # 128 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(16, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = schwaemm128_128_encrypt(key, nonce, ad, pt)
            flag, text = schwaemm128_128_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct
            ), f"[Schwaemm128-128 KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x${(cipher + tag).hex()} !"
            assert (
                pt == text and flag
            ), f"[Schwaemm128-128 KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


if __name__ == '__main__':
    print('Use `pytest` for driving Sparkle tests against Known Answer Tests ( KAT ) !')
