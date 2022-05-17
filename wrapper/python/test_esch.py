#!/usr/bin/python3

import esch
import numpy as np

u8 = np.uint8


def test_esch256_hash_kat():
    """
    Test functional correctness of Esch256 cryptographic hash implementation,
    by comparing digests against NIST LWC submission package's Known Answer Tests
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

            digest = esch.esch256_hash(msg)

            assert (
                md == digest
            ), f"[Esch256 Hash KAT {cnt}] expected {md}, found {digest} !"

            fd.readline()


def test_esch384_hash_kat():
    """
    Test functional correctness of Esch384 cryptographic hash implementation,
    by comparing digests against NIST LWC submission package's Known Answer Tests
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

            digest = esch.esch384_hash(msg)

            assert (
                md == digest
            ), f"[Esch384 Hash KAT {cnt}] expected {md}, found {digest} !"

            fd.readline()
