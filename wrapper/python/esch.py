#!/usr/bin/python3

'''
  Before using `esch` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then all function calls are forwarded to respective C++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>
  
  Project: https://github.com/itzmeanjan/sparkle
'''

import ctypes as ct
import numpy as np
from posixpath import exists, abspath

SO_PATH: str = abspath('../libesch.so')
assert exists(SO_PATH), 'Use `make lib` to generate shared library object !'

SO_LIB: ct.CDLL = ct.CDLL(SO_PATH)

u8 = np.uint8
len_t = ct.c_size_t
uint8_tp = np.ctypeslib.ndpointer(dtype=u8, ndim=1, flags='CONTIGUOUS')

def esch256_hash(msg: bytes) -> bytes:
    '''
    Given a N ( >= 0 ) -bytes input message, this function computes 32 -bytes
    Esch256 cryptographic hash digest
    '''
    m_len = len(msg)
    msg_ = np.frombuffer(msg, dtype=u8)
    digest = np.empty(32, dtype=u8)

    args = [uint8_tp, len_t, uint8_tp]
    SO_LIB.esch256_hash.argtypes = args

    SO_LIB.esch256_hash(msg_, m_len, digest)

    digest_ = digest.tobytes()
    return digest_

def esch384_hash(msg: bytes) -> bytes:
    '''
    Given a N ( >= 0 ) -bytes input message, this function computes 48 -bytes
    Esch384 cryptographic hash digest
    '''
    m_len = len(msg)
    msg_ = np.frombuffer(msg, dtype=u8)
    digest = np.empty(48, dtype=u8)

    args = [uint8_tp, len_t, uint8_tp]
    SO_LIB.esch384_hash.argtypes = args

    SO_LIB.esch384_hash(msg_, m_len, digest)

    digest_ = digest.tobytes()
    return digest_

if __name__ == '__main__':
    print('Use `esch` as library module !')
