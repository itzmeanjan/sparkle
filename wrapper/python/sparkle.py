#!/usr/bin/python3

'''
  Before using `sparkle` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then all function calls are forwarded to respective C++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>
  
  Project: https://github.com/itzmeanjan/sparkle
'''

from typing import Tuple
import ctypes as ct
import numpy as np
from posixpath import exists, abspath

SO_PATH: str = abspath('../libsparkle.so')
assert exists(SO_PATH), 'Use `make lib` to generate shared library object !'

SO_LIB: ct.CDLL = ct.CDLL(SO_PATH)

u8 = np.uint8
len_t = ct.c_size_t
uint8_tp = np.ctypeslib.ndpointer(dtype=u8, ndim=1, flags='CONTIGUOUS')
bool_t = ct.c_bool


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


def schwaemm256_128_encrypt(
    key: bytes, nonce: bytes, data: bytes, text: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypts M ( >=0 ) -many plain text bytes, while using 16 -bytes secret key,
    32 -bytes public message nonce & N ( >=0 ) -bytes associated data, while producing
    M -bytes cipher text & 16 -bytes authentication tag ( in order )
    """
    assert len(key) == 16, "Schwaemm256-128 takes 16 -bytes secret key !"
    assert len(nonce) == 32, "Schwaemm256-128 takes 32 -bytes nonce !"

    ad_len = len(data)
    ct_len = len(text)

    key_ = np.frombuffer(key, dtype=u8)
    nonce_ = np.frombuffer(nonce, dtype=u8)
    data_ = np.frombuffer(data, dtype=u8)
    text_ = np.frombuffer(text, dtype=u8)
    enc = np.empty(ct_len, dtype=u8)
    tag = np.empty(16, dtype=u8)

    args = [uint8_tp, uint8_tp, uint8_tp, len_t,
            uint8_tp, uint8_tp, len_t, uint8_tp]
    SO_LIB.schwaemm256_128_encrypt.argtypes = args

    SO_LIB.schwaemm256_128_encrypt(key_, nonce_, data_, ad_len,
                                   text_, enc, ct_len, tag)

    enc_ = enc.tobytes()
    tag_ = tag.tobytes()

    return enc_, tag_


def schwaemm256_128_decrypt(
    key: bytes, nonce: bytes, tag: bytes, data: bytes, enc: bytes
) -> Tuple[bool, bytes]:
    """
    Decrypts M ( >=0 ) -many cipher text bytes, while using 16 -bytes secret key,
    32 -bytes public message nonce, 16 -bytes authentication tag & N ( >=0 ) -bytes
    associated data, while producing boolean flag denoting verification status ( which 
    must hold truth value, check before consuming decrypted output bytes ) &
    M -bytes plain text ( in order )
    """
    assert len(key) == 16, "Schwaemm256-128 takes 16 -bytes secret key !"
    assert len(nonce) == 32, "Schwaemm256-128 takes 32 -bytes nonce !"
    assert len(tag) == 16, "Schwaemm256-128 takes 16 -bytes authentication tag !"

    ad_len = len(data)
    ct_len = len(enc)

    key_ = np.frombuffer(key, dtype=u8)
    nonce_ = np.frombuffer(nonce, dtype=u8)
    tag_ = np.frombuffer(tag, dtype=u8)
    data_ = np.frombuffer(data, dtype=u8)
    enc_ = np.frombuffer(enc, dtype=u8)
    dec = np.empty(ct_len, dtype=u8)

    args = [uint8_tp, uint8_tp, uint8_tp,
            uint8_tp, len_t, uint8_tp, uint8_tp, len_t]
    SO_LIB.schwaemm256_128_decrypt.argtypes = args
    SO_LIB.schwaemm256_128_decrypt.restype = bool_t

    f = SO_LIB.schwaemm256_128_decrypt(key_, nonce_, tag_, data_,
                                       ad_len, enc_, dec, ct_len)

    dec_ = dec.tobytes()

    return f, dec_


def schwaemm192_192_encrypt(
    key: bytes, nonce: bytes, data: bytes, text: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypts M ( >=0 ) -many plain text bytes, while using 24 -bytes secret key,
    24 -bytes public message nonce & N ( >=0 ) -bytes associated data, while producing
    M -bytes cipher text & 24 -bytes authentication tag ( in order )
    """
    assert len(key) == 24, "Schwaemm192-192 takes 24 -bytes secret key !"
    assert len(nonce) == 24, "Schwaemm192-192 takes 24 -bytes nonce !"

    ad_len = len(data)
    ct_len = len(text)

    key_ = np.frombuffer(key, dtype=u8)
    nonce_ = np.frombuffer(nonce, dtype=u8)
    data_ = np.frombuffer(data, dtype=u8)
    text_ = np.frombuffer(text, dtype=u8)
    enc = np.empty(ct_len, dtype=u8)
    tag = np.empty(24, dtype=u8)

    args = [uint8_tp, uint8_tp, uint8_tp, len_t,
            uint8_tp, uint8_tp, len_t, uint8_tp]
    SO_LIB.schwaemm192_192_encrypt.argtypes = args

    SO_LIB.schwaemm192_192_encrypt(key_, nonce_, data_, ad_len,
                                   text_, enc, ct_len, tag)

    enc_ = enc.tobytes()
    tag_ = tag.tobytes()

    return enc_, tag_


def schwaemm192_192_decrypt(
    key: bytes, nonce: bytes, tag: bytes, data: bytes, enc: bytes
) -> Tuple[bool, bytes]:
    """
    Decrypts M ( >=0 ) -many cipher text bytes, while using 24 -bytes secret key,
    24 -bytes public message nonce, 24 -bytes authentication tag & N ( >=0 ) -bytes
    associated data, while producing boolean flag denoting verification status ( which 
    must hold truth value, check before consuming decrypted output bytes ) &
    M -bytes plain text ( in order )
    """
    assert len(key) == 24, "Schwaemm192-192 takes 24 -bytes secret key !"
    assert len(nonce) == 24, "Schwaemm192-192 takes 24 -bytes nonce !"
    assert len(tag) == 24, "Schwaemm192-192 takes 24 -bytes authentication tag !"

    ad_len = len(data)
    ct_len = len(enc)

    key_ = np.frombuffer(key, dtype=u8)
    nonce_ = np.frombuffer(nonce, dtype=u8)
    tag_ = np.frombuffer(tag, dtype=u8)
    data_ = np.frombuffer(data, dtype=u8)
    enc_ = np.frombuffer(enc, dtype=u8)
    dec = np.empty(ct_len, dtype=u8)

    args = [uint8_tp, uint8_tp, uint8_tp,
            uint8_tp, len_t, uint8_tp, uint8_tp, len_t]
    SO_LIB.schwaemm192_192_decrypt.argtypes = args
    SO_LIB.schwaemm192_192_decrypt.restype = bool_t

    f = SO_LIB.schwaemm192_192_decrypt(key_, nonce_, tag_, data_,
                                       ad_len, enc_, dec, ct_len)

    dec_ = dec.tobytes()

    return f, dec_


def schwaemm128_128_encrypt(
    key: bytes, nonce: bytes, data: bytes, text: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypts M ( >=0 ) -many plain text bytes, while using 16 -bytes secret key,
    16 -bytes public message nonce & N ( >=0 ) -bytes associated data, while producing
    M -bytes cipher text & 16 -bytes authentication tag ( in order )
    """
    assert len(key) == 16, "Schwaemm128-128 takes 16 -bytes secret key !"
    assert len(nonce) == 16, "Schwaemm128-128 takes 16 -bytes nonce !"

    ad_len = len(data)
    ct_len = len(text)

    key_ = np.frombuffer(key, dtype=u8)
    nonce_ = np.frombuffer(nonce, dtype=u8)
    data_ = np.frombuffer(data, dtype=u8)
    text_ = np.frombuffer(text, dtype=u8)
    enc = np.empty(ct_len, dtype=u8)
    tag = np.empty(16, dtype=u8)

    args = [uint8_tp, uint8_tp, uint8_tp, len_t,
            uint8_tp, uint8_tp, len_t, uint8_tp]
    SO_LIB.schwaemm128_128_encrypt.argtypes = args

    SO_LIB.schwaemm128_128_encrypt(key_, nonce_, data_, ad_len,
                                   text_, enc, ct_len, tag)

    enc_ = enc.tobytes()
    tag_ = tag.tobytes()

    return enc_, tag_


def schwaemm128_128_decrypt(
    key: bytes, nonce: bytes, tag: bytes, data: bytes, enc: bytes
) -> Tuple[bool, bytes]:
    """
    Decrypts M ( >=0 ) -many cipher text bytes, while using 16 -bytes secret key,
    16 -bytes public message nonce, 16 -bytes authentication tag & N ( >=0 ) -bytes
    associated data, while producing boolean flag denoting verification status ( which 
    must hold truth value, check before consuming decrypted output bytes ) &
    M -bytes plain text ( in order )
    """
    assert len(key) == 16, "Schwaemm128-128 takes 16 -bytes secret key !"
    assert len(nonce) == 16, "Schwaemm128-128 takes 16 -bytes nonce !"
    assert len(tag) == 16, "Schwaemm128-128 takes 16 -bytes authentication tag !"

    ad_len = len(data)
    ct_len = len(enc)

    key_ = np.frombuffer(key, dtype=u8)
    nonce_ = np.frombuffer(nonce, dtype=u8)
    tag_ = np.frombuffer(tag, dtype=u8)
    data_ = np.frombuffer(data, dtype=u8)
    enc_ = np.frombuffer(enc, dtype=u8)
    dec = np.empty(ct_len, dtype=u8)

    args = [uint8_tp, uint8_tp, uint8_tp,
            uint8_tp, len_t, uint8_tp, uint8_tp, len_t]
    SO_LIB.schwaemm128_128_decrypt.argtypes = args
    SO_LIB.schwaemm128_128_decrypt.restype = bool_t

    f = SO_LIB.schwaemm128_128_decrypt(key_, nonce_, tag_, data_,
                                       ad_len, enc_, dec, ct_len)

    dec_ = dec.tobytes()

    return f, dec_


if __name__ == '__main__':
    print('Use `sparkle` as library module !')
