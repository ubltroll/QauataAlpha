"""Implention of rainbow signature By Troll Meyer @ 27/4/2022

Using rainbow signature at level Ia with circumzenithal style (Cyclic Rainbow)
public key length : 60192
private key length: 103648
signature length  : 66

Interface of rainbow run-time lib:

genkey: (randombytes: uint8 * 48) -> public&private key: uint8 * (60192 + 103648 = 163840)
sig: (msg: uint8 * [mlen], mlen: uint64, private key: uint8 * 103648) -> sig: uint8 * 66
verify: (msg: uint8 * [mlen], mlen: uint64, private key: uint8 * 103648) -> result: int (1: success, 0: fail, -1: error)
"""
import ctypes, os

from typing import Optional, Tuple, Union

rainbow_lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'librainbow.so')
rainbow_lib = ctypes.cdll.LoadLibrary(rainbow_lib_path)

rainbow_lib.genkey.argtypes = [ctypes.c_char_p]
rainbow_lib.genkey.restype = ctypes.POINTER(ctypes.c_ubyte)
rainbow_lib.sign.argtypes = [ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p]
rainbow_lib.sign.restype = ctypes.POINTER(ctypes.c_ubyte)
rainbow_lib.verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong]
rainbow_lib.verify.restype = ctypes.c_int

RAINBOW_PUBLICKEYBYTES = 60192
RAINBOW_SECRETKEYBYTES = 103648
RAINBOW_SINATURESBYTES = 66

class RainbowCrypto(object):
    RAINBOW_PUBLICKEYBYTES = RAINBOW_PUBLICKEYBYTES
    RAINBOW_SECRETKEYBYTES = RAINBOW_SECRETKEYBYTES
    RAINBOW_SINATURESBYTES = RAINBOW_SINATURESBYTES

    @staticmethod
    def generate_key_pair(seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if seed is None:
            seed = os.urandom(48)
        elif len(seed) != 48:
            raise TypeError('Input seed should be 48 bytes.')
        psk_pointer = rainbow_lib.genkey(seed)
        psk = ctypes.string_at(psk_pointer, RAINBOW_PUBLICKEYBYTES + RAINBOW_SECRETKEYBYTES)
        return psk[:RAINBOW_PUBLICKEYBYTES], psk[RAINBOW_PUBLICKEYBYTES:]

    @classmethod
    def raw_sign(cls, msg: bytes, sk: bytes) -> bytes:
        cls.validate_secret_key(sk)
        sig_pointer = rainbow_lib.sign(msg, len(msg), sk)
        return ctypes.string_at(sig_pointer, 66)

    @classmethod
    def raw_verify(cls, pk: bytes, sig: bytes, msg: bytes) -> bool:
        cls.validate_public_key(pk)
        cls.validate_signature(sig)
        res_code = rainbow_lib.verify(pk, sig, msg, len(msg))
        if res_code == -1:
            raise RuntimeError('Crypto engine corrupted')
        return res_code == 1

    @staticmethod
    def validate_public_key(pk: bytes) -> None:
        if len(pk) != RAINBOW_PUBLICKEYBYTES:
            raise TypeError('Public key is invalid.')

    @staticmethod
    def validate_secret_key(sk: bytes) -> None:
        if len(sk) != RAINBOW_SECRETKEYBYTES:
            raise TypeError('Secret key is invalid.')

    @staticmethod
    def validate_signature(sig: bytes) -> None:
        if len(sig) != RAINBOW_SINATURESBYTES:
            raise TypeError('Signature is invalid.')

    def __init__(self, public_key: bytes, secret_key: bytes) -> None:
        self.validate_public_key(public_key)
        self.validate_secret_key(secret_key)
        self.public_key = public_key
        self.secret_key = secret_key

    @classmethod
    def new(cls, seed: bytes = None) -> 'RainbowCrypto':
        return cls(*cls.generate_key_pair(seed))

    def sign_message(self, msg: Union[str, bytes]) -> bytes:
        if type(msg) is str:
            msg = msg.encode()
        return self.raw_sign(msg, self.secret_key)

    def verify_message_signature(self, msg: Union[str, bytes], sig: bytes) -> bool:
        if type(msg) is str:
            msg = msg.encode()
        return self.raw_verify(self.public_key, sig, msg)

    @property
    def canonical_address(self):
        return self.public_key[:20]
