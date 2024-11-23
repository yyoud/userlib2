#!/usr/bin/python3
# all rights reserved to yyoud 2024. (c)
# TODO: in Security finish formatted key functions
# this is all shit btw I will be removing like half the code when I finish dealing with more important stuff.
from __future__ import annotations
import hmac
import base58
from os import urandom
from random import Random
from secrets import choice
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from typing import Literal, Union, Callable
from hashlib import sha3_256, sha3_512, pbkdf2_hmac
from string import ascii_letters, punctuation, digits
from base64 import b64encode as b64e, b64decode as b64d, b32encode as b32e, a85encode as a85e


__all__ = ["generate_key", "force_bytes", "addmod_encryption", "NOT_encryption", "XOR_encryption",
           "encryptbyformat", "encryptbyprefix", "ROT", "REV"]


# default and globals
DEFAULT_COST = 65536  # default iterating cost for PBKDF2
DEFAULT_SALT_SIZE = 16
VALID_PREFIX = Literal['a', 'b', 'c']
VALID_OPERATION = Literal["encrypt", "decrypt"]
VALID_ENCRYPTION_TYPE = Literal[1, 2]
Buffer = Union[bytes, bytearray, memoryview]
T_sb = tuple[int, int, int, int, int, int]


default_params = [
    DEFAULT_COST, DEFAULT_SALT_SIZE,
    VALID_PREFIX,
    VALID_OPERATION, VALID_ENCRYPTION_TYPE,
]

__all__.append(default_params)


def force_bytes(s: Buffer) -> bytes:
    if isinstance(s, memoryview):
        return s.tobytes()
    elif isinstance(s, bytearray):
        return bytes(s)
    else:
        return s


class Key:
    __domains: set[str] = set()

    def __init__(self, domain: str, key: bytes, public_key: bytes):
        # I'm thinking of making a block chaining thing for this so that it wouldn't be easy to temper with but idc
        if domain in Key.__domains:
            raise ValueError("Domain '%s' Already Taken." % domain)

        if len(key) != 32:
            raise ValueError("Key Must Be 32 Bytes Long.")
        Key.__domains.add(domain)
        self._publickey = sha3_256(public_key).digest()
        self._domain = domain
        self._mk = self._gen_mk(domain, key, self._publickey)
        self._hashes: set[str] = set()
        self._dkone: dict = {}
        self._index = 0

    __slots__ = "_mk", "_publickey", "_domain", "_hashes", "_index", "_dkone"

    @staticmethod
    def _gen_mk(domain: str, key: bytes, public_key: bytes):
        return hmac.new(key, public_key, sha3_256).digest()+b'$~'+domain.encode()

    @property
    def public_key(self):
        return self._publickey.hex()

    @property
    def domain(self):
        return self._domain

    def gen_key(self, key: bytes):
        if self._gen_mk(self._domain, key, self._publickey) != self._mk:
            raise ValueError("Invalid key.")
        subkey = urandom(32)
        k = hmac.new(subkey, self._publickey, sha3_256).digest()+b'$~'+self._domain.encode()+b'$~'+str(self._index).encode()
        self._hashes.add(hmac.new(k, key, sha3_256).hexdigest())
        self._dkone[hmac.new(k, key, sha3_256).hexdigest()] = k
        self._index += 1
        return k

    def verify_key(self, subkey: bytes, key: bytes):
        if len(subkey.split(b'$~')) != 3:
            raise ValueError("Invalid Sub-Key.")
        # if self._dkone.get(hmac.new(subkey, key, sha3_256).hexdigest(), "nigger") == subkey:
        #     return True
        if hmac.new(subkey, key, sha3_256).hexdigest() in self._hashes:
            return True
        return False

    def del_subkey(self, key: bytes, subkey: bytes):
        if self._gen_mk(self._domain, key, self._publickey) != self._mk:
            raise ValueError("Invalid key.")
        if self.verify_key(subkey, key):
            self._hashes.remove(hmac.new(subkey, key, sha3_256).hexdigest())


def XOR_encryption(data: bytes, key: bytes, iv: bytes = None, operation: str = 'encrypt') -> bytes:
    if len(key) != 32:
        raise ValueError("Invalid Key. Key must be 32 bytes.")
    if operation == 'encrypt':
        if iv and len(iv) != 16:
            raise ValueError("IV Must Be 16 Bytes Long.")
        iv = iv if iv else urandom(16)
    else:
        iv = data[:16]
        data = data[16:]
    padbyblocksize = lambda D, block_size: D + (b"\x80" + b'\x00' * (block_size - (len(D) % block_size) - 1))

    def unpadbyblocksize(D: bytes, block_size: int) -> bytes:
        if len(D) % block_size != 0:
            raise ValueError("Incorrect Padding.")
        padding_index = D.rfind(b'\x80')
        if padding_index == -1:
            return D
        if D[padding_index + 1:] != b'\x00' * (len(D) - padding_index - 1):
            raise ValueError("Invalid padding.")
        return D[:padding_index]

    dkey: Callable[[bytes, bytes, int], bytes] = \
        lambda _iv, _key, i: hmac.new(_key, _iv + bytes([i]), sha3_256).digest()

    if operation == 'encrypt':
        padded_data: bytes = padbyblocksize(data, 32)
    else:
        padded_data = data

    words: list[bytes] = [padded_data[i:i + 32] for i in range(0, len(padded_data), 32)]
    fval = []

    for i, word in enumerate(words):
        xval = bytearray()
        subkey = dkey(iv, key, i)
        for j, b in enumerate(word):
            xval.append(((~b) ^ subkey[j]) & 0xFF)
        fval.append(bytes(xval))
    result = b''.join(fval)
    if operation == 'decrypt':
        result = unpadbyblocksize(result, 32)
    if operation == 'encrypt':
        return iv + result
    return result


def addmod_encryption(data: bytes, key: bytes, operation: VALID_OPERATION = 'encrypt'):
    """stands for key embedded addmod encryption"""
    if operation == 'encrypt':
        encrypted_bytes = bytes([(b + key[i]) % 256 for i, b in enumerate(data)])
        return b64e(encrypted_bytes).decode()
    elif operation == 'decrypt':
        encrypted_bytes = b64d(data)
        decrypted_data = bytes([(b - key[i]) % 256 for i, b in enumerate(encrypted_bytes)])
        return decrypted_data.decode('utf-8')


def NOT_encryption(data: bytes, key: bytes):
    encrypted_bytes = bytes([((~b) ^ key[i % len(key)]) & 0xFF for i, b in enumerate(data)])
    return encrypted_bytes


def encryptbyprefix(data: bytes, prefix: VALID_PREFIX | str, key: bytes, operation: VALID_OPERATION = 'encrypt'):
    # prefix parameter also uses str to avoid type errors caused by expecting a Literal type.
    if isinstance(prefix, str):
        if prefix not in ['a', 'b', 'c']:
            raise ValueError(f"Invalid prefix.")

    if prefix == 'a':
        return XOR_encryption(data, key, operation=operation)
    elif prefix == 'b':
        return addmod_encryption(data, key, operation=operation)
    elif prefix == 'c':
        return NOT_encryption(data, key)


def encryptbyformat(data: Buffer, key: Buffer,
                    number: VALID_ENCRYPTION_TYPE | int, nonce: bytes = None,
                    operation: VALID_OPERATION = 'encrypt'):
    """
    encrypt with aes or ChaCha20 based on number
    :param operation: operation
    :param data: data to encrypt
    :param key: encryption key_b
    :param nonce: nonce
    :param number: encryption type: from 1, 2 translating to AES, ChaCha20 respectively
    :return: encrypted text in bytes
    """
    if isinstance(key, int):
        raise TypeError("you mixed the key and prefix again")
    if not len(key) == 32:
        # I am too lazy to ensure this, but this is secure enough, it's just to encrypt parameters of the hash.
        # So I don't care.
        key = sha3_256(key).digest()
    if number == 1:
        if len(nonce) != 16:
            raise ValueError("Nonce must be 16 bytes")
        if operation == 'encrypt':
            plaintext = AES.new(key, AES.MODE_CBC, nonce).encrypt(pad(data, AES.block_size))
            return plaintext
        else:
            plaintext = unpad(AES.new(key, AES.MODE_CBC, nonce).decrypt(data), AES.block_size)
            return plaintext
    else:
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")
        if operation == 'encrypt':
            plaintext = ChaCha20.new(key=key, nonce=nonce).encrypt(pad(data, ChaCha20.block_size))
            return plaintext
        else:
            plaintext = unpad(ChaCha20.new(key=key, nonce=nonce).decrypt(data), ChaCha20.block_size)
            return plaintext


def ROT(data: bytes, shift_amount: int, direction: Literal['left', 'right'] = 'right') -> bytes:
    """
    circular bit rotate
    :param data: data to rotate
    :param shift_amount: shift
    :param direction: left or right
    :return:
    """
    def rotate(byte: int, shift: int, _direction: str) -> int:
        if _direction == 'left':
            return ((byte << shift) | (byte >> (8 - shift))) & 0xFF
        else:
            return ((byte >> shift) | (byte << (8 - shift))) & 0xFF
    return bytes(rotate(byte, shift_amount, direction) for byte in data)


def REV(byte_string: bytes):
    """
    reverses bytes such as byte of 10100001 will be 10000101, mirrored basically
    """
    reversed_bytes = bytearray()
    for byte in byte_string:
        reversed_byte = 0
        for i in range(8):  # Since a byte has 8 bits
            if byte & (1 << i):
                reversed_byte |= (1 << (7 - i))  # Set the corresponding bit in reversed order
        reversed_bytes.append(reversed_byte)
    return bytes(reversed_bytes)


def generate_key(key_type: str, length: int, base: int = 16):
    """
    Generates random keys by type.
    Key of type `'nbase'` shall be set to bases: \n
        10, 16, 32, 58, 64, 85,
        all other will raise an error


    :param length: length of desired key_b
    :param base: used for nbase keys
    :param key_type: type of the key_b, from: 'str', 'digit', 'bin', 'nbase'
    :return: finalised key_b, matching key_b type
    """

    if base not in [10, 16, 32, 58, 64, 85]:
        raise ValueError(f"Invalid base{base}")
    charset = digits + ascii_letters + punctuation
    gen_str_key = lambda _length: ''.join(choice(charset) for _ in range(length))
    gen_digit_key = lambda _length: int(''.join(choice(digits) for _ in range(_length)))
    gen_bin_key = lambda _length: ''.join(format(byte, '08b') for byte in urandom(_length))
    gen_nbase_key = lambda _length, nbase: (lambda data: (lambda encoders: encoders.get(nbase, lambda: (_ for _ in ()))(data))({
            10: lambda d: str(int.from_bytes(d, 'big')),
            16: lambda d: d.hex(),
            32: lambda d: b32e(d).decode('utf-8').rstrip('='),
            58: lambda d: base58.b58encode(d).decode('utf-8'),
            64: lambda d: b64e(d).decode('utf-8').rstrip('='),
            85: lambda d: a85e(d).decode('utf-8').rstrip('=')}))(urandom(_length))

    if key_type == "str":
        return gen_str_key(length)
    elif key_type == 'digit':
        return gen_digit_key(length)
    elif key_type == 'bin':
        return gen_bin_key(length)
    elif key_type == 'nbase':
        return gen_nbase_key(length, base)
    else:
        raise ValueError("Invalid key type '%s'." % key_type)


def process_id(username: str, email: str) -> str:
    """
    combines the username, and email to create an id template to later be passed through uuid5.
    :return:
    """

    def monobyte_xor(data: Buffer, monobyte: int) -> bytes:
        if not (0 <= monobyte < 256):
            raise ValueError("monobyte must be between 0 and 255")
        data = force_bytes(data)
        return bytes(byte ^ monobyte for byte in data)

    domains = email.split('@')
    combined_domains = ''.join(domains).encode()
    xored_username = monobyte_xor(username.encode(), (len(username) ** 2) % 256)
    hashed_value = sha3_256(combined_domains + xored_username).digest()
    half_length = len(hashed_value) // 2
    first_half_int = int.from_bytes(hashed_value[:half_length], 'big')
    second_half_int = int.from_bytes(hashed_value[half_length:], 'big')
    combined_integer = (first_half_int & second_half_int) ^ (second_half_int | first_half_int)
    byte_length = (combined_integer.bit_length() + 7) // 8
    combined_bytes = combined_integer.to_bytes(byte_length, 'big')
    base64_encoded = b64e(hmac.new(combined_bytes, hashed_value, sha3_512).digest()).decode()
    return base64_encoded


def process_sixbyte_v2(key: Buffer, sixbyte: T_sb, token: Buffer = None,
                       base: Literal[16, 64, 'raw'] = 16,
                       cost: int = DEFAULT_COST,
                       salt_idx: bool = False,
                       salt_size: int = 16) -> tuple[bytes, bytes]:
    """
    An auth function that uses a key and 6 bytes for 2factor authentication
    :param key: key, length of 16 bytes, if ``token`` is provided the length must be 32 bytes.
    :param sixbyte: tuple of 6 integers between 0-255
    :param token: session token. a TOTP or HOTP used separately for each login session and transfer
    :param base: base of the output, either 16 (default), base 64 or 'raw' - unencoded bytes.
    :param cost: time cost, number of iterations.
    :param salt_idx:
    :param salt_size:
    :return:
    """
    # make token a session token like a nonce but more of a
    def monobyte_xor(data: Buffer, monobyte: int) -> bytes:
        if not (0 <= monobyte < 256):
            raise ValueError("monobyte must be between 0 and 255")
        data = force_bytes(data)
        return bytes(byte ^ monobyte for byte in data)

    t_key = force_bytes(key)
    salt = urandom(salt_size)
    if not salt_idx:
        salt = b''

    if not token and not len(t_key) == 16:
        raise ValueError("Key must be 16 characters long")
    for i in sixbyte:
        if not 0 <= i < 256:
            raise ValueError(f"'{i}' must be a single byte integer")

    # xor 4 times with the quadbytes
    final_key = monobyte_xor(t_key + salt, sixbyte[0])
    for i in sixbyte[1:]:
        final_key = hmac.new(monobyte_xor(final_key, i), final_key+salt, sha3_512).digest()

    if token:
        if len(t_key) != 32:
            raise ValueError("Key must be 32 characters long when using a token.")
        dkey = hmac.new(final_key, token, sha3_512).digest()
        U = dkey
        for i in sixbyte:
            dkey = hmac.new(monobyte_xor(token, (i+len(token)) % 256), dkey+salt, sha3_512).digest()
            U = bytes(A ^ B for A, B in zip(dkey, U))
        if cost >= 12:
            dkey = pbkdf2_hmac("sha3_512", dkey, U+salt, cost-11)
        else:
            dkey = pbkdf2_hmac("sha3_512", dkey, U+salt, cost)
        if base == 16:
            return dkey.hex().encode(), salt
        if base == 'raw':
            return dkey, salt
        return b64e(dkey), salt

    if cost >= 6:
        dkey = pbkdf2_hmac('sha3_512', final_key, final_key+salt, cost-5)
    else:
        dkey = sha3_512(final_key+salt)
    if base == 64:
        return b64e(dkey), salt
    return dkey.hex().encode(), salt


class SeqRand:
    def __init__(self, seed: bytes):
        self._next = b''
        self._og_seed = seed
        self._current_seed = seed
        self._rand = Random(self._og_seed)

    __slots__ = "_next", "_og_seed", "_current_seed", "_rand"

    def _derive_secondary_seed(self, seed: bytes):
        randnums = []
        for i in range(64):  # 64 pseudo random numbers
            self._next = pbkdf2_hmac('sha3_512', self._og_seed, hmac.new(seed, self._next, 'sha3_256').digest(), 1)
            self._rand.seed(self._next)
            randnums.append(self._rand.random())
        c1 = ''
        for i in randnums:
            c1 += str(i)
        self._current_seed = pbkdf2_hmac('sha3_512', bytes(a ^ b for a, b in zip(c1.encode(), self._next)), hmac.new(seed, self._next, 'sha3_256').digest(), 1)
        return self._current_seed

    def seed(self, key: bytes):
        self._derive_secondary_seed(key)
        self._rand.seed(self._current_seed)

    def _reseed(self):
        self._next = self._current_seed
        self._current_seed = self._derive_secondary_seed(self._next)
        self._rand.seed(self._current_seed)

    def randint(self, a, b):
        self._reseed()
        return self._rand.randint(a, b)

    def randrange(self, start: int, stop: int | None = None, step: int = 1):
        self._reseed()
        return self._rand.randrange(start, stop, step)

    def random(self):
        self._reseed()
        return self._rand.random()


if __name__ == "__main__":
    sss = b'\x0f\xffB\xff\x0f\xe7M\xe2-\xc4S\x18\xe8}\xba\xe6\x8f\x11\x15K\xe2\x19\xd1$\x8d\x1e\xdd\xacxp\x13f'
    sssss = Key("her", sss, b"hello world")
    x = sssss.gen_key(sss)
    print(b64e(x).decode())
    y = input("x: ")
    print(sssss.verify_key(b64d(y.encode()), sss))
    print(y.encode())
