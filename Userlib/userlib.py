#!/usr/bin/python3
# all rights reserved to yyoud 2024. (c)
# THIS PROJECT HAS NO PLANS I'M CODING WHATEVER COMES TO MIND
"""
TODO:
    -- develop the key auth in the db and develop that low level db control file already \n
    -- make the passwordless thing already. (idk if i can,  i might be using my nemesis here (flask))
"""

from __future__ import annotations
from hashlib import (sha1, sha256, sha3_256, new)
import hmac  # to not confuse with hashlib.new
from secrets import token_bytes
from uuid import uuid5, NAMESPACE_DNS, UUID
from datetime import datetime
from base64 import b64encode, b64decode
from Userlib.db_env import db_HL_utils as database
from Userlib.utils.auth_utils import validate_email, password_policy, username_policy
from Userlib.utils.security_utils.kdf import kdf, checkpw
from Userlib.utils.security_utils.Security import ToolKit, refine_to_bytes  # noqa
from Userlib.utils.security_utils.bitwise import *
from typing import Literal, Union
import abc


# default database path: "db_env/databases/userf.db"
# database instance from file: `Userlib/db_env/db_HL_utils`
DB_DEFAULT = database.Database("db_env/databases/userf.db", 'users', sha256(b"my_key").digest(), 245)

# for any security wall of this type
Buffer = Union[bytes, bytearray, memoryview]
_T_qb = tuple[int, int, int, int]


def process_quadbyte_based(key: Buffer, quadbyte: _T_qb, token: Buffer = None, base: Literal[16, 64] = 16):
    t_key = refine_to_bytes(key)
    # required length increased to 32 bytes
    if not token and not len(t_key) == 16:
        raise ValueError("Key must be 16 characters long")
    for i in quadbyte:
        if not 0 <= i < 256:
            raise ValueError(f"'{i}' must be a single byte integer")

    # xor 4 times with the quadbytes
    final_key = monobyte_xor(t_key, quadbyte[0])
    for i in quadbyte[1:]:
        final_key = monobyte_xor(final_key, i)

    if token:
        if not len(t_key) == 32:
            raise ValueError("Key must be 32 characters long when using a token.")
        mac = hmac.new(final_key, token, sha3_256)
        for i in quadbyte:
            mac.update(monobyte_xor(token, (i+len(token)) % 256))
        if base == 16:
            return mac.hexdigest()
        return b64encode(mac.digest()).decode()

    # changed to sha 3
    if base == 64:
        return b64encode(sha3_256(final_key).digest()).decode()
    return sha3_256(final_key).hexdigest()


# not finished, as in still has new features coming probably.
class User:
    """
    instance for users to user IDK bro
    """
    user_count = 0
    existing_emails = set()
    users = {}

    def __init__(self, username: str, email: str, password: str) -> None:
        # I will use the username policy when finished
        if not username_policy(username):
            raise ValueError(username_policy(username)[1])
        self.username = username
        self._algo = 'default'

        # don't delete, although seems not a good idea, serves as the static value of the hashed password.
        # that is used in cases where needed.

        if email in User.existing_emails:
            raise ValueError("There is already an account using this email")
        if validate_email(email)[0]:
            self.email = email
        else:
            raise ValueError("Invalid email")

        self.id = uuid5(NAMESPACE_DNS, self.__process_id_raw())
        # used to log the id in the database, as an integer primary key. could be reverted using UUID(int=self.int_id)
        self.warnings = []
        self.logins = []
        self.bans = []
        self._banned = None
        User.existing_emails.add(self.email)
        User.user_count += 1
        self.__counter = User.user_count
        self.__countermod = (self.__counter**2 % 3)+1
        self.__hashed_password = self.__hash_password(password.encode())

    def __str__(self):
        # identifies user with all public variables.
        return f"User(username={self.username}, email={self.email}, id={self.id})"

    def __eq__(self, other):
        if not isinstance(other, User):
            raise TypeError(other)
        return self.id == other.id

    def __ne__(self, other):
        if not isinstance(other, User):
            raise TypeError(other)
        return not self.__eq__(other)

    def __update__(self, field: str, update: str, proof: any):
        # temporary
        if field not in ['email', 'password']:
            raise ValueError(field)
        if field == "password":
            # corrected for future:
            # if self.checkpw(proof)
            if checkpw(proof, self.__derive_final_key(self.__countermod), self.__hashed_password):
                if password_policy(update)[0]:
                    self.__hashed_password = self.__hash_password(update.encode())
                pass
        pass

    # the 'hash password' function can be configured using the algorithm property
    # creating a hashlib.new object

    def __hash_password(self, password: bytes | bytearray | memoryview, salting_idx: bool = True):
        salt = b''
        if salting_idx:
            salt = token_bytes(16)

        if self._algo == 'default':
            return kdf(password, 1, self.__derive_final_key(self.__countermod), salting_idx=salting_idx)
        else:
            return new(self._algo, password + salt)

    @property
    def hashing_fn(self):
        return self._algo

    @hashing_fn.setter
    def hashing_fn(self, algorithm: str):
        self._algo = algorithm

    @hashing_fn.deleter
    def hashing_fn(self):
        del self._algo
        self._algo = 'default'

    @property
    def banned(self):
        return self._banned

    @banned.setter
    def banned(self, value):
        if isinstance(value, bool):
            self._banned = value

    @property
    def hashed_password(self):
        return self.__hashed_password

    def __process_id_raw(self) -> str:
        # prepare values for the hashing
        domains = self.email.split('@')
        combined_domains = ''.join(domains).encode()
        xored_username = monobyte_xor(self.username.encode(), (len(self.username) ** 2) % 256)  # xored for the extra uniqueness

        hashed_value = sha1(combined_domains + xored_username).digest()
        half_length = len(hashed_value) // 2

        first_half_int = int.from_bytes(hashed_value[:half_length], 'big')
        second_half_int = int.from_bytes(hashed_value[half_length:], 'big')

        # combined in a unique way to cause an avalanche effect
        combined_integer = (first_half_int & second_half_int) ^ (second_half_int | first_half_int)

        byte_length = (combined_integer.bit_length() + 7) // 8
        combined_bytes = combined_integer.to_bytes(byte_length, 'big')
        base64_encoded = b64encode(combined_bytes).decode()
        return base64_encoded

    def __process_key_raw(self, mode: int) -> str:
        raw_id = self.__process_id_raw()
        raw_bytes = b64decode(raw_id)
        raw_int = int.from_bytes(raw_bytes, 'big')

        def process_int(_mode, _raw_int=raw_int):
            if _mode == 1:
                _processed_int = SIGMA0(_raw_int) ^ SIGMA1(_raw_int)
            elif _mode == 2:
                _processed_int = (sigma0(_raw_int) & Ch(_raw_int, _raw_int >> 1, _raw_int >> 2)) ^ \
                                (sigma1(_raw_int) & Maj(_raw_int, _raw_int >> 1, _raw_int >> 2))
            elif _mode == 3:
                _processed_int = (SIGMA0(_raw_int) ^ sigma1(_raw_int)) + (Ch(_raw_int, _raw_int >> 3, _raw_int >> 5)) - \
                                (SIGMA1(_raw_int) | Maj(_raw_int, _raw_int >> 2, _raw_int >> 4))
            else:
                raise ValueError("Mode must be 1, 2, or 3")
            return _processed_int & 0xFFFFFFFFFFFFFFFF

        processed_int = process_int(mode, raw_int)
        processed_int += process_int(((mode+1) % 3)+1, raw_int ^ (len(raw_bytes)**2 % 256))
        processed_bytes = processed_int.to_bytes((processed_int.bit_length() + 7) // 8, 'big')
        return b64encode(processed_bytes).decode()

    def __derive_final_key(self, mode: int) -> bytes:
        raw_key_derivative = self.__process_key_raw(mode)
        raw_bytes = b64decode(raw_key_derivative)
        raw_int = int.from_bytes(raw_bytes, 'big')

        def refine_key(_mode, _raw_int):
            if _mode == 1:
                _refined_int = SIGMA0(_raw_int) ^ SIGMA1(_raw_int) ^ Maj(_raw_int, _raw_int >> 2, _raw_int >> 4)
            elif _mode == 2:
                _refined_int = (sigma0(_raw_int) | Ch(_raw_int, _raw_int >> 2, _raw_int >> 3)) ^ \
                               (sigma1(_raw_int) ^ Maj(_raw_int, _raw_int >> 3, _raw_int >> 1))
            elif _mode == 3:
                _refined_int = (SIGMA0(_raw_int) - sigma1(_raw_int)) ^ (Ch(_raw_int, _raw_int >> 4, _raw_int >> 7)) + \
                               (SIGMA1(_raw_int) & Maj(_raw_int, _raw_int >> 1, _raw_int >> 3))
            else:
                raise ValueError("Mode must be 1, 2, or 3")
            return _refined_int & 0xFFFFFFFFFFFFFFFF

        refined_int = refine_key(mode, raw_int)
        refined_bytes = refined_int.to_bytes((refined_int.bit_length() + 7) // 8, 'big')

        intermediate_key = sha1(refined_bytes).digest()
        xor_key = monobyte_xor(intermediate_key, len(refined_bytes) ** 2 % 256)

        for _ in range(1000):
            xor_key = sha1(xor_key).digest()
            xor_key = monobyte_xor(xor_key, len(refined_bytes) % 256)

        final_key = sha3_256(xor_key).digest()
        return final_key

    #  can't be used as a "passwordless" function, as it doesn't implement a zero knowledge proof mechanism.
    def new_password(self, proof, new_password):
        if checkpw(proof.encode(), self.__derive_final_key(self.__countermod), self.__hashed_password):
            self.__hashed_password = self.__hash_password(new_password.encode())


class AbstractUser(abc.ABC):
    # **UNDER DEVELOPMENT**
    # abstract user for creating abstract user spaces and arrays.
    # the normal User class should be used when a defined user is needed, such as in a platform when
    # structured user registration is needed. when using an abstract user, you need to create a userspace of your own,
    # as well as everything else as the abstract user isn't supported in this version of the code
    #
    # used in cases where memory efficiency is needed and operates as a skeleton that redirects registration to
    # the database directly
    pass


# not yet finished
class Manager:
    """only managers have access to the database. shall not be integrated with the `user` class,
    as the integration could cause a security risk for an impersonation or something like that"""
    managers_info = {}
    banned_users = set()

    def __init__(self, key: Buffer, quadbyte: _T_qb, token: Buffer = None):
        if token:
            self._key = process_quadbyte_based(key, quadbyte, token)
        else:
            self._key = process_quadbyte_based(key, quadbyte)
        self._inspections = []

    def _verify_manager(self, key: Buffer, quadbyte: _T_qb):
        final_value = process_quadbyte_based(key, quadbyte)
        if final_value == self._key:
            return True
        return False

    @property
    def inspection(self):
        return self._inspections

    @inspection.setter
    def inspection(self, value):
        if isinstance(value, tuple):
            if value == tuple[str, str, UUID, str, float]:
                self._inspections.append(value)

    @property
    def key(self):
        return self._key

    def inspect_user(self, key: Buffer, quadbyte: _T_qb, inspected_field: str, reasoning: str, identifier: str, method: Literal["uid"] = 'uid'):
        # only supports id inspections for now as it is the only unique attribute.
        if self._verify_manager(key, quadbyte):
            self.inspection = Manager.inspection_type(inspected_field, reasoning, identifier, self._key)
            return DB_DEFAULT.get_user(identifier, method)

    def ban_user(self, key: Buffer, quadbyte: _T_qb, reasoning: str, user: User):
        if self._verify_manager(key, quadbyte):
            Manager.banned_users.add(str(user.id))
            user.banned = True
            user.bans.append(Manager.ban_type(reasoning, str(user.id), self._key))

    def verify_user(self, key: Buffer, quadbyte: _T_qb, uid, password: Buffer, __hash_key: bytes):
        if self._verify_manager(key, quadbyte):
            hashed_password = DB_DEFAULT.get_user(uid)[2]  # returns (username, email, hash, uid)
            if len(hashed_password.split('$')) == 4:
                return checkpw(password, key, hashed_password)
            else:
                return False

    @staticmethod
    def inspection_type(inspected_field: str, reasoning: str, inspected_id: UUID, manager_key: str):
        """returns the tuple of the field, inspected user's id, _key of manager, timestamp"""
        timestamp = datetime.now().timestamp()
        return inspected_field, reasoning, inspected_id, manager_key, timestamp

    @staticmethod
    def ban_type(reasoning: str, banned_id: UUID, manager_key: str):
        timestamp = datetime.now().timestamp()
        return reasoning, banned_id, manager_key, timestamp


if __name__ == "__main__":
    useruseruseruser = User("mynameis", "mailymail@example.example", "passypass123")
    print(b64encode(ToolKit.encryptbynumberform(b"h364oby364ovum", b"12", 1, b"1234567890123456")).decode(), "\n")
    print(ToolKit.kexe("hello", 254))
    print(b64encode((int.from_bytes(b"hello", "big") ^ 254).to_bytes(len(b"hello"), "big")).decode(), "\n")
    print(process_quadbyte_based(b"1234567890123456", (23, 24, 252, 26)))
    print(process_quadbyte_based(b'1234567890123456', (22, 23, 251, 25)), "\n")
    print(refine_to_bytes(bytearray([12, 34, 56, 78, 90])), "refine to bytes\n")
    # print(process_quadbyte_based(b"12345678901234567890123456789012", (0, 0, 2, 0), b"2"))
    key1 = sha256(b'examplekey123456').digest()
    quadbyte1 = (0x1, 0x2, 0x3, 0x4)
    token1 = b'token123456789012345678901234567890'

    key2 = sha256(b'another123456').digest()
    quadbyte2 = (0x5, 0x6, 0x7, 0x8)
    token2 = b'differentiation5678901234567890123456'

    print(process_quadbyte_based(key1, quadbyte1, token1))
    print(b64encode(bytes.fromhex("97c2b0ff5de6fe7d562f0475fff598be006afa57b7b7109457e737017e95cf0b")).decode())
    print(process_quadbyte_based(key1, quadbyte1, token1, 64))
    print(process_quadbyte_based(key2, quadbyte2, token2), end='\n\n')
