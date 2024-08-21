# © all rights  reserved  to yyoud 2024. (C)
# TODO: in Security finish formatted _key functions                                 last
# TODO: split security into classes in different files found in security utils      first


"""
**=====** \n
**userlib** \n
**=====** \n
**user** lib **userlib** \n
`userlib` \
lib of **users**
"""

from __future__ import annotations
from hashlib import (sha1, sha256, new)
from secrets import randbelow, token_bytes
from uuid import uuid5, NAMESPACE_DNS
from datetime import datetime
from base64 import b64encode
from Userlib.db_env import db_HL_utils as database
from Userlib.utils.auth_utils import validate_email, password_policy
from Userlib.utils.security_utils.password_hasher import hash_password, checkpw
from Userlib.utils.errors import FuckOffError
from Userlib.utils.security_utils.Security import Knox
from typing import Literal, Union


# default database path: "db_env/databases/userf.db"
# database instance from file: `Userlib/db_env/DBOperator`
DB_DEFAULT = database.Database("db_env/databases/userf.db", 'users', sha256(b"my_key").digest(), 245)

# for any security wall of this type
T_key = Union[bytes, bytearray, memoryview]
T_quadbyte = tuple[int, int, int, int]


def process_quadbyte_couple(key: T_key, quadbyte: T_quadbyte):
    if isinstance(key, bytearray):
        t_key = bytes(key)
    elif isinstance(key, memoryview):
        t_key = key.tobytes()
    else:
        t_key = key

    if not len(t_key) == 16:
        raise ValueError("key must be 16 characters long")
    for i in quadbyte:
        if not 0 <= i < 256:
            raise ValueError(f"'{i}' must be a single byte integer")

    # xor 4 times with the quadbytes
    final_value = monobyte_xor(t_key, quadbyte[0])
    for i in quadbyte[1:]:
        final_value = monobyte_xor(final_value, i)

    return sha256(final_value).hexdigest()


def process_email_and_username(email: str, username: str) -> str:
    # prepare values for the hashing
    domains = email.split('@')
    combined_domains = ''.join(domains).encode()
    xored_username = monobyte_xor(username.encode(), (len(username)**2) % 256)  # xored for the extra uniqueness

    hashed_value = sha1(combined_domains+xored_username).digest()
    half_length = len(hashed_value) // 2

    first_half_int = int.from_bytes(hashed_value[:half_length], 'big')
    second_half_int = int.from_bytes(hashed_value[half_length:], 'big')

    # combined in a unique way to cause an avalanche effect
    combined_integer = (first_half_int & second_half_int) ^ (second_half_int | first_half_int)

    byte_length = (combined_integer.bit_length() + 7) // 8
    combined_bytes = combined_integer.to_bytes(byte_length, 'big')
    base64_encoded = b64encode(combined_bytes).decode()
    return base64_encoded


def secure_randint(a: int, b: int):
    return randbelow(b-a+1)+a


def monobyte_xor(data: bytes, monobyte: int) -> bytes:
    if not (0 <= monobyte < 256):
        raise ValueError("monobyte must be between 0 and 255")
    # Apply XOR operation byte by byte
    return bytes(byte ^ monobyte for byte in data)


# NOT finished, not tested yet
class User:
    """
    instance for users to user IDK bro
    """
    user_count = 0
    existing_emails = set()
    users = {}

    def __init__(self, username: str, email: str, password: str) -> None:
        self.__password = password  # type: ignore
        self.username = username.replace(' ', '')
        self._algo = 'default'

        # how to use the property functions IDK. but I'll figure it out

        # don't delete, although seems not a good idea, serves as the static value of the hashed password.
        # that is used in cases where needed.
        self.__hashed_password = self.hash_password(password.encode())
        if validate_email(email)[0]:
            self.email = email
        else:
            raise ValueError("Invalid email")

        self.id = uuid5(NAMESPACE_DNS, self._process_id_raw())
        User.existing_emails.add(self.email)
        User.user_count += 1
        self.counter = User.user_count

    def __str__(self):
        return f"User(username={self.username}, email={self.email}, id={self.id})"

    def __eq__(self, other):
        if not isinstance(other, User):
            raise ValueError(other)
        return self.id == other.id

    def __update__(self, field: str, update: str, proof: any):
        # temporary
        if field not in ['email', 'password']:
            raise ValueError(field)
        if field == "password":
            # corrected for future:
            # if self.checkpw(proof)
            if proof == self.__password:
                if password_policy(update)[0]:
                    self.__password = update
                    self.__hashed_password = hash_password(b'')
                pass
        pass

    # the 'hash password' function can be configured using the algorithm property
    # creating a hashlib.new object

    def hash_password(self, password: bytes | bytearray | memoryview, salting_idx: bool = True):
        salt = b''
        if salting_idx:
            salt = token_bytes(16)
        if self._algo == 'default':
            return hash_password(password, salting_idx=salting_idx)
        else:
            return new(self._algo, password + salt)

    @property
    def algorithm(self):
        return self._algo

    @algorithm.setter
    def algorithm(self, algo: str):
        self._algo = algo

    @algorithm.deleter
    def algorithm(self):
        self._algo = 'default'

    def _process_id_raw(self) -> str:
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

    #  can't be used as a "passwordless" function, as it doesn't implement a zero knowledge proof mechanism.
    def new_password(self, proof, new_password):
        if proof == self.__password:
            self.__password = new_password
            self.__hashed_password = hash_password(new_password)


# not yet finished
class Manager:
    """only managers have access to the database. shall not be integrated with the `user` class,
    as the integration could cause a security risk for an impersonation or something like that"""
    managers_info = {}
    banned_users = set()

    def __init__(self, key: T_key, quadbyte: T_quadbyte):
        if isinstance(key, bytearray):
            t_key = bytes(key)
        elif isinstance(key, memoryview):
            t_key = key.tobytes()
        else:
            t_key = key

        if not len(t_key) == 16:
            raise ValueError("key must be 16 characters long")
        for i in quadbyte:
            if not 0 <= i < 256:
                raise ValueError(f"'{i}' must be a single byte integer")

        # xor 4 times with the quadbytes
        final_value = monobyte_xor(t_key, quadbyte[0])
        for i in quadbyte[1:]:
            final_value = monobyte_xor(final_value, i)

        self._key = sha256(final_value).hexdigest()
        self.inspections = []

    def _verify_manager(self, key: T_key, quadbyte: T_quadbyte):
        final_value = process_quadbyte_couple(key, quadbyte)
        if final_value == self._key:
            return True
        return False

    def inspect_user(self, key: T_key, quadbyte: T_quadbyte, inspected_field: str, reasoning: str, identifier: str, method: Literal["idu"] = 'idu'):
        # only supports id inspections for now as it is the only unique attribute.
        if self._verify_manager(key, quadbyte):
            self.inspections.append(Manager.inspection(inspected_field, reasoning, identifier, self._key))
            return DB_DEFAULT.get_user(identifier, method)

    def ban_user(self, key: T_key, quadbyte: T_quadbyte, uid):
        if self._verify_manager(key, quadbyte):
            Manager.banned_users.add(uid)

    def verify_user(self, key: T_key, quadbyte: T_quadbyte, idu, password):
        if self._verify_manager(key, quadbyte):
            hashed_password = DB_DEFAULT.get_user(idu)[2]  # returns (username, email, hash, idu)
            if len(password.split('$')) == 4:
                return checkpw(password, hashed_password)
            else:
                raise FuckOffError("fuck off nigga deal with your costume hashing yourself")

    @staticmethod
    def inspection(inspected_field: str, reasoning: str, inspected_id, manager_key: str):
        """returns the tuple of the field, inspected user's id, _key of manager, timestamp"""
        timestamp = datetime.now().timestamp()
        return inspected_field, reasoning, inspected_id, manager_key, timestamp


if __name__ == "__main__":
    useruseruseruser = User("mynameis", "mailymail@example.example", "passypass123")
    print(b64encode(Knox.encryptbynumberform(b"h364oby364ovum", b"12", 1, b"1234567890123456")).decode())
    # print(User.hash_password("hello"))
    print(Knox.kexe("hello", 254))
    print(b64encode((int.from_bytes(b"hello", "big") ^ 254).to_bytes(len(b"hello"), "big")).decode())
    User("", "c@c.c", "abcdef").algorithm = "sha256"
