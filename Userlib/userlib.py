#!/usr/bin/python3
# all rights reserved to yyoud 2024. (c)
"""
TODO:
    -- develop the key auth in the db and develop that low level db control file already; WOULD NOT HAPPEN PROBABLY. \n
    -- develop db_HL_utils with the table initializer and costume fields. \n
    -- make the passwordless thing already; CURRENT WORK, IN PROGRESS. \n
    -- make the user fetch from the db instead of keeping vars; IN PROGRESS, ONE DAY. \n
    -- further develop the encryption mechanisms in Security; NO TIME FOR THAT CURRENTLY. \n
    -- move all the key deriving functions away from User into the security section; PRETTY MUCH DONE.
"""

from __future__ import annotations
import abc
import hmac
from os import urandom
from datetime import datetime
from typing import Literal, Union, Any
from uuid import uuid5, NAMESPACE_DNS, UUID
from hashlib import sha256, pbkdf2_hmac, sha3_512
from Userlib.utils.passwordless import UserTOTP  # noqa
from Userlib.db_env import db_HL_utils as database
from base64 import b64encode as b64e, b64decode as b64d
from Userlib.utils.security_utils.kdf import TKBKDF, checkpw
from Userlib.utils.security_utils.bitwise import operator, monobyte_xor
from Userlib.utils.auth_utils import validate_email, password_policy, username_policy
from Userlib.utils.security_utils.Security import DEFAULT_COST, process_id as _process_id, process_sixbyte_v2

DB_DEFAULT = database.Database(r"C:\Users\User\PycharmProjects\pythonProject3\Userlib\db_env\databases\userf.db",
                               'users', sha256(b"my_key").digest(), 245)

Buffer = Union[bytes, bytearray, memoryview]
T_sb = tuple[int, int, int, int, int, int]


class User:
    """
    instance for users. takes sufficient amount of memory, so for large datasets consider using ``AbstractUser``.
    """
    user_count = 0
    existing_emails = set()

    def __init__(self, username: str, email: str, password: str, **kwargs) -> None:  # noqa
        up = username_policy(username)
        if isinstance(up, tuple):
            if not up[0]:
                raise ValueError(username_policy(username)[1])
        self.username = username

        if email in User.existing_emails:
            raise ValueError("There is already an account using this email")
        if validate_email(email)[0]:
            self.email = email
        else:
            raise ValueError("Invalid email")

        self.id = uuid5(NAMESPACE_DNS, _process_id(self.username, self.email))
        self._warnings = []
        self._logins = []
        self._bans = []
        self._banned = 0
        User.existing_emails.add(self.email)
        User.user_count += 1
        self.__counter = User.user_count
        self._countermod = (self.__counter**2 % 3)+1
        self.__hashed_password = self._hash_password(password.encode())
        self.logged_in = 0  # temporary value
        DB_DEFAULT.add_user(self.username, self.email, self.__hashed_password, str(self.id), self._banned)

    __slots__ = ("username", "email", "id", "_warnings", "_logins", "_bans", "_banned",
                 "__counter", "__countermod", "__hashed_password", "logged_in")

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

    def __update__(self, field: Literal["password", "email"], update: str, proof: bytes):
        """update a field of a user"""
        if field not in ('email', 'password'):
            raise ValueError("Invalid Field '%s'" % field)

        if checkpw(proof, self._session_key(proof, self._countermod), self.__hashed_password):
            auth_index = True
        else:
            raise ValueError("Incorrect password.")

        if field == "password":
            if password_policy(update) and auth_index:
                self.__hashed_password = self._hash_password(update.encode())
                return
            else:
                raise ValueError("Failed Updating Password.")
        elif field == "email":
            if validate_email(update)[0] and auth_index:
                self.email = validate_email(update)[1]
                return
            else:
                raise ValueError("Failed Updating Email.")

    # the 'hash password' function can be configured using the algorithm property
    # creating a hashlib.new object
    def _hash_password(self, password: Buffer, salting_idx: bool = True, salt: bytes = None):
        saltt = b''
        if salting_idx and not salt:
            saltt = urandom(16)
        elif salt:
            saltt = salt

        return TKBKDF(password, 1, self._session_key(password, self._countermod), salt=saltt)

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

    @hashed_password.deleter
    def hashed_password(self):
        del self.__hashed_password

    @property
    def warnings(self):
        return self._warnings

    @property
    def logins(self):
        return self._logins

    @property
    def bans(self):
        return self._bans

    def _session_key(self, password: Buffer, mode: int) -> bytes:
        r"""
        A KDF that Defines a temporary key, created upon each login, to be logged into TKBKDF.
        :param password: password
        :param mode: 1, 2, or 3. outputs different keys, for different uses.
        for example, one for encrypting the email,
        one for the kdf and one for encrypting the phone number. might remove.
        :return:
        """
        raw_id = _process_id(self.username, self.email)
        raw_bytes = b64d(raw_id)
        raw_int = int.from_bytes(raw_bytes, 'big')
        if mode in (1, 2, 3):
            processed_int = operator(raw_int, mode)
        else:
            raise ValueError("Invalid Option.")
        for i in range(64):
            processed_int += operator(((mode + 1) % 3) + 1, raw_int ^ (len(raw_bytes) ** 2 % 256))
        processed_bytes = processed_int.to_bytes((processed_int.bit_length() + 7) // 8, 'big')
        pp = hmac.new(processed_bytes,
                      operator(3, processed_int).to_bytes(processed_int.bit_length(), "big"),
                      sha3_512).digest()
        raw_key = b64e(pp).decode()
        raw_bytes = b64d(raw_key)
        raw_int = int.from_bytes(raw_bytes, 'big')
        if mode in (1, 2, 3):
            refined_int = operator(raw_int, mode)
        else:
            raise ValueError("Mode must be 1, 2, or 3")

        refined_bytes = refined_int.to_bytes((refined_int.bit_length() + 7) // 8, 'big')
        intermediate_key = sha3_512(refined_bytes).digest()
        xor_key = monobyte_xor(intermediate_key, len(refined_bytes) ** 2 % 256)

        for _ in range(64):
            xor_key = sha3_512(xor_key).digest()
            xor_key = monobyte_xor(xor_key, len(refined_bytes) % 256)
        temp = hmac.new(xor_key, password, 'sha3_512').digest()
        final_key = pbkdf2_hmac('sha3_256', xor_key, temp, DEFAULT_COST)
        return final_key

    #  can't be used as a "passwordless" function, as it doesn't implement a zero knowledge proof mechanism.
    def new_password(self, proof: str, new_password: str):
        if checkpw(proof.encode(), self._session_key(proof.encode(), self._countermod), self.__hashed_password):
            self.__hashed_password = self._hash_password(new_password.encode())
        else:
            print(self._session_key(proof.encode(), self._countermod))

    def gen_otp(self, interval: int = 30):
        # o = _totp.OTP(b32e(self._derive_key(self.__hashed_password.encode(), 3)).decode(), digest=sha3_256)
        # print(o.generate_otp(self.__countermod))
        pass

    def pack(self):
        """
        creates a json file from the user data.
        :return:
        """
        pass


class AbstractUser(abc.ABC):
    # **UNDER DEVELOPMENT**
    # abstract user for creating abstract user spaces and arrays.
    # the normal User class should be used when a defined user is needed, such as in a platform when
    # structured user registration is needed. when using an abstract user, you need to create a userspace of your own,
    # as well as everything else as the abstract user isn't supported in this version of the code
    #
    # used in cases where memory efficiency is needed and operates as a skeleton that redirects registration to
    # the database directly
    uid: UUID
    username: str
    email: str
    __hashed_password: str

    @abc.abstractmethod
    def __init__(self, username, email, password, **kwargs):  # noqa
        pass

    @abc.abstractmethod
    def __str__(self):
        pass

    @abc.abstractmethod
    def _hash_password(self, password: Any, *args, **kwargs):
        pass

    @abc.abstractmethod
    def login(self, username, email, password):
        """login into account"""
        pass
    pass


# under development
# might remove in favour of administrator. in a different file. files now will be more sophisticated,
class Manager:
    """
    Class for managing users by database
    """

    def __init__(self, key: Buffer, sixbyte: T_sb, token: Buffer = None):
        if token:
            self._key = process_sixbyte_v2(key, sixbyte, token)
        else:
            self._key = process_sixbyte_v2(key, sixbyte)
        self._inspections = []

    async def _verify_manager(self, key: Buffer, sixbyte: T_sb):
        final_value = process_sixbyte_v2(key, sixbyte)
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

    def inspect_user(self, key: Buffer, sixbyte: T_sb, inspected_field: str, reasoning: str, identifier: str, method: Literal["uid"] = 'uid'):
        # only supports id inspections for now as it is the only unique attribute.
        if self._verify_manager(key, sixbyte):
            self.inspection = Manager.inspection_type(inspected_field, reasoning, identifier, self._key)
            return DB_DEFAULT.get_user(identifier, method)

    def ban_user(self, key: Buffer, sixbyte: T_sb, reasoning: str, user: User):
        if self._verify_manager(key, sixbyte):
            Manager.banned_users.add(str(user.id))
            user.banned = True
            user.bans.append(Manager.ban_type(reasoning, str(user.id), self._key))

    def verify_user(self, key: Buffer, quadbyte: T_sb, uid, password: Buffer, __hash_key: bytes):
        if self._verify_manager(key, quadbyte):
            hashed_password = DB_DEFAULT.get_user(uid)[2].encode()  # returns (username, email, hash, uid)
            return checkpw(password, key, hashed_password)

    @staticmethod
    def inspection_type(inspected_field: str, reason: str, inspected_id: UUID, manager_key: str):
        """returns the tuple of the field, inspected user's id, _key of manager, timestamp"""
        timestamp = datetime.now().timestamp()
        return inspected_field, reason, str(inspected_id), manager_key, timestamp

    @staticmethod
    def ban_type(reasoning: str, banned_id: UUID, manager_key: str):
        timestamp = datetime.now().timestamp()
        return reasoning, banned_id, manager_key, timestamp


if __name__ == "__main__":
    print(process_sixbyte_v2(b'12345678901234567890123456789012', (1, 2, 3, 4, 5, 6), b'token'))
    print(process_sixbyte_v2(b'1234567890123456', (1, 2, 3, 4, 5, 6), ))
