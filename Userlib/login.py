from __future__ import annotations
from hashlib import sha256
from uuid import uuid5, NAMESPACE_DNS
from Userlib.db_env import db_HL_utils as database
from Userlib.utils.security_utils.kdf import checkpw
from Userlib.utils.security_utils.Security import process_id as _process_id
from Userlib.utils.passwordless import UserTOTP


def forgot_password(username: str, email: str):  # noqa
    pass


def login(username: str, email, password: str, key: bytes):
    DB_DEFAULT = database.Database(r"C:\Users\User\PycharmProjects\pythonProject3\Userlib\db_env\databases\userf.db",
                                   'users', sha256(b"my_key").digest(), 245)

    uid = ''
    password_hash = b''
    if DB_DEFAULT.get_user(email, 'email') is not None:
        password_hash = DB_DEFAULT.get_user(email, 'email')[2]
        uid: str = DB_DEFAULT.get_user(email, 'email')[3]

    compiled_id = str(uuid5(NAMESPACE_DNS, _process_id(username, email)))
    if compiled_id != uid:
        return False, "ID mismatch."

    if not checkpw(password.encode(), key, password_hash):
        return False, "Password mismatch."

    return True


print(login('h', 'hh@lh', 'mypassyword', b'vE~co6\x92\x12\xb0\xe2\x8dq\x03\xc2O\xf4\xa6p\xc4*a`\xa5\xd9\xc7\x84\x87S\x94\xf6\xba\xc9'))
