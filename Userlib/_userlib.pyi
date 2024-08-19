# © all rights  reserved  to Ziv Nathan 2023. (C)

from typing import Any
import hashlib

__all__ = [
    "Database",
    "SecurityMethods",
    "Email",
    "Password",
    "User",
    "Admin",
    "userlib"
]

class Database:
    @staticmethod
    def add_user(_user: User)-> None: ...

    @staticmethod
    def get_user_by_username(username: Any) -> User | list[str | None]: ...

    @staticmethod
    def get_user_by_email(email: Any) -> list[str | None]: ...

    @staticmethod
    def delete_all_users()-> None: ...

class SecurityMethods:
    @staticmethod
    def random_string() -> str: ...

    @staticmethod
    def key_generator(constant: int, size_general_i: bool, size_general_ii: bool) -> str: ...

    @staticmethod
    def generate_constant() -> int: ...

    @staticmethod
    def generate_key(key_type: {__eq__}, security_level: int = 1, **kwargs: Any) -> str | None | int | list: ...

    @staticmethod
    def costume_hash(password: str | bytes = ...,
                     _type: type = ...,
                     encrypting_method: str | None = None,
                     hashing_method: str | object | None = hashlib.sha3_384(),
                     salt: str | bytes | None = None
                     ) -> str | int | bytes: ...

class Email:
    def __new__(cls, value: Any) -> Email | None: ...

class Password:
    def __new__(cls, value: {__new__}) -> Password | None: ...

class User:
    user_count: int = 0
    existing_usernames: set = set()
    existing_emails: set = set()

    def __init__(self,
                 username: str | None,
                 email: str | Email,
                 password: str | Password,
                 _id: str | int | None = None,
                 nickname: str | None = None) -> None: ...

    def __str__(self)-> str: ...

    def hash_password(self, hashing_constant: {__eq__}) -> str: ...

    def new_password(self, verify_password: {__eq__}, new_password: Any, new_hashing_constant: Any = None) -> str: ...

    def new_email(self, verify_password: {__eq__}, change_login: Any) -> Any: ...

    def register(self) -> Any: ...

    def validate_email(self, email: str | None) -> list[bool | str | Email] | list[bool | None]: ...

    def password_policy(self, password: str | Password | None, index: bool = False) -> bool | list[bool | str | Password]: ...

# not finished
class Admin:
    admins_usernames: list[str] = ['סלאח שבתי']

    def __init__(self,
                 _user: User,
                 admin_index: str | int | bool,
                 admin_hash: str | bytes,
                 admin_constant: int,
                 add_admins: str | list[str, str] | None) -> None: ...

    def admin(self, inspect_user: str) -> User | list[str | None]: ...

