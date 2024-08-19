from __future__ import annotations
from validate_email import VALID_ADDRESS_REGEXP as DEFAULT_REGEX
from re import match
import string
from typing import TYPE_CHECKING
from array import array
from mmap import mmap

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer


def validate_email(email: str, regex: str | None = None):
    """
    A function that validates emails to check that they follow the protocol of `validate email` module


    :parameter email: email to validate
    :parameter regex: optional costume regex to check email

    :return: tuple of: (email validation(True/False), email).
    """
    email_regex = DEFAULT_REGEX if not regex else regex
    _match = match(email_regex, email)
    if _match:
        return True, email
    return False, email


def password_policy(
    password: str | ReadableBuffer,
    required_length: int = 8,
    require_digits: bool = None,
    require_caps: bool = None,
    require_punctuation: bool = None
):
    if isinstance(password, (bytes, bytearray)):
        password = password.decode('utf-8')
    elif isinstance(password, (array, mmap)):
        password = ''.join(chr(c) for c in password)
    elif isinstance(password, memoryview):
        password = password.tobytes().decode()

    if len(password) < required_length:
        return False
    if require_digits and not any(char.isdigit() for char in password):
        return False
    if require_caps and not any(char.isupper() for char in password):
        return False
    if require_punctuation and not any(char in string.punctuation for char in password):
        return False

    return True


if __name__ == "__main__":
    print(password_policy(bytearray(b"niggerass")))
