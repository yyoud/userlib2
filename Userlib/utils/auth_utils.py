#!/usr/bin/python3

from __future__ import annotations
from validate_email import VALID_ADDRESS_REGEXP as DEFAULT_REGEX
from re import match
import string
from Userlib.utils.errors import SuspiciousActivity


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
    password: str,
    required_length: int = 8,
    restrict_common_terms: bool = None,
    require_digits: bool = None,
    require_caps: bool = None,
    require_punctuation: bool = None
):

    if len(password) < required_length:
        return False
    # too heavy to compute, possible crashing attempt. could also result in a request error.
    if len(password.encode()) > 1024:  # too heavy to compute, possible crashing attempt. could also result in a request error.
        raise SuspiciousActivity("password too long")
    if require_digits and not any(char.isdigit() for char in password):
        return False
    if require_caps and not any(char.isupper() for char in password):
        return False
    if require_punctuation and not any(char in string.punctuation for char in password):
        return False
    if (restrict_common_terms and password in ((
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "qwerty", "abc123", "password1", "111111",
        "123123", "admin", "welcome", "letmein", "sunshine",
        "iloveyou", "monkey", "football", "000000", "qwerty123"
    )) or '1234' in password):
        return False

    return True


def username_policy(username: str, min_len: int = 3, punctuation_allowed: bool = False):  # noqa: unused parameters
    if min_len < 1:
        raise ValueError("Invalid minimum length")
    if len(username) < min_len:
        return False,  "username must be %d characters." % min_len
    if not punctuation_allowed and any(i in string.punctuation for i in username):
        return False, "Punctuation not allowed."
    return True


if __name__ == "__main__":
    print(password_policy("password"))
