#!/usr/bin/python3
# all rights reserved to yyoud 2024. (c)
from __future__ import annotations
from hashlib import sha3_256, pbkdf2_hmac, new, sha1, sha3_384
from secrets import token_bytes
from base64 import b64encode, b64decode
from Userlib.utils.security_utils.Security import (ToolKit, DEFAULT_COST, DEFAULT_SALT_SIZE, VALID_ENCRYPTION_TYPE,
                                                   Buffer, refine_to_bytes)
from Userlib.utils.security_utils.bitwise import *
from colorama import Fore, init
import hmac
from blake3 import blake3


__all__ = ["kdf", "checkpw", "costume_hashing", "costume_checkpw"]


# fuck that secure storage nothing fucking works
__pepper = "plz give me money +K/G1qt4yGKArG98O59HQ0GqMEqApYxGH9l5Llil-b1ZOEw7vv26oPTcYs6jFVmnMBz2gOzgMKw==-+K/G1qsXniyTooDDVTd6dFkZmI/WzEBBInlCFlSO-+K/G1qt/3m6Tru//f79/d1m7uM/W7cxHP/l7Plyv"


# ** THE PEPPER ABOVE IS AN EXAMPLE OK LEAVE ME ALONE **
# fully tested
def kdf(password: Buffer,
        prefix: VALID_ENCRYPTION_TYPE,
        key: bytes,
        cost=DEFAULT_COST,
        salt_size=DEFAULT_SALT_SIZE,
        salting_idx: bool = False,
        salt: bytes = None) -> str:
    """
    a secure kdf for type ``User``
    :arg key: key of encryption for matching purposes\
    :param password: password \
    :param salt_size: size of salt in bytes if salt is none \
    :param prefix: encrypting prefix and format provider \
    :param cost: time cost \
    :param salting_idx: generates random salt if true or uses the given salt \
    :param salt: pre-given salt for password-matching purposes \
    :return: hashed password
    """
    if salt_size < 0:
        raise ValueError("Salt size must be grater or equal to 0")

    _key = token_bytes(16) if not key else key
    padbyblocksize = lambda data, block_size: data + (b"\x80" + b'\x00' * (block_size - (len(data) % block_size)-1))

    password_e = refine_to_bytes(password)
    password_b = padbyblocksize(password_e, 64)

    blocks = [password_b[i:i + 64] for i in range(0, len(password_b), 64)]  # Divide padded_data into blocks of 64 bytes

    # ensure at least two blocks
    if len(blocks) < 2:
        blocks.append(monobyte_xor(password_b, len(password_b) % 256))
    hashed_blocks = []

    if salting_idx:
        uisalt = token_bytes(salt_size) if not salt else salt
    else:
        # constant salt (as much as it hurts you it also hurts me)
        uisalt = b''

    # it checks if the salt parameter is not none to make it easier to implement for dev
    if salt:
        salting_idx = True
        uisalt = salt

    for block in blocks:
        if salting_idx:
            block_with_salt = block + uisalt  # Append uisalt to the block
            reversed_block = ToolKit.reverse(block_with_salt)  # mirror bits
        else:
            block_without_salt = block
            reversed_block = ToolKit.reverse(block_without_salt)  # mirror bits  still has the info

        rotated_block = ToolKit.cbr(reversed_block, len(blocks))
        inted_block = int.from_bytes(rotated_block, "big")

        operated_block1 = SIGMA0(inted_block) ^ SIGMA1(inted_block) ^ Maj(inted_block, inted_block >> 2,
                                                                          inted_block >> 4)

        operated_block2 = (sigma0(operated_block1) | Ch(operated_block1, operated_block1 >> 2,
                                                        operated_block1 >> 3)) ^ (
                                  sigma1(operated_block1) ^ Maj(operated_block1, operated_block1 >> 3,
                                                                operated_block1 >> 1))
        operated_block3 = ((SIGMA0(operated_block2) - sigma1(operated_block2)) ^
                           (Ch(operated_block2, operated_block2 >> 4, operated_block2 >> 7)) +
                           (SIGMA1(operated_block2) & Maj(operated_block2, operated_block2 >> 1,
                                                          operated_block2 >> 3))) & 0xFFFFFFFF
        # Issue fixed.
        # The issue was making the whole fully operated block only 32 bits and a bunch of 0s.
        # Fixed by only adding the operated thing as an additive to induce more chaos,
        # rather than replacing the original block.
        fully_operated_block = int.to_bytes(operated_block3, len(rotated_block), "big")+rotated_block
        unreversed_block = ToolKit.reverse(fully_operated_block)  # un-mirror
        unrotated_block = ToolKit.cbr(unreversed_block, len(blocks), 'right')[::-1]
        # im too afraid to leave it without iterating a little bit
        # iterating makes me cu... I mean calm
        for i in range(14):
            unrotated_block = ToolKit.cbr(unreversed_block, len(blocks), 'right')[::-1]
        hashed_block = blake3(unrotated_block).digest(64)  # Hash the salted block
        hashed_blocks.append(hashed_block)  # add to list
    concatenated_hash = b"".join(hashed_blocks)
    f_hash = hmac.new(__pepper.encode(), concatenated_hash, blake3).digest()

    # iterate to make brute force expensive
    f_hash = pbkdf2_hmac('sha3_256', f_hash, uisalt, cost)

    for i in range(2*len(password)//3):  # getting hashed at the end again
        f_hash = sha3_256(f_hash).digest()
        f_hash = ToolKit.cbr(f_hash, i % len(blocks) + 2)  # added 2 to the block number to ensure more chaos in the function.

    nonce = sha1(f_hash).digest()
    if prefix == 1:
        nonce = nonce[:16]
    else:
        nonce = nonce[:12]
    # encrypt uisalt with key_b, to later extract the key_b and the uisalt
    encrpt_salt = b64encode(ToolKit.encryptbynumberform(uisalt, _key, prefix, nonce)).decode()
    encrpt_cost = b64encode(ToolKit.encryptbynumberform(str(cost).encode(), _key, prefix, nonce)).decode()

    # encode to base 64
    final_hash = b64encode(sha3_384(f_hash).digest()).decode()

    # format: <hash>$len(key_b)+prefix+encrypted cost$len(uisalt size)~uisalt size$uisalt
    # example: <hash>$2a<encrypted cost>$2~16$<uisalt>
    return f"{final_hash}${b64encode(nonce).decode()}${str(prefix) + encrpt_cost}${encrpt_salt}"


def _extract_params(hashed_password: str):
    """
    :param hashed_password: idk
    :returns: something
    """
    try:
        if len(hashed_password.split('$')) != 4:
            raise ValueError("Invalid hash")
        password_hash, nonce, prefix_plus_encrypted_cost, encrypted_salt = hashed_password.split('$')
        encrypted_cost = prefix_plus_encrypted_cost[1:]
        prefix = prefix_plus_encrypted_cost[0]
        return (password_hash,
                b64decode(nonce.encode()), prefix,
                b64decode(encrypted_cost.encode()),
                b64decode(encrypted_salt.encode()))
    except ValueError as e:
        print(f"{Fore.YELLOW}Error: {Fore.LIGHTRED_EX}{e}")
        return False


def checkpw(password: Buffer, key: bytes, __hash: str):
    """meant to fit only in type https://github.com/yyoud/userlib2"""
    try:
        params = _extract_params(__hash)
        prefix = int(params[2])
        decrypted_salt = ToolKit.encryptbynumberform(params[-1], key, prefix, nonce=params[1], operation='decrypt')
        decrypted_cost = ToolKit.encryptbynumberform(params[-2], key, prefix, nonce=params[1], operation='decrypt')
        hashed_password = kdf(password, prefix, key, int(decrypted_cost), salt_size=0, salt=decrypted_salt)
        if hashed_password == __hash:
            return True
        return False
    except ValueError as e:
        # normally means that the key was incorrect. if I'd be bored enough I'd fix it to say that.
        print(f"{Fore.YELLOW}Error Matching Password: {Fore.LIGHTRED_EX}{e}")
        return False


# less secure than the above function, but it can fit anywhere unlike the above that requires a User type
# to actually implement as intended
def _special_password_hashing_case(hash_fn_name: str,
                                   password: bytes,
                                   salt: bytes):
    # I only created this for the people who are fucking morons that have to always ruin everything
    hashed_password = new(hash_fn_name, password+b64encode(salt)).hexdigest()
    # the validation number indicates that the format of hashing is special to not fit
    # in the regular splitting format used for the better hashing above, as well as authenticating the hash.
    validation_number = (int.from_bytes(password, "big") ^ len(password)**2) % 256
    # that last thing the $# is to ensure it isn't mixed with that concept
    return f"{hash_fn_name}${validation_number}${b64encode(salt).decode()}${hashed_password}$#"


def _special_case_check_password(password: bytes, password_hash: str):
    if len(password_hash.split('$')) != 5:
        raise ValueError("Invalid hash format")

    hash_name, validation_number, salt, hashed_password, placeholder = password_hash.split('$')
    if _special_password_hashing_case(hash_name, password, b64decode(salt)) == password_hash:
        return True
    return False


def costume_hashing(hash_fn_name: str,
                    password: bytes,
                    salt: bytes):
    return _special_password_hashing_case(hash_fn_name, password, salt)


def costume_checkpw(password: bytes, password_hash: str):
    return _special_case_check_password(password, password_hash)


if __name__ == "__main__":

    # Initialize colorama
    init(autoreset=True)

    def colorize_output(hashed_password: str) -> str:
        password_hash, nonce, prefix_plus_encrypted_cost, encrypted_salt = hashed_password.split('$')

        # Colorize each part
        colored_hash = f"{Fore.BLUE}{password_hash}"
        colored_dollar = f"{Fore.GREEN}$"
        colored_nonce = f"{Fore.RED}{nonce}"
        colored_prefix_cost = f"{Fore.MAGENTA}{prefix_plus_encrypted_cost}"
        colored_salt = f"{Fore.YELLOW}{encrypted_salt}"

        # Combine the colored parts
        _colored_output = (
            f"{colored_hash}{colored_dollar}"
            f"{colored_nonce}{colored_dollar}"
            f"{colored_prefix_cost}{colored_dollar}"
            f"{colored_salt}"
        )

        return _colored_output


    # Example usage
    x = kdf(b'vraqbegqretuq35t2423t45g452tqw7hy64t3r28h7uy94rw7968yg24r122323', 1, b'poop key', salting_idx=True)
    print(checkpw(b'vraqbegqretuq35t2423t45g452tqw7hy64t3r28h7uy94rw7968yg24r122323', b'poop key', __hash=x))
    print(colorize_output(x))
    x = ToolKit.encryptbynumberform('באתי לעולם לא שאלו את פי מה אבקש ומה חפץ לבי באתי לעולם וכבר הכל קיים וכמו כולם אני רק בן אדם עייף ומאוכזב ורק חולם להיות אדם'.encode(), 'סוד המזלות'.encode(), 1, nonce=b'1234567890123456')
    y = ToolKit.encryptbynumberform(x, 'סוד המזלות'.encode(), 1, nonce=b'1234567890123456', operation='decrypt').decode()
    print(x, y, sep='\n')
