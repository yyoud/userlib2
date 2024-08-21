from __future__ import annotations
from hashlib import sha3_256, pbkdf2_hmac
from secrets import token_bytes, randbelow
from base64 import b64encode
from string import ascii_letters, digits, punctuation
from secrets import choice
from Userlib.utils.security_utils.Security import (
    Knox, DEFAULT_PREFIX, DEFAULT_COST, DEFAULT_SALT_SIZE,
    VALID_PREFIX, ReadableBufferNonExtensive)

__all__ = ["hash_password", "checkpw"]


# I could not import from userlib because of circular imports! what a disappointment to copy paste bro
# TODO: move the Knox class from userlib to another file to prevent this

def hash_password(password: ReadableBufferNonExtensive,
                  prefix: VALID_PREFIX = DEFAULT_PREFIX,
                  cost=DEFAULT_COST,
                  salt_size=DEFAULT_SALT_SIZE,
                  salting_idx: bool = False,
                  salt: bytes = None,
                  key: int = None) -> str:
    """
    most secure `hasher` I could build. (I am a beginner I'm not very good)
    :arg key: key_b of encryption for matching purposes\
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
    if prefix not in ['a', 'b', 'c']:
        raise ValueError("Invalid prefix")
    if isinstance(password, memoryview):
        password_e = password.tobytes()
    elif isinstance(password, bytearray):
        password_e = bytes(password)
    else:
        password_e = password
    padbyblocksize = lambda data, block_size: data + (b"\x80" + b'\x00' * (block_size - (len(data) % block_size)-1))
    _key = None
    password_b = padbyblocksize(password_e, 64)

    blocks = [password_b[i:i + 64] for i in range(0, len(password_b), 64)]  # Divide padded_data into blocks of 64 bytes
    hashed_blocks = []

    if salting_idx:
        uisalt = token_bytes(salt_size) if not salt else salt
        _key = randbelow(256) if not key else key
    else:
        uisalt = b''
        _key = 0

    if salt:
        salting_idx = True
        uisalt = salt

    for block in blocks:
        if salting_idx:
            block_with_salt = block + uisalt  # Append uisalt to the block
            reversed_block = Knox.reverse_bytes(block_with_salt)  # mirror bits
        else:
            block_without_salt = block  # I'm too lazy to change it to block without uisalt so...
            reversed_block = Knox.reverse_bytes(block_without_salt)  # mirror bits
        rotated_block = Knox.cbr(reversed_block, len(blocks))

        unreversed_block = Knox.reverse_bytes(rotated_block)  # un-mirror
        unrotated_block = Knox.cbr(unreversed_block, len(blocks), 'right')

        hashed_block = sha3_256(unrotated_block).digest()  # Hash the salted block
        hashed_blocks.append(hashed_block)  # add to list
    concatenated_hash = b"".join(hashed_blocks)
    f_hash = sha3_256(concatenated_hash).digest()

    # iterate

    f_hash = pbkdf2_hmac('sha3_256', f_hash, uisalt, cost)

    for i in range(2*len(password)//3):  # getting hashed at the end again
        f_hash = sha3_256(f_hash).digest()
        f_hash = Knox.cbr(f_hash, i % len(blocks) + 2)  # added 2 to the block number to ensure more chaos in the function.

    # encrypt uisalt with key_b, to later extract the key_b and the uisalt
    encrpt_salt = Knox.encryptbyprefix(uisalt + bytes(_key), prefix, _key)
    encrpt_cost = Knox.encryptbyprefix(str(cost), prefix, _key)

    # encode to base 64
    final_hash = b64encode(sha3_256(f_hash).digest()).decode()

    # format: <hash>$len(key_b)+prefix+encrypted cost$len(uisalt size)~uisalt size$uisalt
    # example: <hash>$2a<encrypted cost>$2~16$<uisalt>
    return f"{final_hash}${prefix + encrpt_cost}${encrpt_salt}"


def _extract_parameters(hashed_password: str):
    """
    Extract parameters from a hashed password string.

    :param hashed_password: The hashed password string to extract parameters from.
    :return: A tuple containing the extracted parameters.
    """

    hashed_pass, prefix_plus_cost, encrypted_salt = hashed_password.split('$')
    prefix = prefix_plus_cost[0]
    encrypted_cost = prefix_plus_cost[1:]  # encrypted with _key, so I'll use this to retrieve the universal _key
    decrypted_cost, universal_key = Knox.encryptbyprefix(encrypted_cost, prefix, operation='decrypt')
    decrypted_salt = Knox.encryptbyprefix(encrypted_salt, prefix, operation='decrypt')[0]

    return hashed_pass, prefix, int(decrypted_cost), decrypted_salt.encode(), universal_key


def checkpw(password: ReadableBufferNonExtensive, hashed_password: str):
    params = _extract_parameters(hashed_password)
    hashed_pw = hash_password(password, params[1], params[2], salt=params[3], key=params[4])
    if hashed_pw == hashed_password:
        return True
    return False


if __name__ == "__main__":
    print(hash_password(b"bvt982b25v0tb0n3vt"))
    charset = ascii_letters + digits + punctuation
    utf_8safe = lambda length: ''.join(choice(charset) for _ in range(length)).encode()
    x = utf_8safe(16)
    xx = utf_8safe(17)
    print(checkpw(x, hash_password(x, salt=xx)))
    print(hash_password(x, salt=xx))
