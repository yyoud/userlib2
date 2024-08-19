from __future__ import annotations
from hashlib import sha3_256, pbkdf2_hmac
from secrets import token_bytes, randbelow
from base64 import b64encode, b64decode
from typing import Literal, Union
from string import ascii_letters, digits, punctuation
from secrets import choice

__all__ = ["hash_password", "checkpw"]

# any global variable falls into here.
# cannot import from userlib, as it would raise a circular imports error.
DEFAULT_COST = 65536  # default iterating cost for PBKDF2
DEFAULT_SALT_SIZE = 16
VALID_PREFIX = Literal['a', 'b', 'c']
VALID_ENCRYPTION_OPERATION = Literal["encrypt", "decrypt"]
VALID_ENCRYPTION_TYPE = Literal[1, 2]
DEFAULT_PREFIX = 'a'
ReadableBufferNonExtensive = Union[bytes, bytearray, memoryview]


# I could not import from userlib because of circular imports! what a disappointment to copy paste bro
# TODO: move the Security class from userlib to another file to prevent this
class Security:
    @staticmethod
    def xor_encrypt_decrypt(data: str | bytes, key: int = None, operation: VALID_ENCRYPTION_OPERATION = 'encrypt'):
        if isinstance(data, str):
            data = data.encode('utf-8')
        if operation == 'encrypt':
            if key is None:
                raise ValueError("Key is required for encryption.")
            encrypted_bytes = bytes([b ^ key for b in data])
            return b64encode((encrypted_bytes + bytes([key]))).decode()
        elif operation == 'decrypt':
            if key is not None:
                raise ValueError("Key should not be provided for decryption, it will be extracted.")
            encrypted_bytes = b64decode(data)
            extracted_key = encrypted_bytes[-1]
            decrypted_data = bytes([b ^ extracted_key for b in encrypted_bytes[:-1]])
            return decrypted_data.decode('utf-8'), extracted_key
        else:
            raise ValueError("Invalid operation")

    @staticmethod
    def addmod_encrypt_decrypt(data: str | bytes, key: int = None, operation: VALID_ENCRYPTION_OPERATION = 'encrypt'):
        if isinstance(data, str):
            data = data.encode('utf-8')
        if operation == 'encrypt':
            if key is None:
                raise ValueError("Key is required for encryption.")
            # Convert data to bytes and encrypt
            encrypted_bytes = bytes([(b + key) % 256 for b in data]) + bytes([key])
            # Encode to Base64
            return b64encode(encrypted_bytes).decode()
        elif operation == 'decrypt':
            if key is not None:
                raise ValueError("Key should not be provided for decryption, it will be extracted.")
            # Decode from Base64
            encrypted_bytes = b64decode(data)
            # Extract key_b
            extracted_key = encrypted_bytes[-1]
            # Decrypt data
            decrypted_data = bytes([(b - extracted_key) % 256 for b in encrypted_bytes[:-1]])
            return decrypted_data.decode('utf-8'), extracted_key

        else:
            raise ValueError("Invalid operation")

    @staticmethod
    def not_encrypt_decrypt(data: str | bytes, key: int = None, operation: VALID_ENCRYPTION_OPERATION = 'encrypt'):
        if isinstance(data, str):
            data = data.encode('utf-8')

        if operation == 'encrypt':
            if key is None:
                raise ValueError("Key is required for encryption.")
            # Encrypt data
            encrypted_bytes = bytes([~b & 0xFF for b in data]) + bytes([key])
            # Encode to Base64
            return b64encode(encrypted_bytes).decode()
        elif operation == 'decrypt':
            if key is not None:
                raise ValueError("Key should not be provided for decryption, it will be extracted.")
            # Decode from Base64
            encrypted_bytes = b64decode(data)
            # Extract key_b
            extracted_key = encrypted_bytes[-1]
            # Decrypt data
            decrypted_data = bytes([~b & 0xFF for b in encrypted_bytes[:-1]])
            return decrypted_data.decode('utf-8'), extracted_key

        else:
            raise ValueError("Invalid operation")

    @staticmethod
    def encryptbyprefix(data, prefix: VALID_PREFIX | str, key: int = None,
                        operation: VALID_ENCRYPTION_OPERATION = 'encrypt') -> str | tuple[str, int]:
        # prefix parameter also uses str to avoid type errors caused by expecting a Literal type.
        if not isinstance(data, (str, bytes)):
            raise TypeError(f"Invalid data type: {type(data)}")

        if isinstance(prefix, str):
            if prefix not in ['a', 'b', 'c']:
                raise ValueError(f"Invalid prefix: {prefix}")

        if operation == 'encrypt':
            if key is None or key > 255:
                raise ValueError("Key must be provided and be less than 256 for encryption.")

            # Encryption logic
            if prefix == 'a':
                return Security.xor_encrypt_decrypt(data, key, operation=operation)
            elif prefix == 'b':
                return Security.addmod_encrypt_decrypt(data, key, operation=operation)
            elif prefix == 'c':
                return Security.not_encrypt_decrypt(data, key, operation=operation)
        elif operation == 'decrypt':
            if key is not None:
                raise ValueError("Key should not be provided for decryption, it will be extracted from the data.")

            # Decryption logic
            if prefix == 'a':
                return Security.xor_encrypt_decrypt(data, operation=operation)
            elif prefix == 'b':
                return Security.addmod_encrypt_decrypt(data, operation=operation)
            elif prefix == 'c':
                return Security.not_encrypt_decrypt(data, operation=operation)
        else:
            raise ValueError(f"Invalid operation: {operation}")

    @staticmethod
    def circular_bit_rotate(data: bytes, shift_amount: int, direction: str = 'left') -> bytes:
        def rotate_byte(byte: int, shift: int, _direction: str) -> int:
            if _direction == 'left':
                return ((byte << shift) | (byte >> (8 - shift))) & 0xFF
            elif _direction == 'right':
                return ((byte >> shift) | (byte << (8 - shift))) & 0xFF
            else:
                raise ValueError("Direction must be 'left' or 'right'")

        return bytes(rotate_byte(byte, shift_amount, direction) for byte in data)

    @staticmethod
    def reverse_bytes(byte_string: bytes):
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
            reversed_block = Security.reverse_bytes(block_with_salt)  # mirror bits
        else:
            block_without_salt = block  # I'm too lazy to change it to block without uisalt so...
            reversed_block = Security.reverse_bytes(block_without_salt)  # mirror bits
        rotated_block = Security.circular_bit_rotate(reversed_block, len(blocks))

        unreversed_block = Security.reverse_bytes(rotated_block)  # un-mirror
        unrotated_block = Security.circular_bit_rotate(unreversed_block, len(blocks), 'right')

        hashed_block = sha3_256(unrotated_block).digest()  # Hash the salted block
        hashed_blocks.append(hashed_block)  # add to list
    concatenated_hash = b"".join(hashed_blocks)
    f_hash = sha3_256(concatenated_hash).digest()

    # iterate

    f_hash = pbkdf2_hmac('sha3_256', f_hash, uisalt, cost)

    for i in range(2*len(password)//3):  # getting hashed at the end again
        f_hash = sha3_256(f_hash).digest()
        f_hash = Security.circular_bit_rotate(f_hash, i % len(blocks) + 2)  # added 2 to the block number to ensure more chaos in the function.

    # encrypt uisalt with key_b, to later extract the key_b and the uisalt
    encrpt_salt = Security.encryptbyprefix(uisalt + bytes(_key), prefix, _key)
    encrpt_cost = Security.encryptbyprefix(str(cost), prefix, _key)

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
    decrypted_cost, universal_key = Security.encryptbyprefix(encrypted_cost, prefix, operation='decrypt')
    decrypted_salt = Security.encryptbyprefix(encrypted_salt, prefix, operation='decrypt')[0]

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
