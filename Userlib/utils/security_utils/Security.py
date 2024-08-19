from __future__ import annotations
from hashlib import (new, sha3_256, pbkdf2_hmac)
from secrets import choice, token_bytes
from string import ascii_letters, punctuation, digits
from base64 import b64encode, b64decode, b32encode, a85encode
import base58
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad
from typing import Literal, TYPE_CHECKING
if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

# default and globals
DEFAULT_COST = 65536  # default iterating cost for PBKDF2
DEFAULT_SALT_SIZE = 16
VALID_PREFIX = Literal['a', 'b', 'c']
VALID_ENCRYPTION_OPERATION = Literal["encrypt", "decrypt"]
VALID_ENCRYPTION_TYPE = Literal[1, 2]
DEFAULT_PREFIX = 'a'


class Security:

    # not finished
    @staticmethod
    def formatted_key(
                      token: str | bytes | bytearray | memoryview,
                      key_b: int,
                      key_cg: bytes,
                      nonce: bytes,
                      prefix_rl: Literal["sk", "mk", "ns"],
                      prefix_b: VALID_PREFIX = DEFAULT_PREFIX,  # noqa
                      prefix_et: VALID_ENCRYPTION_TYPE = 2,
                      hash_name: str = 'sha512',
                      cost=DEFAULT_COST,):
        """
        examples:
        'sk=<base64key>#c2<key_b>#key2
        Args:
            hash_name: name of the given hashing algorithm, such as 'sha256'
            token: token to base the key_b upon
            key_b: key_b for bitwise encryption
            prefix_b: encrypting format
            cost: iterations
            prefix_et: encryption type
            key_cg: key_b for cryptographic encryption
            nonce: nonce
            prefix_rl: restriction level of key_b out of:
        Returns:
            '<security>=<base64 key_b>#<encrypted prefix_b+prefix_et+key_b>#<encrypted key2>'
            sk means secure _key
            ns means no security
        """

        if not 0 < key_b < 255:
            raise ValueError("Invalid key_b", key_b)

        if prefix_rl == 'sk':
            # prefix_b defines the encryption of the final key_b components
            # step1: encrypt the token using prefix_et, 1 or 2                                TO-DO:   done
            # step2: derive key_b from it                                                     TO-DO:   done
            # step3: encrypt key_cg, both prefixes using encryptbyprefix, with arg 'key_b'.   TO-DO:   done
            # prefix_rl implemented, token implemented, key_b implemented,
            # example: sk=<b64 key_b>#c2#<encrypted key_cg>
            _encrypted_token = Security.encryptbynumberform(token, key_cg, prefix_et, nonce)
            fkey = pbkdf2_hmac(hash_name, _encrypted_token, b'', cost)  # key_b finalized

            encrypted_cryptographic_key = Security.encryptbyprefix(key_cg, prefix_b, key_b)
            encrypted_prefixes = Security.encryptbyprefix(prefix_b + str(prefix_et) + str(key_b), prefix_b, key_b)

            return f"sk={b64encode(fkey).decode()}#{encrypted_prefixes}#{encrypted_cryptographic_key}"
        elif prefix_rl == 'mk':
            # create a secure checksum algorithm that can generate new checksum formats, randomly
            # create a sample id_ using the checksum, and put it in a format of:
            # 'mk=<checksum hex>#<address>
            # the checksum would be recognized and new ids could be made that's the point
            # to make this a master _key and associate access to the private id_ and the checksum both
            # so that a master _key owner could change the private _key and remain with the checksum to mass block
            # _key owners obligated to him
            fkey = None  # noqa
            pass

    @staticmethod
    def verify_key_format(key: str):
        possible_prefixes = ['a1', 'a2', 'b1', 'b2', 'c1', 'c2']
        prefix_b = None   # noqa
        prefix_et = None  # noqa

        if key.startswith('sk='):
            pkey = key.split("#")
            for i in ['a', 'b', 'c']:
                if Security.encryptbyprefix(pkey[1], i, operation='decrypt')[0] in possible_prefixes:
                    prefix_b = None  # noqa  idk please help
        pass

    @staticmethod
    def gen_key_domain(master_key: str, duplicates: int):  # noqa
        if not master_key.startswith(("sk=", "mk=", "ns=")):
            raise ValueError("Invalid _key")

    # -------------------------------------------------------
    #             bitwise encryption things
    # -------------------------------------------------------
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
    def encryptbyprefix(data, prefix: VALID_PREFIX | str, key: int = None, operation: VALID_ENCRYPTION_OPERATION = 'encrypt') -> str | tuple[str, int]:
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
    def encryptbynumberform(data: bytes | bytearray | memoryview, key: bytes | bytearray | memoryview, number: VALID_ENCRYPTION_TYPE, nonce: bytes = None):
        """
        :param data: data to encrypt
        :param key: encryption key_b
        :param nonce: nonce
        :param number: encryption type: from 1, 2 translating to AES, ChaCha20 respectively
        :return: encrypted text in bytes
        """
        kkey = key
        if not len(key) == 32:
            kkey = sha3_256(key).digest()
        if number == 1:
            if len(nonce) < 16:
                raise ValueError("Nonce should be 16 characters long")
            elif len(nonce) > 16:
                nonce = sha3_256(nonce).digest()[:16]
            cipher = AES.new(kkey, AES.MODE_CBC, nonce)
            encrypted_text = cipher.encrypt(pad(data, AES.block_size))
            return encrypted_text
        else:
            if not len(nonce) < 12:
                raise ValueError("Nonce should be 16 characters long")
            elif len(nonce) > 12:
                nonce = sha3_256(nonce).digest()[:12]
            cipher = ChaCha20.new(key=kkey, nonce=nonce)
            encrypted_text = cipher.encrypt(pad(data, ChaCha20.block_size))
            return encrypted_text

    # -------------------------------------------------------
    #              bitwise logical operations
    # -------------------------------------------------------

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

    @staticmethod
    def maj2(hex_list):
        n = len(hex_list)
        xor_result = 0

        # Iterate over all pairs of elements in the list
        for i in range(n):
            for j in range(i + 1, n):
                # Compute AND operation for each pair
                and_result = hex_list[i] & hex_list[j]
                # XOR the result into the final result
                xor_result ^= and_result

        # Mask to ensure result is 32-bit
        return xor_result & 0xFFFFFFFF

    # -------------------------------------------------------
    #                 _key and hash things
    # -------------------------------------------------------

    # the difference between this and the formatted key_b is that this is purly random.
    # but the formatted key_b is not random at all, and it's actually secure.
    @staticmethod
    def generate_key(key_type: str, length: int, base: int = 16):
        """
        Generates random keys by type.
        Key of type `'nbase'` shall be set to bases: \n
            10, 16, 32, 58, 64, 85,
            all other will raise an error


        :param length: length of desired key_b
        :param base: used for nbase keys
        :param key_type: type of the key_b, from: 'str', 'digit', 'bin', 'nbase'
        :return: finalised key_b, matching key_b type
        """

        if base not in [10, 16, 32, 58, 64, 85]:
            raise ValueError(f"Invalid base{base}")
        charset = digits + ascii_letters + punctuation
        gen_str_key = lambda _length: ''.join(choice(charset) for _ in range(length))
        gen_digit_key = lambda _length: int(''.join(choice(digits) for _ in range(_length)))
        gen_bin_key = lambda _length: ''.join(format(byte, '08b') for byte in token_bytes(_length))
        gen_nbase_key = lambda _length, nbase: (lambda data: (lambda encoders: encoders.get(nbase, lambda: (_ for _ in ()))(data))({
                10: lambda d: str(int.from_bytes(d, 'big')),
                16: lambda d: d.hex(),
                32: lambda d: b32encode(d).decode('utf-8').rstrip('='),
                58: lambda d: base58.b58encode(d).decode('utf-8'),
                64: lambda d: b64encode(d).decode('utf-8').rstrip('='),
                85: lambda d: a85encode(d).decode('utf-8').rstrip('='),
            }))(token_bytes(_length))
        if key_type == "str":
            return gen_str_key(length)
        elif key_type == 'digit':
            return gen_digit_key(length)
        elif key_type == 'bin':
            return gen_bin_key(length)
        elif key_type == 'nbase':
            return gen_nbase_key(length, base)
        else:
            raise ValueError(f"Invalid key_b type '{key_type}'")

    @staticmethod
    def costume_hash(
            password: ReadableBuffer,
            _type: type,
            hash_name: str,
            encrypting_method: VALID_ENCRYPTION_TYPE | None = None,
            nonce: bytes = None,
            salt: str | ReadableBuffer | None = None):
        hash_obj = new(hash_name)
        password_bytes = password.encode() if isinstance(password, str) else password
        if not salt:
            salt = b''
        else:
            salt = salt.encode() if isinstance(salt, str) else salt
        salted_password = password_bytes + salt if salt else password_bytes

        # Encrypting the password (if specified)
        if encrypting_method:
            key = token_bytes(16)
            salted_password = Security.encryptbynumberform(salted_password, key, encrypting_method, nonce)
        hash_obj.update(salted_password)
        hashed_result = hash_obj.digest()

        if _type is str:
            return hashed_result.hex()
        elif _type is int:
            return int.from_bytes(hashed_result, byteorder='big')
        elif _type is bytes:
            return hashed_result
        else:
            raise ValueError("Invalid type")
