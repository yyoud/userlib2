# © all rights  reserved  to yyoud 2024. (C)
# TODO: in Security finish formatted _key functions                                  last
# TODO: move the hashing function to security utils and implement in User           first
# TODO: make functions to extract parameters and match password with hash           second
# TODO: split security into classes in different files found in security utils      last

"""
**=====** \n
**userlib** \n
**=====** \n
**user** lib **userlib** \n
`userlib`
"""

from __future__ import annotations
from hashlib import (sha1, sha256, new, sha3_256, pbkdf2_hmac)
from secrets import randbelow, choice, token_bytes
from string import ascii_letters, punctuation, digits
from uuid import uuid5, NAMESPACE_DNS
from datetime import datetime
from base64 import b64encode, b64decode, b32encode, a85encode
import base58
from validate_email import VALID_ADDRESS_REGEXP as DEFAULT_REGEX
from Userlib.db_env import db_HL_utils as database
from Userlib.utils.auth_utils import validate_email, password_policy
from Userlib.utils.security_utils.password_hashmentship import hash_password, checkpw
from Userlib.utils.errors import FuckOffError
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad
from typing import Literal, TYPE_CHECKING, Union
if TYPE_CHECKING:
    from _typeshed import ReadableBuffer


# default database path: "db_env/databases/userf.db"
# database instance from file: `Userlib/db_env/DBOperator`
DB_DEFAULT = database.Database("db_env/databases/userf.db", 'users', sha256(b"my_key").digest(), 245)


# any global variable falls into here
DEFAULT_COST = 65536  # default iterating cost for PBKDF2
DEFAULT_SALT_SIZE = 16
VALID_PREFIX = Literal['a', 'b', 'c']
VALID_ENCRYPTION_OPERATION = Literal["encrypt", "decrypt"]
VALID_ENCRYPTION_TYPE = Literal[1, 2]
DEFAULT_PREFIX = 'a'
T_key = Union[bytes, bytearray, memoryview]
T_quadbyte = tuple[int, int, int, int]

default_params = [
    DEFAULT_COST,
    DEFAULT_SALT_SIZE,
    VALID_PREFIX
]


def secure_randint(a: int, b: int):
    return randbelow(b-a+1)+a


def monobyte_xor(data: bytes, monobyte: int) -> bytes:
    if not (0 <= monobyte < 256):
        raise ValueError("monobyte must be between 0 and 255")
    # Apply XOR operation byte by byte
    return bytes(byte ^ monobyte for byte in data)


# Not Finished, tested methods: generate_key
# ignore, moved to another file and will be replaced once I get it more organized in the other file

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
            # step1: encrypt the token using prefix_et, 1 or 2                                TODO:   done
            # step2: derive key_b from it                                                     TODO:   done
            # step3: encrypt key_cg, both prefixes using encryptbyprefix, with arg 'key_b'.   TODO:   done
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
        self.algo = 'default'

        # how to use the property functions IDK. but I'll figure it out


        # don't delete, although seems not a good idea, serves as the static value of the hashed password.
        # that is used in cases where needed.
        self.__hashed_password = self.hash_password(password.encode())
        if validate_email(email)[0]:
            self.email = email
        else:
            raise ValueError("Invalid email")
        domains = email.split('@')
        replica = ''.join(domains).encode()
        hash_value = sha1(replica).digest()
        mid = int(len(hash_value) / 2)
        rep_int = int.from_bytes(hash_value[:mid], 'big')
        lica_int = int.from_bytes(hash_value[mid:], 'big')
        combined_value = (rep_int & lica_int) ^ (lica_int | rep_int)
        udom = b64encode(combined_value.to_bytes(len(replica), 'big')).decode()
        self.id = uuid5(NAMESPACE_DNS, udom)
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

    # the 'hash password' function can be configured using the 'hash name' parameter
    # creating either a hashlib.new object,
    # or a bcrypt or argon2 object, with all default parameters.

    def hash_password(self, password: bytes | bytearray | memoryview, salting_idx: bool = True):
        salt = b''
        if salting_idx:
            salt = token_bytes(16)
        if self.algo == 'default':
            return hash_password(password, salting_idx=salting_idx)
        else:
            return new(self.algo, password+salt)

    @property
    def algorithm(self):
        return self.algo

    @algorithm.setter
    def algorithm(self, algo: str):
        self.algo = algo

    @algorithm.deleter
    def algorithm(self):
        self.algo = 'default'

    #  can't be used as a "passwordless" function, as it doesn't implement a zero knowledge proof mechanism.
    def new_password(self, proof, new_password):
        if proof == self.__password:
            self.__password = new_password
            self.__hashed_password = hash_password(new_password)


# not yet finished
class Manager:
    """only managers have access to the database. shall not be integrated with the `user` class,
    as the integration could cause a weakness"""
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
        if isinstance(key, bytearray):
            t_key = bytes(key)
        elif isinstance(key, memoryview):
            t_key = key.tobytes()
        else:
            t_key = key
        if not len(t_key) == 16:
            raise ValueError("_key must be 16 characters long")
        for i in quadbyte:
            if not 0 <= i < 256:
                raise ValueError(f"'{i}' must be a single byte integer")
        final_value = monobyte_xor(t_key, quadbyte[0])
        for i in quadbyte[1:]:
            final_value = monobyte_xor(final_value, i)
        final_value = sha256(final_value).hexdigest()
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


# on the spot simple test yes broady
def aatest():
    # user1 = User("housemaster", "housemaster@gmail.com", "123456")
    print(DEFAULT_REGEX)
    print(validate_email("niggar@email.email"))
    print(Security.addmod_encrypt_decrypt(b"hello", 245))


if __name__ == "__main__":
    useruseruseruser = User("mynameis", "mailymail@example.example", "passypass123")
    print(b64encode(Security.encryptbynumberform(b"h364oby364ovum", b"12", 1, b"1234567890123456")).decode())
    # print(User.hash_password("hello"))
    print(Security.xor_encrypt_decrypt("hello", 254))
    print(b64encode((int.from_bytes(b"hello", "big") ^ 254).to_bytes(len(b"hello"), "big")).decode())
    print()
