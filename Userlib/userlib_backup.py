"""with database class included directly
not up to date. not tested and will produce errors.
"""


# © all rights  reserved  to Ziv Nathan 2024. (C)


from __future__ import annotations
from hashlib import (sha256, new, sha3_256, sha3_384, sha1)
import re
from secrets import randbelow, choice, token_bytes
import sqlite3 as sq
from functools import cache
from string import ascii_letters, punctuation, digits
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from uuid import uuid5, NAMESPACE_DNS
from datetime import datetime
from base64 import b64encode, b64decode, b32encode, a85encode
import base58


# Create a SQLite database and table for users
# don't change database only drop table and create a new one
def _alter_tables():
    conn = sq.connect("userf.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE users (
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT,
            uid INTEGER PRIMARY KEY
            )
        """)

    conn.commit()


# not finished, not tested A BIG PIECE OF SHIT, source of all problems
class Database:
    @staticmethod
    def add_user(username, email, hashed_password, idu):
        """if implementing in an __init__ function, remember to not add the self arg"""
        try:
            _conn = sq.connect('userf.db')
            _cursor = _conn.cursor()
            _cursor.execute("SELECT username FROM Users WHERE username=?", (username,))
            existing_username = _cursor.fetchone()
            _cursor.execute("SELECT email FROM Users WHERE email=?", (email,))
            existing_email = _cursor.fetchone()
            # Raise ValueError if username or email already exists
            if existing_username:
                raise ValueError(f"Username '{username}' already exists.")
            elif existing_email:
                raise ValueError(f"Email '{email}' already exists.")

            _cursor.execute("""
                    INSERT INTO Users (username, email, password_hash, uid)
                    VALUES (?, ?, ?, ?)
                """, (username, email, hashed_password, idu))
            _conn.commit()
            _cursor.close()
            _conn.close()
        except sq.Error as e:
            print(f"Database error: {repr(e)}")
            return None

    @staticmethod
    def get_user(identifier: str, method: str = 'username'):
        """returns tuple or None. \n
        fetch:
            username - (email, hash, id_) \n
            email - (username, hash, id_) \n
            id_ - (username, email, hash) \n
        """
        try:
            # Connect to the SQLite database
            _conn = sq.connect('userf.db')
            _cursor = _conn.cursor()
            if method == 'username':
                # Execute the query to fetch email password_hash and id_ from user table
                _cursor.execute("SELECT email, password_hash, uid FROM Users WHERE username=?", identifier)
                # Fetch the result (only one row expected)
                user = _cursor.fetchone()
                _cursor.close()
                _conn.close()
                return user if user else None

            elif method == 'email':
                # Execute the query to fetch user information by email
                _cursor.execute("SELECT username, password_hash, uid FROM Users WHERE email=?", identifier)
                # Fetch the result (only one row expected)
                user = _cursor.fetchone()
                _cursor.close()
                _conn.close()
                return user if user else None

            elif method == 'id_':
                # Execute the query to fetch user information by email
                _cursor.execute("SELECT username, email, password_hash FROM Users WHERE uid=?", identifier)
                # Fetch the result (only one row expected)
                user = _cursor.fetchone()
                _cursor.close()
                _conn.close()
                return user if user else None

            else:
                raise ValueError("method is unsupported. please use 'username', 'email', or 'id_'.")

        except sq.Error as e:
            print(f"Error retrieving user information: {e}")
        return None

    @staticmethod
    def delete_user(identifier: str, method: str = 'username'):
        cn = sq.connect(f"userf.db")
        crsr = cn.cursor()
        try:
            if method == 'username':
                crsr.execute("""
                    DELETE FROM Users WHERE username=?
                """, identifier)
            elif method == 'email':
                crsr.execute("""
                    DELETE FROM Users WHERE email=?
                """, identifier)
            elif method == 'id_':
                crsr.execute("""
                    DELETE FROM Users WHERE uid=?
                """, identifier)

        except sq.Error as e:
            print(f"error: {e}")
        pass

    @staticmethod
    def reset(commitment: str, table='Users'):
        """
        deletes all users/ history.
        :param commitment: needs to be the sha256 hexdigest of "commitment".
        :param table: table name
        """
        if commitment == sha256(b"commitment").hexdigest():
            _conn = sq.connect("userf.db")
            _cursor = _conn.cursor()
            _cursor.execute(f"DELETE FROM {table}")
            _conn.commit()
            _conn.close()

    @staticmethod
    def update_user(identifier: str, update: str, update_field: str, id_method='username'):
        """Updates a specified field of a user identified by `identifier`. ID cannot be updated."""
        cn = sq.connect('userf.db')
        crsr = cn.cursor()

        try:
            if id_method == 'username':
                if update_field == 'password':
                    crsr.execute("""UPDATE Users SET password=? WHERE username=?""", (update, identifier))
                elif update_field == 'email':
                    crsr.execute("""UPDATE Users SET email=? WHERE username=?""", (update, identifier))
                elif update_field == 'username':
                    crsr.execute("""UPDATE Users SET username=? WHERE username=?""", (update, identifier))
                else:
                    print("Invalid update_field. Use 'password', 'email', or 'username'.")
                    return

            elif id_method == 'email':
                if update_field == 'password':
                    crsr.execute("""UPDATE Users SET password=? WHERE email=?""", (update, identifier))
                elif update_field == 'username':
                    crsr.execute("""UPDATE Users SET username=? WHERE email=?""", (update, identifier))
                elif update_field == 'email':
                    crsr.execute("""UPDATE Users SET email=? WHERE email=?""", (update, identifier))
                else:
                    print("Invalid update_field. Use 'password', 'email', or 'username'.")
                    return

            elif id_method == 'id_':
                if update_field == 'password':
                    crsr.execute("""UPDATE Users SET password=? WHERE id_=?""", (update, identifier))
                elif update_field == 'username':
                    crsr.execute("""UPDATE Users SET username=? WHERE id_=?""", (update, identifier))
                elif update_field == 'email':
                    crsr.execute("""UPDATE Users SET email=? WHERE id_=?""", (update, identifier))
                else:
                    print("Invalid update_field. Use 'password', 'email', or 'username'.")
                    return

            else:
                print("Invalid id_method. Use 'username', 'email', or 'id_'.")
                return

            cn.commit()  # Commit the transaction
        except sq.Error as e:
            print(f"Error: {e}")
        finally:
            cn.close()  # Close the database connection


# any global variable falls into here
DEFAULT_COST = 1024
DEFAULT_LEN = 512
DEFAULT_SALT_SIZE = 16
DEFAULT_PREFIX = 'a'


def randint(a: int, b: int):
    return randbelow(b-a+1)+a


# Finished, lightly tested LEAST OF MY WORRIES
class SecurityMethods:

    @staticmethod
    def formatted_key(token, key: int, prefix='a', cost=DEFAULT_COST):
        """return: 'sk= <base64 >#prefix#encrypted key_b'"""
        if key > 255:
            raise ValueError("Key should be smaller then 255")
        finale = sha1(SecurityMethods.encryptbyprefix(token, prefix, key).encode()).digest()
        for i in range(cost):
            finale = sha1(finale).digest()

        return f"sk= {finale.hex()}"

    @staticmethod
    def verify_formatted_key(key):
        pass

    @staticmethod
    def xor_encrypt_decrypt(data: str, key: int = None, operation='encrypt'):
        if operation == 'encrypt':
            if key is None:
                raise ValueError("Key is required for encryption.")
            encrypted_bytes = bytes([b ^ key for b in data.encode()])
            return b64encode((encrypted_bytes + bytes([key]))).decode()
        elif operation == 'decrypt':
            if key is not None:
                raise ValueError("Key should not be provided for decryption, it will be extracted.")
            encrypted_bytes = b64decode(data)
            extracted_key = encrypted_bytes[-1]
            decrypted_data = bytes([b ^ extracted_key for b in encrypted_bytes[:-1]])
            return decrypted_data.decode(), extracted_key
        else:
            raise ValueError("Invalid operation")

    @staticmethod
    def addmod_encrypt_decrypt(data: str, key: int = None, operation='encrypt'):
        if operation == 'encrypt':
            if key is None:
                raise ValueError("Key is required for encryption.")
            # Convert data to bytes and encrypt
            encrypted_bytes = bytes([(b + key) % 256 for b in data.encode()]) + bytes([key])
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
            return decrypted_data.decode(), extracted_key

        else:
            raise ValueError("Invalid operation")

    @staticmethod
    def not_encrypt_decrypt(data: str, key: int = None, operation='encrypt'):
        if operation == 'encrypt':
            if key is None:
                raise ValueError("Key is required for encryption.")
            # Encrypt data
            encrypted_bytes = bytes([~b & 0xFF for b in data.encode()]) + bytes([key])
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
            return decrypted_data.decode(), extracted_key

        else:
            raise ValueError("Invalid operation")

    @staticmethod
    def encryptbyprefix(data, prefix, key: int = None, operation='encrypt'):
        if prefix not in ['a', 'b', 'c']:
            raise ValueError("Invalid format")
        if key > 255:
            raise ValueError("key_b should be ")
        # encryption method
        e_m = {'a': SecurityMethods.xor_encrypt_decrypt(data, key, operation=operation),
               'b': SecurityMethods.addmod_encrypt_decrypt(data, key, operation=operation),
               'c': SecurityMethods.addmod_encrypt_decrypt(data, key, operation=operation)}
        return e_m[prefix]

    # the difference between this and the formatted key_b is that this is purly random.
    # but the formatted key_b is not random at all and its actually secure enough I'd say
    @staticmethod
    def generate_key(key_type: str, length: int, base=16):
        """
        Generates random keys by type.

        :param length: length of desired key_b
        :param base: used for nbase keys
        :param key_type: type of the key_b, from: 'str', 'digit', 'bin', 'nbase'
        :return: finalised key_b, matching key_b type
        """
        charset = digits + ascii_letters + punctuation
        gen_str_key = lambda _length: ''.join(choice(charset) for _ in range(length))
        gen_digit_key = lambda _length: int(''.join(choice(digits) for _ in range(_length)))
        gen_bin_key = lambda _length: ''.join(format(byte, '08b') for byte in token_bytes(_length))
        gen_nbase_key = lambda _length, nbase: (
            lambda data: (lambda encoders: encoders.get(nbase, lambda: (_ for _ in ()).throw(ValueError("Invalid base. Supported bases are: 10, 16, 32, 58, 64, 85.")))(data))({
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
            password: str | bytes = ...,
            _type: type = ...,
            encrypting_method: str | None = None,
            hashing_method: str | object | None = sha3_384(),
            salt: str | bytes | None = None) -> str | int | bytes:

        # Ensure valid hashing method
        if isinstance(hashing_method, str):
            hashing_method = new(hashing_method)

        # Convert password and uisalt to bytes if they are strings
        password_bytes = password.encode() if isinstance(password, str) else password
        salt_bytes = salt.encode() if isinstance(salt, str) else salt

        # Apply uisalt to the password
        salted_password = password_bytes + salt_bytes if salt_bytes else password_bytes

        # Encrypting the password (if specified)
        if encrypting_method:
            key = sha256(salted_password).digest()[:16]  # Use the first 16 bytes as the key_b
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            salted_password = encryptor.update(salted_password) + encryptor.finalize()

        # Hash the password
        hashing_method.update(salted_password)
        hashed_result = hashing_method.digest()

        # Convert the result to the desired type (str, int, bytes)
        if _type is str:
            return hashed_result.hex()
        elif _type is int:
            return int.from_bytes(hashed_result, byteorder='big')
        elif _type is bytes:
            return hashed_result
        else:
            raise ValueError("Invalid type specified for the result")


def create_c_id(id_u: str | bytes, __length: int = 32):
    """
    Generates a custom ID based on SHA-256 hash of input string or bytes.

    :param id_u: String or bytes to operate on.
    :param __length: Length of the finalized string (up to 64 characters).
    :return: Custom ID string.
    """

    # Ensure id_u is bytes
    if isinstance(id_u, str):
        id_ub = id_u.encode()
    else:
        id_ub = id_u

    # Compute SHA-256 hash
    id_s = sha256(id_ub).hexdigest()

    # Return custom ID of specified length
    return id_s[:__length]


# NOT finished, not tested yet
class User:
    user_count = 0
    existing_usernames = {}
    existing_emails = set()
    users = {}
    admins = {}

    def __init__(self, username: str, email: str, password: str, id_u: str | int | None = None) -> None:
        self.password = password
        self.username = username
        # serves as manager token
        self.id = None
        if id_u is not None:
            self.id = create_c_id(id_u)
        else:
            self.id = uuid5(NAMESPACE_DNS, username)
            User.admins[username] = id_u
        self.hashed_password = User.hash_password(self.password)
        self.email_address, self.email_domain = None, None
        if isinstance(email, str):
            if self.validate_email(email)[1]:
                self.email = self.validate_email(email)[1]
            else:
                raise ValueError("Incorrect email.")
        else:
            self.email = email
        self.admin_hash = None
        self.is_admin = False
        User.existing_emails.add(self.email)
        User.existing_usernames[self.username] = self.id
        User.user_count += 1
        self.number = User.user_count
        User.users[username] = {'id_': self.id, 'password': self.hashed_password, 'email': self.email}

    def __str__(self):
        return f"User(username={self.username}, email={self.email}, id_={self.id})"

    def __update__(self):
        self.__init__(self.username, self.email, self.password)

    @staticmethod
    def identify(username):
        return User.users[username]

    # the 'hash password' function isn't necessary all the time if you have
    # a costume hashing function but definitely a helper.
    @staticmethod
    def hash_password(password: str, prefix=DEFAULT_PREFIX, cost=DEFAULT_COST, salt_size=DEFAULT_SALT_SIZE, salting_idx=False, salt=None, key=None) -> str:
        """
        most secure hasher I could build.
        :param key: key_b of encryption for matching purposes\
        :param password: password \
        :param salt_size: size of uisalt in bytes if uisalt is none \
        :param prefix: encrypting prefix and format provider \
        :param cost: time cost \
        :param salting_idx: generates random uisalt if true or uses the given uisalt \
        :param salt: pre-given uisalt for password-matching purposes \
        :return: hashed password
        """
        if salt_size < 0:
            raise ValueError("Salt size must be grater or equal to 0")
        password_e = password.encode()
        if prefix not in ['a', 'b', 'c']:
            raise ValueError("Invalid prefix")

        def pad(data, mod: int = 64):
            padding_len = mod - (len(data) % mod)
            padded_data = data + b'\x80'
            padded_data += b'\x00' * (padding_len - 1)  # Subtract 1 for the initial '\x80'
            return padded_data

        def mirror_bits(byte_string: bytes):
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

        def circular_bit_rotate(data: bytes, shift_amount: int, direction: str = 'left') -> bytes:
            def rotate_byte(byte: int, shift: int, _direction: str) -> int:
                if _direction == 'left':
                    return ((byte << shift) | (byte >> (8 - shift))) & 0xFF
                elif _direction == 'right':
                    return ((byte >> shift) | (byte << (8 - shift))) & 0xFF
                else:
                    raise ValueError("Direction must be 'left' or 'right'")
            return bytes(rotate_byte(byte, shift_amount, direction) for byte in data)

        _key = randbelow(255) if not key else key

        password_b = pad(password_e)
        blocks = [password_b[i:i + 64] for i in range(0, len(password_b), 64)]  # Divide padded_data into blocks of 64 bytes
        hashed_blocks = []
        if salting_idx:
            salt = token_bytes(salt_size) if not salt else salt
        else:
            salt = b''
        for block in blocks:
            if salting_idx is True:
                block_with_salt = block + salt.encode()  # Append uisalt to the block
                reversed_block = mirror_bits(block_with_salt)  # mirror bits
            else:
                block_without_salt = block  # I'm too lazy to change it to block without uisalt so...
                reversed_block = mirror_bits(block_without_salt)  # mirror bits
            rotated_block = circular_bit_rotate(reversed_block, len(blocks))
            unreversed_block = mirror_bits(rotated_block)  # un-mirror
            unrotated_block = circular_bit_rotate(unreversed_block, len(blocks), 'right')

            hashed_block = sha3_256(unrotated_block).digest()  # Hash the salted block
            hashed_blocks.append(hashed_block)  # add to list
        concatenated_hash = b"".join(hashed_blocks)
        f_hash = sha3_256(concatenated_hash).digest()
        # iterate
        for i in range(cost-1):  # getting hashed at the end again
            f_hash = sha3_256(f_hash+salt).digest()
            f_hash = circular_bit_rotate(f_hash, i % len(blocks)+2)  # added 2 to the block number to ensure more chaos in the function.

        # encrypt uisalt with key_b, to later extract the key_b and the uisalt
        encrypted_salt = SecurityMethods.encryptbyprefix(str(salt)+str(_key), prefix, _key)
        encrypted_cost = SecurityMethods.encryptbyprefix(str(cost), prefix, _key)
        final_hash = sha3_256(f_hash).hexdigest()
        # format: <hash>$len(key_b)+prefix+encrypted cost$len(uisalt size)~uisalt size$uisalt
        # example: <hash>$2a<encrypted cost>$2~16$<uisalt>
        return f"{final_hash}${str(len(str(_key)))+prefix+encrypted_cost}${str(len(str(salt_size)))+'~'+str(salt_size)}${encrypted_salt}"

    # changes the password when needed.
    def new_password(self, old_password, new_password):
        try:
            if old_password == self.password:
                self.password = new_password
                self.hashed_password = User.hash_password(new_password)
                self.__update__()
        except ValueError as e:
            print(f'problem with renewing password: {e}')

    # storage functions are in `_good_but_not_enough.txt` file if I ever need them

    @staticmethod
    def validate_email(email: str, regex: str | None = None):
        """
        A function that validates emails to check that they follow the protocol of example@example.example
        (standard email protocol).

        :parameter email: email to validate
        :parameter regex: optional costume regex to check email

        :return: List of: [email validation(True/False), email(email/None), address(address/None), domain(domain/None)].
        """
        try:
            # Updated regular expression for email validation and extraction
            email_regex = r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])" if not regex else regex
            match = re.match(email_regex, email)
            if match:
                # Extracting email address and domain
                email_address, email_domain = match.group(1), match.group(2)
                return [True, email, email_address, email_domain]
        except ValueError as e:
            print(f"Error validating email: {e}")
        return [False, email, None, None]

    @staticmethod
    def password_policy(password: str, printing_index: bool = False):
        """
        Used to validate password by the following policy: 12<=length<=50, has number, has special chars.
        :param password: password to validate.
        :param printing_index: If True prints a statement explaining what went wrong.
        :return: List of: [password validation(bool), password, stmt (if needed.)].
        """
        try:
            if 8 <= len(password):
                has_number = any(char in digits for char in password)
                has_special_char = any(char in punctuation for char in password)
                if has_number and has_special_char:
                    return [True, password]
                elif not has_number:
                    stmt = "Password must contain a number."
                else:
                    stmt = "Password must contain a special character."
            else:
                stmt = "The password length must be grater then 8 characters"
            if printing_index:
                print(stmt)
                return False
            else:
                return [False, password, stmt]
        except ValueError as e:
            print(f"problem checking password: {e}")


# NOT FINISHED AND ALSO A PIECE OF SHIT. I FUCKING HATE THIS PROGRAM. DOES THINGS WITHOUT ME EVER TELLING IT. SHIT.
class Manager:
    """only managers have access to the database. managers have a determined token registered in the User class."""
    managers_info = {}
    banned_users = {}

    def __init__(self, suser: User):
        if User.admins[suser.username]:
            self.admin = True
            self.name = suser.username
            self.token = suser.id
            Manager.managers_info[self.name] = self.token
            self.inspections = {}

    def __eq__(self, user):
        if isinstance(user, User):
            return self.managers_info[user.username] == user.id
        else:
            return False

    def __hex__(self):
        pass

    def inspect_user(self, name, token, identifier: str, method: str = 'username'):
        if Manager.managers_info.get(name, None) and Manager.managers_info[name] == token and self.name == name and self.token == token:
            self.inspections[identifier] = {'method': method, 'timestamp': datetime.now()}
            return Database.get_user(identifier, method)

    def ban_user(self, name, token, username):
        if Manager.managers_info.get(name, None) and Manager.managers_info[name] == token and self.name == name and self.token == token:
            Manager.banned_users[username] = User.users.get(username, None)

    def verify_user(self, name, token, username, password):
        if Manager.managers_info.get(name, None) and Manager.managers_info[name] == token and self.name == name and self.token == token:
            info_list = self.from_hash(self.name, self.token, password)
            salt, key, cost, salt_size, prefix = info_list[6], info_list[7], info_list[3], info_list[4], info_list[2]

            pwhash = User.hash_password(password, salt_size, prefix, cost, salt=salt)
            # actual password hash
            apwh = Database.get_user(username)[1]  # returns (email, hash, id_)
            if apwh == pwhash:
                return True
            return False

    def from_hash(self, name, token, encoded_string):
        """returns [hash, key_b length, encryption, length uisalt size, uisalt size, uisalt]"""
        if Manager.managers_info.get(name, None) and Manager.managers_info[name] == token and self.name == name and self.token == token:

            # Use regular expressions to extract information
            pattern = r"(?P<hash>[a-fA-F0-9]+)\$(?P<len_key>\d+)(?P<prefix>[a-zA-Z]+)(?P<encrypted_cost>[a-zA-Z0-9]+)\$(?P<len_salt_size>\d+)~(?P<salt_size>\d+)\$(?P<encrypted_salt>[a-fA-F0-9]+)"
            match = re.match(r"(?P<hash>[a-fA-F0-9]+)\$(?P<len_key>\d+)(?P<prefix>[a-zA-Z]+)(?P<encrypted_cost>[a-zA-Z0-9]+)\$(?P<len_salt_size>\d+)~(?P<salt_size>\d+)\$(?P<encrypted_salt>[a-fA-F0-9]+)", encoded_string)
            if not match:
                raise ValueError("Invalid format")
            info = match.groupdict()
            # Convert lengths and sizes to integers
            info['len_key'] = int(info['len_key'])
            info['len_salt_size'] = int(info['len_salt_size'])
            info['salt_size'] = int(info['salt_size'])

            decrypted_salt, decrypted_key = SecurityMethods.encryptbyprefix(info['encrypted_salt'], info['prefix'], operation='decrypt')
            decrypted_cost = SecurityMethods.encryptbyprefix(info['encrypted_cost'], info['prefix'], operation='decrypt')

            return [info['hash'], info['len_key'], info['prefix'], decrypted_cost, info['len_salt_size'], info['salt_size'],
                    decrypted_salt, decrypted_key]


# on the spot simple test yes broady
@cache
def aatest():
    pass


if __name__ == "__main__":
    aatest()
