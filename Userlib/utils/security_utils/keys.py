#!/usr/bin/python3
# under development

from secrets import choice
from random import randrange
from Crypto.PublicKey import RSA  # noqa
from typing import Literal
from Userlib.utils.security_utils.bitwise import monobyte_xor
from uuid import uuid5, NAMESPACE_DNS

T_key_format = Literal["sk", "mk", "ns"]


class ChecksumKeys:
    def __init__(self, hex_str):
        """
        Initialize with a specific hex string defining the operations.

        :param hex_str: String defining the sequence of operations
        """
        self.hex_str = hex_str

    @staticmethod
    def create_checksum_hex(num_operations=4):
        """
        Create a checksum hex string with a given number of operations.

        :param num_operations: Number of operations to include in the hex string
        :return: A string representing the checksum operations
        """
        operations = ['r', 's', 'd', 'sbt', 'm']
        op_str = ""
        random_d = lambda: f"d({choice([2, 3, 4])})"
        random_sbt = lambda: f"sbt({choice([5, 7, 9])})"
        random_m = lambda: f"m({choice([10, 11, 12])})"

        for _ in range(num_operations):
            op = choice(operations)
            if op == 'r':
                op_str += 'r:'
            elif op == 'd':
                op_str += random_d() + ':'
            elif op == 'sbt':
                op_str += random_sbt() + ':'
            elif op == 's':
                op_str += 's:'
            elif op == 'm':
                op_str += random_m() + ':'
        return op_str.rstrip(':')

    def verify_id(self, id_):
        """
        Verify an ID by applying operations defined in the instance's hex string.

        :param id_: A string of 9 digits, or a list/tuple of such strings
        :return: True if the ID passes the checksum verification, False otherwise
        """
        # Check if id_ is a string
        if isinstance(id_, str):
            if len(id_) != 9 or not id_.isdigit():
                raise ValueError("ID must be a 9-digit string")
            return self._apply_operations(id_, self.hex_str)

        # Check if id_ is a list or tuple of strings
        elif isinstance(id_, (list, tuple)):
            for item in id_:
                if not isinstance(item, str) or len(item) != 9 or not item.isdigit():
                    raise ValueError("Each item in the list/tuple must be a 9-digit string")
            results = [self._apply_operations(item, self.hex_str) for item in id_]
            return all(results)  # Returns True if all IDs pass the verification

        # Raise an error for unsupported types
        else:
            raise TypeError("ID must be a string, list, or tuple of 9-digit strings")

    def generate_keys(self, quantity: int):
        """
        Generate a number of keys based on the instance's hex string.

        :param quantity: Number of _keys to generate
        :return: A tuple containing the generated _keys
        """
        _keys = []
        while len(_keys) < quantity:
            _id = f"{randrange(100000000, 1000000000):09}"  # Generate a random 9-digit ID
            if self.verify_id(_id):
                _keys.append(_id)
        return tuple(_keys)

    @staticmethod
    def _apply_operations(number_str, operations):
        """
        Apply operations to the ID as defined in the hex string.

        :param number_str: A string of _digits
        :param operations: The operations string
        :return: True if operations result in a valid checksum, False otherwise
        """
        def reverse(_digits):
            return _digits[::-1]

        def double(_digits, _step):
            return [d * _step if (i + 1) % 2 == 0 else d for i, d in enumerate(_digits)]

        def subtract(_digits, _x):
            return [d - _x if d > _x else d for d in _digits]

        def sum_digits(_digits):
            return sum(_digits)

        def mod(total_sum, _x):
            return total_sum % _x == 0

        digits = list(map(int, number_str))
        operations = operations.split(':')

        TOTAL_SUM = 0
        for op in operations:
            if op == 'r':
                digits = reverse(digits)
            elif op.startswith('d'):
                step = int(op.split('(')[1].split(')')[0])
                digits = double(digits, step)
            elif op.startswith('sbt'):
                x = int(op.split('(')[1].split(')')[0])
                digits = subtract(digits, x)
            elif op == 's':
                TOTAL_SUM = sum_digits(digits)
            elif op.startswith('m'):
                x = int(op.split('(')[1].split(')')[0])
                if not mod(TOTAL_SUM, x):
                    return False
            else:
                raise ValueError(f"Unknown operation: {op}")

        return True


class MasterKey:
    """
    idea:
    every regular key, will include this format: \n
    ns=<digested key of the uid>$ \n
    every master key: \n
    mk=<private domain key>$<number of regular keys in domain>
    \n
    \n
    where the number of regular keys in each domain has to be predefined.
    """

    def __init__(self, name: str, key_format: T_key_format, key: bytes):  # noqa i am a nigga. if you see this, fuck you.
        self.sk = ...
        self.pk = ...  # private and public key placeholders
        integer = int.from_bytes(key, "big") % 256
        integer_2 = (len(name)**2) % 256
        self.uid = uuid5(NAMESPACE_DNS, monobyte_xor(name.encode()+key, (
                int.from_bytes(monobyte_xor(key, integer), "big") ^
                int.from_bytes(monobyte_xor(name.encode(), integer_2), "big")) % 256).decode('latin-1'))

        # ok so I need to implement the rsa and all these

    def _digest_key(self):
        # idk what to do honestly
        pass

    def __str__(self):

        return f"mk="


class KeyDomains:
    pass


# Example usage
hex_str556 = ChecksumKeys.create_checksum_hex(num_operations=4)
print(f"Generated checksum operations: {hex_str556}")

# Create an instance with the generated hex string
checksum_keys = ChecksumKeys(hex_str556)

# Generate 5 valid keys based on the hex algorithm
keys = checksum_keys.generate_keys(quantity=5)
print(f"Generated keys: {keys}")

# Verify a specific ID
id_to_verify = checksum_keys.generate_keys(1)[0]  # Example 9-digit ID
print(id_to_verify)
print(f"Verification result: {checksum_keys.verify_id(id_to_verify)}")
