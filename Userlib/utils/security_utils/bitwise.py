from __future__ import annotations
from typing import Union, Literal
from Userlib.utils.security_utils.Security import force_bytes

Buffer = Union[bytes, bytearray, memoryview]

__all__ = ["monobyte_xor", "RotR", "ShR", "Ch", "Maj", "SIGMA0", "SIGMA1", "sigma0", "sigma1", "operator"]


def monobyte_xor(data: Buffer, monobyte: int) -> bytes:
    if not (0 <= monobyte < 256):
        raise ValueError("monobyte must be between 0 and 255")
    data = force_bytes(data)
    return bytes(byte ^ monobyte for byte in data)


def zip_xor(a: bytes, b: bytes) -> bytes:
    return bytes(A ^ B for A, B in zip(a, b))


RotR = lambda A, n: ((A >> n) | (A << (32 - n)))
ShR = lambda A, n: A >> n

# Ch(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z),
# Maj(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z) ⊕ (Y ∧ Z),
# Σ0(X) = RotR(X, 2) ⊕ RotR(X, 13) ⊕ RotR(X, 22),
# Σ1(X) = RotR(X, 6) ⊕ RotR(X, 11) ⊕ RotR(X, 25),
# σ0(X) = RotR(X, 7) ⊕ RotR(X, 18) ⊕ ShR(X, 3),
# σ1(X) = RotR(X, 17) ⊕ RotR(X, 19) ⊕ ShR(X, 10)

Ch = lambda X, Y, Z: (X & Y) ^ (~X & Z)
Maj = lambda X, Y, Z: (X & Y) ^ (X & Z) ^ (Y & Z)
SIGMA0 = lambda X: RotR(X, 2) ^ RotR(X, 13) ^ RotR(X, 22)
SIGMA1 = lambda X: RotR(X, 6) ^ RotR(X, 11) ^ RotR(X, 25)
sigma0 = lambda X: RotR(X, 7) ^ RotR(X, 18) ^ ShR(X, 3)
sigma1 = lambda X: RotR(X, 17) ^ RotR(X, 19) ^ ShR(X, 10)


def operator(data: int, mode: Literal[1, 2, 3] | int):
    """
        Operator based on SHA256 bitwise functions and algorithms.
        operations are tested for good avalanche and diffusions, and are masked for 32 bits.
        (sha256 operations) \n
        includes functions:
            Ch(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z), \n
            Maj(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z) ⊕ (Y ∧ Z), \n
            Σ0(X) = RotR(X, 2) ⊕ RotR(X, 13) ⊕ RotR(X, 22), \n
            Σ1(X) = RotR(X, 6) ⊕ RotR(X, 11) ⊕ RotR(X, 25), \n
            σ0(X) = RotR(X, 7) ⊕ RotR(X, 18) ⊕ ShR(X, 3), \n
            σ1(X) = RotR(X, 17) ⊕ RotR(X, 19) ⊕ ShR(X, 10) \n

        *operation 1:*
            `Σ0(data) ⊕ Σ1(data) ⊕ Maj(data, ShR(data, 2), ShR(data, 4))`

        *operation  2:*
            `σ0(data) | Ch(data, ShR(data, 2), ShR(data, 3))) ⊕ (σ1(data) ⊕ Maj(data, ShR(data, 3), ShR(data, 1))` \n

        *operation 3:*
            `(Σ0(data) - σ1(data)) ⊕ (Ch(data, ShR(data, 4), ShR(data, 7)))) + (Σ1(data) & Maj(data, ShR(data, 1), ShR(data, 3))`


        :param data: data to operate on
        :param mode: mode from 1, 2, 3 to select which operator operates on the data
        :return: operated data
        """
    if mode == 1:
        return SIGMA0(data) ^ SIGMA1(data) ^ Maj(data, data >> 2, data >> 4)
    elif mode == 2:
        return (sigma0(data) | Ch(data, data >> 2, data >> 3)) ^ (sigma1(data) ^ Maj(data, data >> 3, data >> 1))
    else:
        return ((SIGMA0(data) - sigma1(data)) ^ (Ch(data, data >> 4, data >> 7)) +
                (SIGMA1(data) & Maj(data, data >> 1, data >> 3)))


if __name__ == "__main__":
    # example
    inted_mixed = 52

    Ch = lambda X, Y, Z: (X & Y) ^ (~X & Z)
    Maj = lambda X, Y, Z: (X & Y) ^ (X & Z) ^ (Y & Z)
    # noinspection NonAsciiCharacters
    Σ0 = lambda X: RotR(X, 2) ^ RotR(X, 13) ^ RotR(X, 22)
    # noinspection NonAsciiCharacters
    Σ1 = lambda X: RotR(X, 6) ^ RotR(X, 11) ^ RotR(X, 25)
    # noinspection NonAsciiCharacters
    σ0 = lambda X: RotR(X, 7) ^ RotR(X, 18) ^ ShR(X, 3)
    # noinspection NonAsciiCharacters
    σ1 = lambda X: RotR(X, 17) ^ RotR(X, 19) ^ ShR(X, 10)

    print(hex(operator(inted_mixed, 1)), sep=" enhanced: ")
    print(hex(operator(inted_mixed, 2)), sep=" enhanced: ")
    print(hex(σ1(233034532)))
