from typing import Union
from Userlib.utils.security_utils.Security import refine_to_bytes


Buffer = Union[bytes, bytearray, memoryview]

__all__ = ["monobyte_xor", "RotR", "ShR", "Ch", "Maj", "SIGMA0", "SIGMA1", "sigma0", "sigma1"]


def monobyte_xor(data: Buffer, monobyte: int) -> bytes:
    if not (0 <= monobyte < 256):
        raise ValueError("monobyte must be between 0 and 255")
    # Apply XOR operation byte by byte
    data = refine_to_bytes(data)
    return bytes(byte ^ monobyte for byte in data)


RotR = lambda A, n: ((A >> n) | (A << (32 - n))) & 0xFFFFFFFF
ShR = lambda A, n: A >> n & 0xFFFFFFFF

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

if __name__ == "__main__":
    # example
    inted_mixed = 52

    alg1 = SIGMA0(inted_mixed) ^ SIGMA1(inted_mixed) ^ Maj(inted_mixed, inted_mixed >> 2, inted_mixed >> 4)
    alg2 = (sigma0(inted_mixed) | Ch(inted_mixed, inted_mixed >> 2, inted_mixed >> 3)) ^ (sigma1(inted_mixed) ^ Maj(inted_mixed, inted_mixed >> 3, inted_mixed >> 1))
    alg3 = (SIGMA0(inted_mixed) - sigma1(inted_mixed)) ^ (Ch(inted_mixed, inted_mixed >> 4, inted_mixed >> 7)) + (SIGMA1(inted_mixed) & Maj(inted_mixed, inted_mixed >> 1, inted_mixed >> 3))

    print(hex(alg1), sep=" enhanced: ")
    print(hex(alg2), sep=" enhanced: ")
    print(hex(alg3))
