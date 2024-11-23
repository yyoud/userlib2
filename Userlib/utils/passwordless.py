# still in development
# https://github.com/yyoud
# all rights to yyoud (c)
# might abandon this because idk how to implement.
# could use socket but idk

# idea: use a totp to verify users.
# implementation: what I need to do is to assert an otp value to a user and delete it after use.
# create a pin property and make a setter and deleter, then just set it and get it and delete it and that's it.

import pyotp


class UserTOTP:
    def __init__(self, secret: str = None):
        self._secret = secret if secret else pyotp.random_base32()

    def gen_totp(self, interval: int = 30, nonce: str = None):
        nnonce = nonce if nonce else ''
        objectT = pyotp.TOTP(self._secret+nnonce, interval=interval)
        return objectT.now()

    def verify_totp(self, otp: str, nonce: str = None):
        nnonce = nonce if nonce else ''
        objectT = pyotp.TOTP(self._secret+nnonce)
        return objectT.verify(otp)

    @property
    def secret(self):
        return self._secret


if __name__ == "__main__":
    # 1. Generate a secret key (save this for later)
    secsret = pyotp.random_base32()
    print(f"Secret Key (save this for later): {secsret}")

    # 2. Initialize TOTP object with the secret
    totp = pyotp.TOTP(secsret, interval=60)

    # 3. Generate OTP (it will change every 30 seconds)
    ottp = totp.now()  # Get OTP for current time
    print(f"Generated OTP: {ottp}")
    print(totp.verify(input("enter otp: ")))
    ottp = totp.now()  # Get OTP for current time
    print(f"Generated OTP: {ottp}")
    # Wait for 30 seconds and generate OTP again
    otp2 = totp.now()
    print(f"Generated OTP after 30 seconds: {otp2}")
