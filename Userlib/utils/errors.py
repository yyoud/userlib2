#!/usr/bin/python3
from __future__ import annotations
from typing import Optional, TYPE_CHECKING
from datetime import datetime
# who tf invented circular imports I'll fucking put a fucking grenade in his ass


class _Error(Exception):
    def __init__(self, message: Optional[str] = None):
        self.message = message
        super().__init__(self.message)


class SuspiciousActivity(Exception):
    if TYPE_CHECKING:
        from Userlib.userlib import User

    def __init__(self, message: Optional[str], user: User = None, ban_or_warning=None):
        # format of <error type>; <message>; <optional user id>; <optional warning or ban>
        # or just Suspicious Activity Found;
        # Construct the error message
        if message:
            base_message = "Suspicious Activity; " + message
            if user:
                base_message += "; for user: " + str(user.id)
        else:
            base_message = "Suspicious Activity Found;"
        if ban_or_warning:
            if "warning" in ban_or_warning.lower():
                base_message += "; Warning"
                user.warnings.append((base_message, datetime.now()))
                if len(user.warnings) >= 3:
                    user.banned = True
            elif "ban" in ban_or_warning.lower():
                base_message += "; Ban"
                user.banned = True

        # Call the parent constructor with the complete message
        super().__init__(base_message)
    # made it directly from Exception, as I wanted to create another attribute to determine a ban or a warning.
    # Linking it to a UserSpace can be a bit tricky, but I will resolve that in the future IDK


class RequestDenied(_Error):
    """used for when a request to the database is denied. \n
    Meant to be for when someone tries to make the database crash; normally, if 2 or more requests per second,
    for a second or a fraction of it are detected, the user is banned."""
    if TYPE_CHECKING:
        from Userlib.userlib import User

    def __init__(self, message: Optional[str], user: User = None, ban_or_warning=None):
        # format of <error type>; <message>; <optional user id>; <optional warning or ban>
        # or just Request Denied;
        # Construct the error message
        if message:
            base_message = "Request Denied: " + message + "for user: " + str(user.id)
        else:
            base_message = "Request Denied;"
        if ban_or_warning:
            if "Warning" in ban_or_warning.lower():
                base_message += "; Warning"
                user.warnings.append((base_message, datetime.now()))
                if len(user.warnings) >= 3:
                    user.banned = True
            elif "Ban" in ban_or_warning.lower():
                base_message += "; Ban"
                user.banned = True

        # Call the parent constructor with the complete message
        super().__init__(base_message)


class FuckOffError(_Error):
    """tells you to fuck off. if you want something work for it."""
    pass


class BullShitError(_Error):
    """stop fucking bullshitting me douche"""
    pass


class NiggaAssError(_Error):
    """stfu nigga ass"""
    pass


if __name__ == "__main__":
    from Userlib.userlib import User as Ur

    serer = Ur('dd', 'dd@dd.dd', 'ddd123456d')

    try:
        # This will raise the exception
        raise SuspiciousActivity("Some message here", user=serer, ban_or_warning='ban')
    except SuspiciousActivity as e:
        # Handle the exception and print warnings
        print(e)  # This will print the exception message
        print(serer.banned)  # This will print the warnings list
