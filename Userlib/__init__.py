#!/usr/bin/python3

# thanks for looking through this code, I appreciate you looking into it.
# it's my first project, and I'm trying to learn, so if you find something
# that you think I should change or a bug in my code, reach out, I'll be happy to learn more.
# https://www.github.com/yyoud to reach out.
# project on GitHub:
# https://www.github.com/yyoud/userlib2

# tell me what you think of my implementation, although the simplicity.
# after all, I am just a beginner.

# BTW, this project is more of a learning project, rather than a functional one,
# and it is not built to hold or handle many users.
# If you try to do so, it will crash out, because I use a single writer db, for now.
# It's also meant to be humorist, rather than serious
# More on that in the README.md file on GitHub.


from Userlib.userlib import *
from Userlib.db_env import *
from Userlib.utils import *


__all__ = ["userlib", "db_env", "utils", "User"]

__version__ = "1.0.1"
__author__ = "yyoud"


if sys.version_info[:2] < (3, 9):
    raise RuntimeWarning("Module designed and maintained for py 3.9.")
