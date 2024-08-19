
# hello bro, how is it going?
# hey thanks for looking through this code, appreciate it.
# it's my first project, and I'm trying to learn, so if you find something
# bad in my code, reach out, I'll be happy to learn more.
# https://www.github.com/yyoud to reach out.

import sys
from Userlib.userlib import *
from Userlib.db_env import *
from Userlib.utils import *

__all__ = ["userlib", "db_env", "utils"]
__version__ = "1.0.0"
__author__ = "yyoud"

if sys.version_info[:2] < (3, 9):
    raise RuntimeError("This package requires Python 3.9 or later.")
