# Simple User Handling System
   This is a simple system for handling users.
   Although the simplicity, it can still be used as an actual tool (although not recommended)

## Base features:
   - `User` class provides a structed user instance. it cannot be abstructed, but if i'm board enough to create an abstract class.
   - provides cool security features like password hashing and encryptions that i think are cool
   - i'm planning on updrading the code. but for now, here is an example of making good use of the code (note: UserArray is a planned update, coming soon...)
   
```python
from Userlib import User
class UserSpace(UserArray):
   array = UserArray.array()

   def __init__(self):
      self._typeuser = None

   def __new__(user: User):
      super().array.append(user)

   @proprty
   def TypeUser(self):
      return self._typeuser

   @TypeUser.setter
   def TypeUser(self, value):
      if not isinstance(value, UserConfig):
         raise ValueError("Invalid value type")
      self._typeuser = value

   @TypeUser.deleter
   def TypeUser(self):
      self._typeuser = "_T"
```

the example above is an example of making use of UserArray to create a UserSpace for an application.
it can be used for a lot of things.

## My Idea:
   I originally wanted to create this for a simple pygame.
   Though it has evloved, and became the main focus.
   Today, i really put an emphesis on the cryptography that comes into it.
   ```python
import Userlib
class Game:
   def __init__(self, ...):
      self.user = None
      ...
   #game here

   def register(self, user: User):
      self.user = user

   def display_text(self):
      return f"Hello {self.user.username}, enjoy the game!"
   ...
```
   simple idea overall. 
   It wasn't really meant to be used for logins and password hashing in the beginning.
