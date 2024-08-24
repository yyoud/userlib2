##User Handling System;

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


   
