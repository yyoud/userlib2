# User Handling System

This repository contains a user handling system written in Python. The system includes functionality for user management, including user creation, password handling, and ID generation.

## Features

- User creation with validation
- Password hashing and verification
- Unique user ID generation
- Email validation
- Strong kdf and hashing

## Getting Started

To get started with the user handling system, follow these steps:

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yyoud/userlib2.git
   cd userlib2

## Example

```python
from Userlib.userlib import User

def register_100_users():
    for i in range(100):
        username = input("username: ")
        email = input("email: ")
        password = input("enter password: ")
        yield User(username, email, password)
```

#### I am only a begginer, and i am still learning. a lot of code here is going to be bullshit, but i have to learn someway.

