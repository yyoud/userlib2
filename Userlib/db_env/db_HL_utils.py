# TODO: implement a user banning mechanism, unit test or manual test
# TODO: implement security mechanism by ensuring a _key and a monobyte number for bitwise encryption
# though the code is incomplete, it can function completely.
# publish code on GitHub only when completed as to not need to update recently
# README file in Userlib/README.md, includes all files.

from __future__ import annotations
import sqlite3 as sq
from pathlib import Path
from os import PathLike


# Initialize the database and table
def _alter_tables():
    conn = sq.connect("databases/userf.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE  users (
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        password_hash TEXT,
        idu INTEGER PRIMARY KEY
        )
       """)
    conn.commit()
    conn.close()


class Database:
    def __init__(self, database: str | bytes | PathLike[str] | PathLike[bytes], table_name: str, key: bytes | bytearray | memoryview, monobyte: int):
        self.table = table_name
        self.db = Database._resolve_path(database)
        if not self.db.suffix == '.db':
            raise ValueError("DB file must have a '.db' suffix")
        if not len(key) == 32:
            raise ValueError("_key must be 32 bytes long")
        if isinstance(key, memoryview):
            self.key = key.tobytes()
        elif isinstance(key, bytearray):
            self.key = bytes(key)
        else:
            self.key = key
        if not 0 <= monobyte < 256:
            raise ValueError("monobyte must be between 0 and 255")
        self.monobyte = monobyte

    @staticmethod
    def _resolve_path(database: str | bytes | PathLike[str] | PathLike[bytes]) -> Path:
        if isinstance(database, bytes):
            database = database.decode()
        return Path(database).resolve()

    # tested
    def add_user(self, username, email, hashed_password, idu):
        """Add a new user to the database."""
        cn = sq.connect(self.db)
        crsr = cn.cursor()
        crsr.execute(f"""INSERT INTO {self.table} (username, email, password_hash, idu) VALUES (?, ?, ?, ?)""",
                     (username, email, hashed_password, idu))
        cn.commit()
        crsr.close()
        cn.close()

    def get_user(self, identifier: str, method: str = 'idu'):
        """Returns user information based on the identifier and method."""

        cn = sq.connect(self.db)
        crsr = cn.cursor()

        if method == 'username':
            crsr.execute(f"SELECT * FROM {self.table} WHERE username=?", (identifier,))
        elif method == 'email':
            crsr.execute(f"SELECT * FROM {self.table} WHERE email=?", (identifier,))
        elif method == 'id_':
            crsr.execute(f"SELECT * FROM {self.table} WHERE idu=?", (identifier,))
        else:
            crsr.close()
            cn.close()
            raise ValueError("method is unsupported. please use 'username', 'email', or 'id_'.")

        user = crsr.fetchone()
        crsr.close()
        cn.close()
        return user

    def delete_user(self, identifier: str, method: str = 'username'):
        """Deletes a user from the database based on the identifier and method."""
        cn = sq.connect(self.db)
        crsr = cn.cursor()

        if method == 'username':
            crsr.execute(f"DELETE FROM {self.table} WHERE username=?", (identifier,))
        elif method == 'email':
            crsr.execute(f"DELETE FROM {self.table} WHERE email=?", (identifier,))
        elif method == 'id_':
            crsr.execute(f"DELETE FROM {self.table} WHERE idu=?", (identifier,))
        else:
            print("Invalid id_method. Use 'username', 'email', or 'id_'.")
            return

        cn.commit()
        crsr.close()
        cn.close()

    # called 'clean' and not 'reset' as to not get confused with
    # a function in 'db_env/DBConfig' to reset a database,
    # and to not create a mix-up and potential errors
    def clean(self):
        """Deletes all records from the specified table."""
        cn = sq.connect(self.db)
        crsr = cn.cursor()
        crsr.execute(f"DELETE FROM {self.table}")
        cn.commit()
        cn.close()

    # tested
    def update_user(self, identifier: str | int, update: str, update_field: str, id_method='username'):
        """Updates a specified field of a user identified by `identifier`. ID cannot be updated."""

        # Connect to the database
        cn = sq.connect(self.db)
        crsr = cn.cursor()

        if id_method == 'username':
            if update_field == 'username':
                raise ValueError("Username cannot be updated.")
            elif update_field == 'email':
                crsr.execute(f"UPDATE {self.table} SET email=? WHERE username=?", (update, identifier))
            elif update_field == 'password':
                crsr.execute(f"UPDATE {self.table} SET password_hash=? WHERE username=?", (update, identifier))
            else:
                raise ValueError("Invalid update field.")

        elif id_method == 'email':
            if update_field == 'username':
                raise ValueError("Email cannot be updated.")
            elif update_field == 'email':
                crsr.execute(f"UPDATE {self.table} SET username=? WHERE email=?", (update, identifier))
            elif update_field == 'password':
                crsr.execute(f"UPDATE {self.table} SET password_hash=? WHERE email=?", (update, identifier))
            else:
                raise ValueError("Invalid update field.")

        elif id_method == 'id_':
            if update_field == 'username':
                crsr.execute(f"UPDATE {self.table} SET username=? WHERE idu=?", (update, identifier))
            elif update_field == 'email':
                crsr.execute(f"UPDATE {self.table} SET email=? WHERE idu=?", (update, identifier))
            elif update_field == 'password':
                crsr.execute(f"UPDATE {self.table} SET password_hash=? WHERE idu=?", (update, identifier))
            else:
                raise ValueError("Invalid update field.")

        else:
            raise ValueError("Invalid ID method.")

        # Commit the transaction and close the connection
        cn.commit()
        cn.close()

    @staticmethod
    def _fetchall():
        cn = sq.connect("databases/userf.db")
        crsr = cn.cursor()
        x = crsr.execute("""SELECT * FROM users""")
        return x.fetchall()

    # temporary
    @staticmethod
    def fetchall():
        return Database._fetchall()


if __name__ == "__main__":
    db1 = Database("databases/userf.db", "users")
    # db1.add_user("niggauser_2", "example@example.comcom", "passpassword", 9)
    print(db1.get_user('user1'))
    print(db1.update_user(9, 'passpassword4updated', 'password', 'id_'))
    print(db1.fetchall())
    print()
