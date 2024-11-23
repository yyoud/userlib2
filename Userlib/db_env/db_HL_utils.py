# TODO: implement a user banning mechanism, implement the sixbyte thing (on me dont do it),
# manual to do so:
# user banning by making another column in another table called 'user' or now
# its a bool and it can be set to true or false. that's it for now basically for this file.
# quadbyte on me again i have a system ok imma implement it by myself
# also please implement the request denied thing in the ban mechanism so that if the ban is true the user
# cant come back with the same email and stuff yk


from __future__ import annotations

import sqlite3 as sq
from pathlib import Path
from os import PathLike
from hashlib import sha256
from Userlib.utils.errors import RequestDeniedException  # noqa


def _alter_tables():
    conn = sq.connect(r"C:\Users\User\PycharmProjects\pythonProject3\Userlib\db_env\databases\userf.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE users (
        username TEXT,
        email TEXT UNIQUE,
        password TEXT,
        id TEXT UNIQUE,
        banned BOOLEAN
    )
    """)
    conn.commit()
    conn.close()


def _second_alter_tables():
    conn = sq.connect(r"C:\Users\User\PycharmProjects\pythonProject3\Userlib\db_env\databases\userf.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE users (
        username TEXT,
        email TEXT UNIQUE,
        password TEXT,
        id TEXT UNIQUE,
        banned BOOLEAN,
        logged_in BOOLEAN,
    )
    """)
    conn.commit()
    conn.close()


def _del_table():
    conn = sq.connect(r"C:\Users\User\PycharmProjects\pythonProject3\Userlib\db_env\databases\userf.db")
    cursor = conn.cursor()
    cursor.execute("DROP TABLE users")
    conn.commit()
    conn.close()


def create_db(name):
    sq.connect(rf'C:\Users\User\PycharmProjects\pythonProject3\Userlib\db_env\databases\{name}')


class Database:
    def __init__(self, database: str | bytes | PathLike[str] | PathLike[bytes], table_name: str,
                 key: bytes | bytearray | memoryview, monobyte: int):
        self.table = table_name
        self.db = Database._resolve_path(database)
        if not self.db.suffix == '.db':
            raise ValueError("DB file must have a '.db' suffix")
        if not len(key) == 32:
            raise ValueError("key must be 32 bytes long")
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

    def init_table(self, name: str):
        cn = sq.connect(self.db)
        crsr = cn.cursor()
        crsr.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {name}(
                username TEXT,
                email TEXT UNIQUE,
                password TEXT,
                id TEXT UNIQUE,
                banned BOOLEAN,
            """)

    def add_user(self, username, email, hashed_password, uid, banned):
        """Add a new user to the database."""
        cn = sq.connect(self.db)
        crsr = cn.cursor()
        crsr.execute(f"INSERT INTO {self.table} (username, email, password, id, banned) VALUES (?, ?, ?, ?, ?)",
                     (username, email, hashed_password, uid, banned))
        cn.commit()
        crsr.close()
        cn.close()

    def get_user(self, identifier: str, method: str = 'id') -> tuple[str, str, str, str, bool] | None:
        """
        Returns user information based on the identifier and method.
        :return (username, email, hash, id, banned_status)
        """

        cn = sq.connect(self.db)
        crsr = cn.cursor()

        if method == 'username':
            crsr.execute(f"SELECT * FROM {self.table} WHERE username=?", (identifier,))
        elif method == 'email':
            crsr.execute(f"SELECT * FROM {self.table} WHERE email=?", (identifier,))
        elif method == 'id':
            crsr.execute(f"SELECT * FROM {self.table} WHERE id=?", (identifier,))
        else:
            crsr.close()
            cn.close()
            raise ValueError("method is unsupported. please use 'username', 'email', or 'id'.")

        user = crsr.fetchone()
        crsr.close()
        cn.close()
        return user

    def delete_user(self, identifier: str, method: str = 'id'):
        """Deletes a user from the database based on the identifier and method."""
        cn = sq.connect(self.db)
        crsr = cn.cursor()

        if method == 'username':
            crsr.execute(f"DELETE FROM {self.table} WHERE username=?", (identifier,))
        elif method == 'email':
            crsr.execute(f"DELETE FROM {self.table} WHERE email=?", (identifier,))
        elif method == 'id':
            crsr.execute(f"DELETE FROM {self.table} WHERE id=?", (identifier,))
        else:
            print("Invalid id_method. Use 'username', 'email', or 'id'.")
            return

        cn.commit()
        crsr.close()
        cn.close()

    def clean(self):
        """Deletes all records from the specified table."""
        cn = sq.connect(self.db)
        crsr = cn.cursor()
        crsr.execute(f"DELETE FROM {self.table}")
        cn.commit()
        cn.close()

    def update_user(self, identifier: str | int, update: str, update_field: str, id_method='id'):
        """Updates a specified field of a user identified by `identifier`. Email cannot be updated."""

        # Connect to the database
        cn = sq.connect(self.db)
        crsr = cn.cursor()

        if self.is_user_banned(identifier, id_method):
            raise RequestDeniedException("This user is banned and cannot be modified.")

        if id_method == 'username':
            if update_field == 'email':
                raise ValueError("Email cannot be updated.")
            elif update_field == 'username':
                crsr.execute(f"UPDATE {self.table} SET username=? WHERE username=?", (update, identifier))
            elif update_field == 'password':
                crsr.execute(f"UPDATE {self.table} SET password=? WHERE username=?", (update, identifier))
            elif update_field == 'banned':
                crsr.execute(f"UPDATE {self.table} SET banned=? WHERE username=?", (update, identifier))
            else:
                raise ValueError("Invalid update field.")

        elif id_method == 'email':
            if update_field == 'username':
                crsr.execute(f"UPDATE {self.table} SET username=? WHERE email=?", (update, identifier))
            elif update_field == 'password':
                crsr.execute(f"UPDATE {self.table} SET password=? WHERE email=?", (update, identifier))
            elif update_field == 'banned':
                crsr.execute(f"UPDATE {self.table} SET banned=? WHERE email=?", (update, identifier))
            else:
                raise ValueError("Invalid update field.")

        elif id_method == 'id':
            if update_field == 'username':
                crsr.execute(f"UPDATE {self.table} SET username=? WHERE id=?", (update, identifier))
            elif update_field == 'password':
                crsr.execute(f"UPDATE {self.table} SET password=? WHERE id=?", (update, identifier))
            elif update_field == 'banned':
                crsr.execute(f"UPDATE {self.table} SET banned=? WHERE id=?", (update, identifier))
            else:
                raise ValueError("Invalid update field.")

        else:
            raise ValueError("Invalid ID method.")

        # Commit the transaction and close the connection
        cn.commit()
        cn.close()

    def is_user_banned(self, identifier: str, id_method: str) -> bool:
        """Check if a user is banned based on their identifier."""
        cn = sq.connect(self.db)
        crsr = cn.cursor()

        if id_method == 'username':
            crsr.execute(f"SELECT banned FROM {self.table} WHERE username=?", (identifier,))
        elif id_method == 'email':
            crsr.execute(f"SELECT banned FROM {self.table} WHERE email=?", (identifier,))
        elif id_method == 'id':
            crsr.execute(f"SELECT banned FROM {self.table} WHERE id=?", (identifier,)
                         )
        else:
            crsr.close()
            cn.close()
            raise ValueError("Invalid ID method.")

        result = crsr.fetchone()
        crsr.close()
        cn.close()

        return result[0] if result else False

    @staticmethod
    def _fetchall():
        cn = sq.connect("databases/userf.db")
        crsr = cn.cursor()
        x = crsr.execute("SELECT * FROM users")
        return x.fetchall()

    @staticmethod
    def fetchall():
        return Database._fetchall()


if __name__ == "__main__":
    db1 = Database(r"C:\Users\User\PycharmProjects\pythonProject3\Userlib\db_env\databases\userf.db", "users", sha256(b'').digest(), 234)
    db1.clean()
    db1.add_user("niggauser_2", "example@example.comcom", "passpassword", "i7845344325bv465bn336745n53467n", False)
    db1.add_user("user1", "user1email@email.com", "passypassword", "4356bn345nb34w56nw3456n34w65n3", False)
    print(db1.get_user('user1', 'username'))

    db1.update_user(1, 'user2', 'username', 'id')
    print(db1.fetchall())
