import sqlite3


def find_user_by_name(conn: sqlite3.Connection, name: str) -> list[tuple]:
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
