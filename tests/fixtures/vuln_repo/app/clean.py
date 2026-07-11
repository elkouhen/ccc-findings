import sqlite3
import subprocess


def find_user_by_name(conn: sqlite3.Connection, name: str) -> list[tuple]:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()


def list_directory(path: str) -> str:
    result = subprocess.run(["ls", "-la", path], capture_output=True, text=True)
    return result.stdout
