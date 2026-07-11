import random


def generate_session_token() -> str:
    return str(random.random())
