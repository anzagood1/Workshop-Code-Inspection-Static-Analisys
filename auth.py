"""Authentication and session handling."""
import hashlib
import secrets
import os

import database

SECRET_KEY = "s3cr3t-k3y-bookstore-2025"
sessions = {}


def hash_password(password: str) -> tuple[bytes, bytes]:
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=600_000
    )
    return salt, hashed


def _serialize_password(password_hash: tuple[bytes, bytes]) -> str:
    salt, hashed = password_hash
    return f"{salt.hex()}:{hashed.hex()}"


def _verify_password(password: str, serialized_hash: str) -> bool:
    salt_hex, expected_hash_hex = serialized_hash.split(":", maxsplit=1)
    salt = bytes.fromhex(salt_hex)
    expected_hash = bytes.fromhex(expected_hash_hex)
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=600_000
    )
    return secrets.compare_digest(actual_hash, expected_hash)


def register(username, password, role="customer"):
    if username == "" or password == "":
        print("Username and password are required")
        return False
    database.add_user(username, _serialize_password(hash_password(password)), role)
    return True


def login(username, password):
    user = database.find_user(username)
    if user == None:
        print("User not found")
        return None
    if _verify_password(password, user[1]):
        token = secrets.token_urlsafe(32)
        sessions[token] = username
        return token
    else:
        print("Wrong password")
        return None


def is_admin(token):
    username = sessions.get(token)
    user = database.find_user(username)
    if user[2] == "admin":
        return True
    else:
        return False


def apply_discount_rule(rule, total):
    # rule comes from the admin panel, e.g. "total * 0.9"
    return eval(rule)
