from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(plain_password):
    return generate_password_hash(str(plain_password or ''))


def verify_password(stored_hash, plain_password):
    if not stored_hash:
        return False
    return check_password_hash(str(stored_hash), str(plain_password or ''))
