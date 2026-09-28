from auth import hash_password, verify_password


def test_hash_and_verify_roundtrip():
    salt, digest = hash_password("correct-horse-battery")
    assert verify_password("correct-horse-battery", salt, digest)
    assert not verify_password("wrong-password", salt, digest)
