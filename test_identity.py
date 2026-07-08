"""
Tests for src/identity.py. These will fail with NotImplementedError
until you implement Identity.generate/sign/verify -- that's the point,
use them to check your work as you go.
"""

from src.identity import Identity


def test_generate_produces_matching_keypair():
    identity = Identity.generate("alice")
    assert identity.name == "alice"
    assert identity.private_key.public_key().public_numbers() == identity.public_key.public_numbers()


def test_sign_then_verify_succeeds():
    identity = Identity.generate("alice")
    data = b"some data to sign"
    signature = identity.sign(data)
    assert Identity.verify(identity.public_key, data, signature) is True


def test_verify_fails_on_tampered_data():
    identity = Identity.generate("alice")
    data = b"some data to sign"
    signature = identity.sign(data)
    assert Identity.verify(identity.public_key, b"different data", signature) is False


def test_verify_fails_with_wrong_public_key():
    alice = Identity.generate("alice")
    mallory = Identity.generate("mallory")
    data = b"some data to sign"
    signature = alice.sign(data)
    # Mallory's key should NOT validate Alice's signature -- this is the
    # exact check that stops a MITM from substituting their own identity.
    assert Identity.verify(mallory.public_key, data, signature) is False
