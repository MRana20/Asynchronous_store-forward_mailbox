"""
Tests for src/crypto_utils.py. Fail with NotImplementedError until you
implement encrypt_and_tag/verify_and_decrypt.
"""

import pytest

from src.crypto_utils import encrypt_and_tag, verify_and_decrypt


ENC_KEY = b"0" * 32
MAC_KEY = b"1" * 32


def test_roundtrip_encrypt_then_decrypt():
    plaintext = b"attack at dawn"
    encrypted = encrypt_and_tag(ENC_KEY, MAC_KEY, plaintext)
    decrypted = verify_and_decrypt(ENC_KEY, MAC_KEY, encrypted)
    assert decrypted == plaintext


def test_tampered_ciphertext_is_rejected():
    plaintext = b"attack at dawn"
    encrypted = encrypt_and_tag(ENC_KEY, MAC_KEY, plaintext)

    tampered = type(encrypted)(
        iv=encrypted.iv,
        ciphertext=bytes([encrypted.ciphertext[0] ^ 0xFF]) + encrypted.ciphertext[1:],
        tag=encrypted.tag,
    )
    with pytest.raises(Exception):
        verify_and_decrypt(ENC_KEY, MAC_KEY, tampered)


def test_wrong_mac_key_is_rejected():
    plaintext = b"attack at dawn"
    encrypted = encrypt_and_tag(ENC_KEY, MAC_KEY, plaintext)
    wrong_mac_key = b"2" * 32
    with pytest.raises(Exception):
        verify_and_decrypt(ENC_KEY, wrong_mac_key, encrypted)
