from src.kdf import derive_keys
def test_derive_keys_returns_32_byte_keys():
    keys = derive_keys(b"some raw shared secret")
    assert len(keys.enc_key) == 32
    assert len(keys.mac_key) == 32


def test_enc_key_and_mac_key_are_different():
    keys = derive_keys(b"some raw shared secret")
    assert keys.enc_key != keys.mac_key


def test_same_input_gives_same_output_deterministic():
    keys1 = derive_keys(b"same secret", info=b"async-mailbox v1", salt=b"fixed-salt")
    keys2 = derive_keys(b"same secret", info=b"async-mailbox v1", salt=b"fixed-salt")
    assert keys1.enc_key == keys2.enc_key
    assert keys1.mac_key == keys2.mac_key


def test_different_secrets_give_different_keys():
    keys1 = derive_keys(b"secret one")
    keys2 = derive_keys(b"secret two")
    assert keys1.enc_key != keys2.enc_key
