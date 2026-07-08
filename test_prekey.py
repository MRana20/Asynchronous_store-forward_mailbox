import pytest

from src.identity import Identity
from src.prekey import (
    load_dh_parameters,
    generate_prekey,
    create_signed_bundle,
    verify_bundle,
    compute_shared_secret,
    serialize_dh_public,
    PrekeyBundle,
)


@pytest.fixture(scope="module")
def parameters():
    return load_dh_parameters()


def test_both_sides_derive_the_same_shared_secret(parameters):
    alice_dh = generate_prekey(parameters)
    bob_dh = generate_prekey(parameters)

    alice_secret = compute_shared_secret(alice_dh, serialize_dh_public(bob_dh.public_key()))
    bob_secret = compute_shared_secret(bob_dh, serialize_dh_public(alice_dh.public_key()))

    assert alice_secret == bob_secret


def test_signed_bundle_verifies_against_the_right_identity(parameters):
    bob_identity = Identity.generate("bob")
    bob_dh = generate_prekey(parameters)
    bundle = create_signed_bundle(bob_identity, bob_dh)

    assert verify_bundle(bundle, bob_identity.public_key) is True


def test_tampered_bundle_fails_verification(parameters):
    bob_identity = Identity.generate("bob")
    bob_dh = generate_prekey(parameters)
    bundle = create_signed_bundle(bob_identity, bob_dh)

    # Simulate a MITM swapping in their own DH public value while
    # keeping Bob's claimed identity -- signature must fail.
    mallory_dh = generate_prekey(parameters)
    forged_bundle = PrekeyBundle(
        owner="bob",
        public_value_bytes=serialize_dh_public(mallory_dh.public_key()),
        signature=bundle.signature,  # old signature, new (wrong) value
    )

    assert verify_bundle(forged_bundle, bob_identity.public_key) is False
