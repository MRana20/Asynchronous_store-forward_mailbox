# (ONGOING) Asynchronous_store-forward_mailbox
The premise: two users want to exchange encrypted messages without both being online at the same time, and without ever having met to swap keys in person.

Each user generates a long-term RSA keypair (their identity). They also generate a DH keypair (an ephemeral "prekey") and sign the prekey's public value with their RSA private key. They publish their RSA public key and signed prekey to a shared directory.
When Alice wants to message Bob, she fetches Bob's prekey bundle, verifies the RSA signature against the SHA256 hash to confirm it really came from Bob, then runs the DH exchange to get a shared secret.
The raw DH secret gets run through a SHA256-based key derivation function to produce a separate encryption key and a MAC key.
The message gets encrypted and tagged with an HMAC-SHA256 for integrity, then dropped in the mailbox for Bob to pick up whenever he comes online.
Stretch goal that makes this genuinely impressive: after each exchange, both sides derive a new DH keypair and chain the next key off the SHA256 hash of the previous one.
