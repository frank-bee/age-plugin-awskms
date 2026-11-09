# Test data

`testkey.pem` is a throwaway RSA-2048 key generated only for these tests. It
plays the role of the private half of a KMS key in the fake KMS. It protects
nothing and must never be used for anything else.

`vector.age` was encrypted to `recipient.txt` (the public half of `testkey.pem`
under an example ARN). `TestVector` decrypts it to make sure the archive
format stays compatible across releases.
