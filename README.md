# Enchive : encrypted personal archives

Enchive is a tool encrypts files to yourself for long-term archival.
It's intended as a focused, simple alternative to more complex
solutions such as GnuPG. This program has no external dependencies and
is very easy to build for local use.

Files are secured with uses ChaCha20, Curve25519, and SHA-224.

## Usage

There are only three commands to worry about: `keygen`, `archive`, and
`extract`. The very first thing to do is generate a master keypair
using `keygen`.

    $ enchive keygen

By default, this will create two files in your home directory:
`.enchive.pub` (public key) and `.enchive.sec` (secret key).
Distribute `.enchive.pub` to any machines where you plan to archive
files. It's sufficient to encrypt files, but not to decrypt them.

To archive a file for storage:

    $ enchive archive file.tar.gz

This will encrypt `file.tar.gz` as `file.tar.gz.enchive` (leaving the
original in place). You can safely archive this wherever.

To extract the file later on a machine with `.encrypt.sec`:

    $ enchive extract file.tar.gz.enchive

This will reproduce `file.tar.gz`.

## Notes

There's no effort at error recovery. It bails out on the first error.

## Format

The process for encrypting a file:

1. Generate an ephemeral 256-bit Curve25519 key pair.
2. Perform a Curve25519 Diffie-Hellman key exchange with the master
   key to produce a shared secret.
3. Generate a 64-bit IV for ChaCha20.
5. Initialize ChaCha20 with the shared secret as the key.
4. Write the 8-byte IV.
5. Write the 32-byte ephemeral public key.
6. Encrypt the file with ChaCha20 and write the ciphertext.
7. Write `sha256(key + sha256(plaintext))`.

The process for decrypting a file:

1. Read the 8-byte ChaCha20 IV.
2. Read the 32-byte ephemeral public key
3. Perform a Curve25519 Diffie-Hellman key exchange with the ephemeral
   public key.
4. Initialize ChaCha20 with the shared secret as the key.
5. Decrypt the ciphertext using ChaCha20.
6. Verify `sha256(key + sha256(plaintext))`.
