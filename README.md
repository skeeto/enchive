# Enchive : encrypted personal archives

Enchive is a tool encrypts files to yourself for long-term archival.
It's intended as a focused, simple alternative to more complex
solutions such as GnuPG. This program has no external dependencies and
is very easy to build for local use. Portability is emphasized over
performance.

Files are secured with uses ChaCha20, Curve25519, and SHA-256.

## Usage

There are only three commands to worry about: `keygen`, `archive`, and
`extract`. The very first thing to do is generate a master keypair
using `keygen`. You will be prompted for the passphrase to protect the
secret key, just like `ssh-keygen`.

    $ enchive keygen

By default, this will create two files in your home directory:
`.enchive.pub` (public key) and `.enchive.sec` (secret key).
Distribute `.enchive.pub` to any machines where you plan to archive
files. It's sufficient to encrypt files, but not to decrypt them.

To archive a file for storage:

    $ enchive archive sensitive.zip

This will encrypt `sensitive.zip` as `sensitive.zip.enchive` (leaving
the original in place). You can safely archive this wherever.

To extract the file on a machine with `.encrypt.sec`, use `extract`.
It will prompt for the passphrase you entered during key generation.

    $ enchive extract sensitive.zip.enchive

The original `sensitive.zip` will be reproduced.

With no filenames, `archive` and `extract` operate on standard input
and output.

### Key management

One of the core features of Enchive is the ability to derive an
asymmetric key pair from a passphrase. This means you can store your
archive key in your brain! To access this feature, use the `--derive`
(`-d`) option with the `keygen` command.

    $ enchive keygen --derive

There's an optional argument to `--derive` that controls the number of
key derivation iterations (e.g. `--derive=26`). The default is 24.
This is a power two exponent, so every increment doubles the cost.

If you want to change your protection passphrase, use the `--edit`
option with `keygen`. It will load the secret key as if it were going
to "extract" an archive, then write it back out with the new options.
This mode will also regenerate the public key file.

## Notes

There's no effort at error recovery. It bails out on early on the
first error. It should clean up any incomplete files when it does so.

The `--derive` key generation option can be used to produce
deterministic keys which you can re-derive should your secret key
lost. This key derivation function is run more aggressively (slowly)
when generating a master key.

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

## Roadmap

* Symmetric key management: change the passphrase on your secret key.
* Decrypt multiple files in a short period: some kind of key agent?
* Improve key generation.
