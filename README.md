# Enchive : encrypted personal archives

Enchive is a tool to encrypt files to yourself for long-term archival.
It's a focused, simple alternative to more complex solutions such as
GnuPG or encrypted filesystems. Enchive has no external dependencies
and is trivial to build for local use. Portability is emphasized over
performance.

Supported platforms: Linux, BSD, macOS, Windows

The name is a portmanteau of "encrypt" and "archive," pronounced
en'kīv.

Files are secured with ChaCha20, Curve25519, and HMAC-SHA256.

Manual page: [`enchive(1)`](http://nullprogram.com/enchive/)

## Installation

Clone this repository, then:

    $ make PREFIX=/usr install

This will install both the compiled binary and manual page under
`PREFIX`. For staged installs, `DESTDIR` is also supported. The binary
doesn't have any external dependencies and doesn't actually need to be
installed before use.

## Usage

There are only three commands to worry about: `keygen`, `archive`, and
`extract`. The very first thing to do is generate a master keypair
using `keygen`. You will be prompted for the passphrase to protect the
secret key, just like `ssh-keygen`.

    $ enchive keygen

By default, this will create two files in `$XDG_CONFIG_HOME/enchive`
(or `$HOME/.config/enchive`): `enchive.pub` (public key) and
`enchive.sec` (secret key). On Windows, these are found under
`%APPDATA%\enchive` instead. Distribute `enchive.pub` to any machines
where you plan to archive files. It's sufficient to encrypt files, but
not to decrypt them.

To archive a file for storage:

    $ enchive archive sensitive.zip

This will encrypt `sensitive.zip` as `sensitive.zip.enchive` (leaving
the original in place). You can safely archive this wherever.

To extract the file on a machine with `encrypt.sec`, use `extract`. It
will prompt for the passphrase you entered during key generation.

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
key derivation iterations (e.g. `--derive=26`). The default is 29.
This is a power two exponent, so every increment doubles the cost both
in memory and computational demands.

If you want to change your protection passphrase, use the `--edit`
option with `keygen`. It will load the secret key as if it were going
to "extract" an archive, then write it back out with the new options.
This mode will also regenerate the public key file whether or not it
exists.

Enchive has a built-in protection key agent that keeps the protection
key in memory for a configurable period of time (default: 15 minutes)
after a protection passphrase has been read. This allows many files to
be decrypted inside a brief window with only a single passphrase
prompt. Use the `--agent` (`-a`) global option to enable it. If it's
enabled by default, use `--no-agent` to turn it off.

    $ enchive --agent extract file.enchive

Unlike gpg-agent and ssh-agent, this agent need not be started ahead
of time. It is started on demand, shuts down on timeout, and does not
coordinate with environment variables. One agent is created per unique
secret key file. This feature requires a unix-like system.

## Notes

The major version number increments each time any of the file formats
change, including the key derivation algorithm.

There's no effort at error recovery. It bails out on early on the
first error. It should clean up any incomplete files when it does so.

A purposeful design choice is that encrypted/archived files have no
distinguishing marks whatsoever (magic numbers, etc.), making them
indistinguishable from random data.

No effort is made to set stdin and stdout to binary mode. For Windows
this means passing data through Enchive using stdin/stdout isn't
useful. This is low priority because Microsoft's [UCRT file streams
are broken anyway][pipe] when pipes are involved.

### Frequently asked questions

> This tool will never achieve critical mass, so what's the point?

Enchive doesn't need to interact with any other systems or people, so
there's no need for critical mass, nor that there are any other users.

> Why can't you use an existing/established tool instead?

I'm not aware of any tool that does everything Enchive does. GnuPG
comes close, but doesn't support deriving a key pair from a
passphrase. If you're aware of an equal or better tool, please let me
know.

> Isn't it dangerous to derive a key pair from a passphrase?

It is when it's done incorrectly. However, Enchive uses a memory-hard
key derivation scheme that makes cracking passphrases very expensive —
prohibitively so for any decent passphrase. This is because anyone who
has access to even a single encrypted file can mount an offline
attack.

Deriving asymmetric keys from a passphrase is a standard practice in
the Bitcoin world: [brainwallets][bw]. The caveat is that the
passphrase must be sufficiently long, preferably chosen by a computer
or [with dice][dw].

When generating a master key, Enchive's default configuration is
extremely paranoid. It would be far cheaper to break into your home
and perform an evil maid attack than it would be to crack even a short
passphrase. This is not the weak point.

> Shouldn't the initialization vector (IV) be generated randomly?

The purpose of an IV is to allow the same key to be safely used
multiple times. This is particularly important when the same key is
derived on different occasions by Diffie-Hellman between the same key
pair. Enchive generates a random ephemeral key pair each time a file
is encrypted, so the IV is unnecessary.

Since ChaCha20 requires an IV regardless, Enchive simply uses the hash
of the key. This has the additional effect of allowing the client to
verify its symmetric key before beginning decryption. Otherwise a
wrong key would only be detected by the MAC after decryption has
completed.

> I'm getting the error "Value too large for defined data type."

This is a flaw in the 32-bit version of glibc that prevents C programs
from even opening files larger than 2GB. Compile with "large file
support" enabled:

    make CFLAGS='-O3 -D_FILE_OFFSET_BITS=64'

Alternatively, use your shell to open files for Enchive:

    $ enchive archive <largefile >largefile.enchive

Note that Enchive will not be able to delete shell-opened files in case
of errors (tampering, etc.).

## Encryption/decryption algorithm

The process for encrypting a file:

1. Generate an ephemeral 256-bit Curve25519 key pair.
2. Perform a Curve25519 Diffie-Hellman key exchange with the master
   key to produce a shared secret.
3. SHA-256 hash the shared secret to generate a 64-bit IV.
4. Add the format number to the first byte of the IV.
5. Initialize ChaCha20 with the shared secret as the key.
6. Write the 8-byte IV.
7. Write the 32-byte ephemeral public key.
8. Encrypt the file with ChaCha20 and write the ciphertext.
9. Write `HMAC(key, plaintext)`.

The process for decrypting a file:

1. Read the 8-byte ChaCha20 IV.
2. Read the 32-byte ephemeral public key.
3. Perform a Curve25519 Diffie-Hellman key exchange with the ephemeral
   public key.
4. Validate the IV against the shared secret hash and format version.
5. Initialize ChaCha20 with the shared secret as the key.
6. Decrypt the ciphertext using ChaCha20.
7. Verify `HMAC(key, plaintext)`.

## Key derivation algorithm

Enchive uses an scrypt-like algorithm for key derivation, requiring a
large buffer of random access memory. Derivation is controlled by a
single difficulty exponent *D*. Secret key derivation requires 512MB
of memory (D=29) by default, and protection key derivation requires
32MB by default (D=25). The salt for the secret key is all zeros.

1. Allocate a `(1 << D) + 32` byte buffer, *M*.
2. Compute `HMAC_SHA256(salt, passphrase)` and write this 32-byte
   result to the beginning of *M*.
3. For each uninitialized 32-byte chunk in *M*, compute the SHA-256
   hash of the previous 32-byte chunk.
4. Initialize a byte pointer *P* to the last 32-byte chunk of *M*.
5. Compute the SHA-256 hash, *H*, of the 32 bytes at *P*.
6. Overwrite the memory at *P* with *H*.
7. Take the first *D* bits of *H* and use this value to set a new *P*
   pointing into *M*.
8. Repeat from step 5 `1 << (D - 5)` times.
9. *P* points to the result.

## Compilation

To build on any unix-like system, run `make`. The resulting binary has
no dependencies or external data, so you can just copy/move this into
your `PATH`.

    $ make

The easiest way to build with Visual Studio is to use the amalgamation
build. On any unix-like system (requires `sed`):

    $ make amalgamation

This will create `enchive-cli.c`, a standalone C program that you can
copy anywhere and compile. Over on Windows:

    C:\> cl.exe -nologo -Ox enchive-cli.c advapi32.lib

The compile-time options below also apply to this amalgamation build.

### Compile-time configuration

Various options and defaults can be configured at compile time using C
defines (`-D...`).

#### `ENCHIVE_OPTION_AGENT`

Whether to expose the `--agent` and `--no-agent` option. This option
is 0 by default on Windows since agents are unsupported.

#### `ENCHIVE_AGENT_TIMEOUT`

The default agent timeout in seconds. This can be configured at run
time with an optional argument to `--agent`.

#### `ENCHIVE_AGENT_DEFAULT_ENABLED`

Whether or not to enable the agent by default. This can be explicitly
overridden at run time with `--agent` and `--no-agent`.

#### `ENCHIVE_PINENTRY_DEFAULT`

The default program to use for `pinentry`.

#### `ENCHIVE_PINENTRY_DEFAULT_ENABLED`

Whether or not to use `pinentry` by default when reading passphrases.

#### `ENCHIVE_KEY_DERIVE_ITERATIONS`

Power-of-two exponent for protection key derivation. Can be configured
at run time with `--iterations`.

#### `ENCHIVE_SECKEY_DERIVE_ITERATIONS`

Power-of-two exponent for secret key derivation. Can be configured at
run time with the optional argument to `--derive`.

#### `ENCHIVE_PASSPHRASE_MAX`

Maximum passphrase size in bytes, including null terminator.


[myths]: http://www.2uo.de/myths-about-urandom/
[djb]: https://blog.cr.yp.to/20140205-entropy.html
[getrandom]: https://manpages.debian.org/testing/manpages-dev/getrandom.2.en.html
[getentropy]: http://man.openbsd.org/OpenBSD-current/man2/getentropy.2
[csp]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa380246(v=vs.85).aspx
[pipe]: https://radiance-online.org/pipermail/radiance-dev/2016-March/001576.html
[bw]: https://en.bitcoin.it/wiki/Brainwallet
[dw]: http://world.std.com/~reinhold/diceware.html
