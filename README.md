# Enchive : encrypted personal archives

Enchive is a tool encrypts files to yourself for long-term archival.
It's intended as a focused, simple alternative to more complex
solutions such as GnuPG. This program has no external dependencies and
is very easy to build for local use. Portability is emphasized over
performance.

Supported platforms: Linux, BSD, macOS, Windows

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

Enchive has a built-in protection key agent that keeps the protection
key in memory for a configurable period of time (default: 15 minutes)
after a protection passphrase has been read. This allows any files to
be decrypted inside this window with only a single passphrase prompt.
Use the `--agent` (`-a`) global option to enable it. If it's enabled
by default, use `--no-agent` to turn it off.

    $ enchive --agent extract file.enchive

Unlike gpg-agent and ssh-agent, this agent need not be started ahead
of time. It is started on demand, shuts down on timeout, and does not
coordinate with environment variables. One agent is created per unique
secret key file. This feature requires a unix-like system.

## Notes

There's no effort at error recovery. It bails out on early on the
first error. It should clean up any incomplete files when it does so.

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

## Compile-time configuration

Various options and defaults can be configured at compile time using C
defines (`-D...`). These also apply to the amalgamation build.

### `ENCHIVE_RANDOM_DEVICE`

For unix-like systems, this is the default source of entropy when
creating keys and IVs. The default value is `/dev/urandom`. You could
set this to `/dev/random`, though that's [pointless][djb] and [a waste
of time][myths]. It can be changed at run time with `--random-device`.

In the future, Enchive may first try `getrandom(2)` / `getentropy(2)`.

### `ENCHIVE_OPTION_RANDOM_DEVICE`

Whether or not the `--random-device` option should be available. This
option is 0 by default on Windows, where Enchive always uses a
[Cryptographic Service Provider][csp].

### `ENCHIVE_OPTION_AGENT`

Whether to expose the `--agent` and `--no-agent` option. This option
is 0 by default on Windows since agents are unsupported.

### `ENCHIVE_AGENT_TIMEOUT`

The default agent timeout in seconds. This can be configured at run
time with an optional argument to `--agent`.

### `ENCHIVE_AGENT_DEFAULT_ENABLED`

Whether or not to enable the agent by default. This can be explicitly
overridden at run time with `--agent` and `--no-agent`.

### `ENCHIVE_KEY_DERIVE_ITERATIONS`

Power-of-two exponent for protection key derivation. Can be configured
at run time with `--iterations`.

### `ENCHIVE_SECKEY_DERIVE_ITERATIONS`

Power-of-two exponent for secret key derivation. Can be configured at
run time with the optional argument to `--derive`.

### `ENCHIVE_PASSPHRASE_MAX`

Maximum passphrase size in bytes, including null terminator.


[myths]: http://www.2uo.de/myths-about-urandom/
[djb]: https://blog.cr.yp.to/20140205-entropy.html
[getrandom]: https://manpages.debian.org/testing/manpages-dev/getrandom.2.en.html
[getentropy]: http://man.openbsd.org/OpenBSD-current/man2/getentropy.2
[csp]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa380246(v=vs.85).aspx
