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

    $ enchive archive <file>

This will encrypt `file` as `file.enchive` (leaving the original in
place). You can safely archive this wherever.

To extract the file later on a machine with `.encrypt.sec`:

    $ enchive extract <file.enchive>

This will reproduce `file`.
