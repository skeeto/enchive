static const char *docs_usage[] = {
"usage enchive [-p|--pubkey <file>] [-s|--seckey <file>]",
#if ENCHIVE_OPTION_RANDOM_DEVICE
"              [--random-device <file>]",
#endif
"              <command> [args]",
"",
"Commands (unique prefixes accepted):",
"  keygen      generate a new master keypair",
"  archive     archive using the public key",
"  extract     extract from an archive using the secret key",
"  help        get help on a specific topic",
"",
"  --random-device <file> select the entropy source [/dev/urandom]",
"  --pubkey <file>, -p    set the public key file [~/.enchive.pub]",
"  --seckey <file>, -s    set the secret key file [~/.enchive.sec]",
"",
"Enchive archives files by encrypting them to yourself using your",
"public key. It uses ChaCha20, Curve25519, and SHA-224.",
0};

static const char *docs_keygen[] = {
"usage: enchive keygen [-d|--derive[=count]] [-e|--edit] [-f|--force]",
"                      [-p|--plain] [-k|--iterations count]",
"  Generate a brand new keypair.",
"",
"  --derive[=<n>]     derive secret key from a passphrase [24]",
"  --edit             edit the protection on an existing key",
"  --iterations <n>   iterations for protection key derivation [20]",
"  --force, -f        overwrite any existing keys (default: no clobber)",
"  --plain, -u        don't encrypt the secret key with a protection key",
"",
"The global --pubkey and --seckey options select the filenames.",
0};

static const char *docs_archive[] = {
"usage: enchive archive [input [output]]",
"  Encrypt a single file for archival (only requires public key).",
"",
"  --delete, -d       delete input file after successful encryption",
"",
"If no output filename is given, an '.enchive' suffix is given to",
"the input filename. The original file is untouched. If no",
"filenames are given, Enchive will encrypt standard input to",
"standard output.",
0};

static const char *docs_extract[] = {
"usage: enchive extract [input [output]]",
"  Extract a single file from archival (requires secret key).",
"",
"  --delete, -d       delete input file after successful decryption",
"",
"If no output filename is given, the '.enchive' suffix is removed",
"from the input filename. It is an error for the input to lack an",
".enchive suffix. If no filenames are given, Enchive will dencrypt",
"standard input to standard output.",
0};

static const char *docs_help[] = {
"usage: enchive help [command]",
"  Provide help on a specific command",
0};
