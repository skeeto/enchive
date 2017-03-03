static const char docs_usage[] =
"usage enchive [--random-device <file>]\n"
"              [--pubkey <file>] [--seckey <file>]\n"
"              <command> [args]\n"
"\n"
"Commands:\n"
"  keygen      generate a new master keypair\n"
"  archive     archive using the public key\n"
"  extract     extract from an archive using the secret key\n"
"  help        get help on a specific topic\n"
"\n"
"  --random-device <file> select the entropy source [/dev/urandom]\n"
"  --pubkey <file>        set the public key file [~/.enchive.pub]\n"
"  --seckey <file>        set the secret key file [~/.enchive.sec]\n"
"Enchive archives files by encrypting them to yourself using your\n"
"public key. It uses ChaCha20, Curve25519, and SHA-224.\n";

static const char docs_keygen[] =
"usage: enchive keygen [-f|--force]\n"
"  Generate a brand new keypair.\n"
"\n"
"  --force, -f        overwrite any existing keys (default: no clobber)\n"
"  --plain, -u        don't encrypt the secret key\n"
"  --derive, -d       derive secret key from a passphrase\n"
"\n"
"The global --pubkey and --seckey options select the filenames.\n";

static const char docs_archive[] =
"usage: enchive archive [input [output]]\n"
"  Encrypt a single file for archival (only requires public key).\n"
"\n"
"If no output filename is given, an '.enchive' suffix is given to\n"
"the input filename. The original file is untouched. If no\n"
"filenames are given, Enchive will encrypt standard input to\n"
"standard output.\n" ;

static const char docs_extract[] =
"usage: enchive extract [input [output]]\n"
"  Extract a single file from archival (requires secret key).\n"
"\n"
"If no output filename is given, the '.enchive' suffix is removed\n"
"from the input filename. It is an error for the input to lack an\n"
".enchive suffix. If no filenames are given, Enchive will dencrypt\n"
"standard input to standard output.\n";

static const char docs_help[] =
"usage: enchive help [command]\n"
"  Provide help on a specific command\n";
