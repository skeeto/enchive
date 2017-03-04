#define _POSIX_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#define OPTPARSE_IMPLEMENTATION
#include "docs.h"
#include "sha256.h"
#include "chacha.h"
#include "optparse.h"

int curve25519_donna(u8 *p, const u8 *s, const u8 *b);

/* Global options. */
static char *global_random_device = "/dev/urandom";
static char *global_pubkey = 0;
static char *global_seckey = 0;

static struct {
    char *name;
    FILE *file;
} cleanup[2];

static void
cleanup_register(FILE *file, char *name)
{
    if (file) {
        unsigned i;
        for (i = 0; i < sizeof(cleanup) / sizeof(*cleanup); i++) {
            cleanup[i].name = name;
            cleanup[i].file = file;
            return;
        }
    }
    abort();
}

static void
fatal(const char *fmt, ...)
{
    unsigned i;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "enchive: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    for (i = 0; i < sizeof(cleanup) / sizeof(*cleanup); i++) {
        if (cleanup[i].file)
            fclose(cleanup[i].file);
        remove(cleanup[i].name);
    }
    exit(EXIT_FAILURE);
}

static void
get_passphrase_dumb(char *buf, size_t len, char *prompt)
{
    size_t passlen;
    fprintf(stderr, "warning: reading passphrase from stdin with echo\n");
    fputs(prompt, stderr);
    fflush(stderr);
    if (!fgets(buf, len, stdin))
        fatal("could not read passphrase");
    passlen = strlen(buf);
    if (buf[passlen - 1] < ' ')
        buf[passlen - 1] = 0;
}

#if defined(__unix__) || defined(__APPLE__)
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>

static FILE *
secure_creat(char *file)
{
    int fd = open(file, O_CREAT | O_WRONLY, 00600);
    if (fd == -1)
        return 0;
    return fdopen(fd, "wb");
}

static void
get_passphrase(char *buf, size_t len, char *prompt)
{
    int tty = open("/dev/tty", O_RDWR);
    if (tty == -1) {
        get_passphrase_dumb(buf, len, prompt);
    } else {
        char newline = '\n';
        size_t i = 0;
        struct termios old, new;
        write(tty, prompt, strlen(prompt));
        tcgetattr(tty, &old);
        new = old;
        new.c_lflag &= ~ECHO;
        tcsetattr(tty, TCSANOW, &new);
        errno = 0;
        while (i < len - 1 && read(tty, buf + i, 1) == 1) {
            if (buf[i] == '\n' || buf[i] == '\r')
                break;
            i++;
        }
        buf[i] = 0;
        tcsetattr(tty, TCSANOW, &old);
        write(tty, &newline, 1);
        close(tty);
        if (errno)
            fatal("could not read passphrase from /dev/tty");
    }
}
#else

/* fallback to standard open */
static FILE *
secure_creat(char *file)
{
    return fopen(file, "wb");
}

static void
get_passphrase(char *buf, size_t len, char *prompt)
{
    get_passphrase_dumb(buf, len, prompt);
}
#endif

#define KEY_DERIVE_ITERATIONS    0x00400000ul
#define SECKEY_DERIVE_ITERATIONS 0x01000000ul

static void
key_derive(char *key, u8 *buf, unsigned long iterations)
{
    unsigned long i;
    SHA256_CTX ctx[1];
    sha256_init(ctx);
    sha256_final(ctx, buf);
    for (i = 0; i < iterations; i++) {
        sha256_init(ctx);
        sha256_update(ctx, (void *)key, strlen(key));
        sha256_update(ctx, buf, sizeof(buf));
        sha256_final(ctx, buf);
    }
}

#if defined(__unix__) || defined(__APPLE__)
static void
secure_entropy(void *buf, size_t len)
{
    FILE *r = fopen(global_random_device, "rb");
    if (!r)
        fatal("failed to open /dev/urandom");
    if (!fread(buf, len, 1, r))
        fatal("failed to gather entropy");
    fclose(r);
}

#elif defined (_WIN32)
#include <windows.h>

static void
secure_entropy(void *buf, size_t len)
{
    HCRYPTPROV h = 0;
    DWORD type = PROV_RSA_FULL;
    DWORD flags = CRYPT_VERIFYCONTEXT | CRYPT_SILENT;
    if (!CryptAcquireContext(&h, 0, 0, type, flags) ||
        !CryptGenRandom(h, len, buf))
        fatal("failed to gather entropy");
    CryptReleaseContext(h, 0);
}
#endif



static void
generate_secret(u8 *s)
{
    secure_entropy(s, 32);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

static void
compute_public(u8 *p, const u8 *s)
{
    static const u8 b[32] = {9};
    curve25519_donna(p, s, b);
}

static void
compute_shared(u8 *sh, const u8 *s, const u8 *p)
{
    curve25519_donna(sh, s, p);
}

static void
symmetric_encrypt(FILE *in, FILE *out, u8 *key, u8 *iv)
{
    static u8 buffer[2][CHACHA_BLOCKLENGTH * 1024];
    u8 msghash[SHA256_BLOCK_SIZE];
    SHA256_CTX hash[1];
    chacha_ctx ctx[1];
    chacha_keysetup(ctx, key, 256);
    chacha_ivsetup(ctx, iv);
    sha256_init(hash);

    for (;;) {
        size_t z = fread(buffer[0], 1, sizeof(buffer[0]), in);
        if (!z) {
            if (ferror(in))
                fatal("error reading plaintext file");
            break;
        }
        sha256_update(hash, buffer[0], z);
        chacha_encrypt_bytes(ctx, buffer[0], buffer[1], z);
        if (!fwrite(buffer[1], z, 1, out))
            fatal("error writing ciphertext file");
        if (z < sizeof(buffer[0]))
            break;
    }

    sha256_final(hash, msghash);
    sha256_init(hash);
    sha256_update(hash, key, 32);
    sha256_update(hash, msghash, sizeof(msghash));
    sha256_final(hash, msghash);

    if (!fwrite(msghash, SHA256_BLOCK_SIZE, 1, out))
        fatal("error writing checksum to ciphertext file");
    if (fflush(out))
        fatal("error flushing to ciphertext file");
}

static void
symmetric_decrypt(FILE *in, FILE *out, u8 *key, u8 *iv)
{
    static u8 buffer[2][CHACHA_BLOCKLENGTH * 1024 + SHA256_BLOCK_SIZE];
    u8 msghash[SHA256_BLOCK_SIZE];
    SHA256_CTX hash[1];
    chacha_ctx ctx[1];
    chacha_keysetup(ctx, key, 256);
    chacha_ivsetup(ctx, iv);
    sha256_init(hash);

    /* Always keep SHA256_BLOCK_SIZE bytes in the buffer. */
    if (!(fread(buffer[0], SHA256_BLOCK_SIZE, 1, in))) {
        if (ferror(in))
            fatal("cannot read ciphertext file");
        else
            fatal("ciphertext file too short");
    }

    for (;;) {
        u8 *p = buffer[0] + SHA256_BLOCK_SIZE;
        size_t z = fread(p, 1, sizeof(buffer[0]) - SHA256_BLOCK_SIZE, in);
        if (!z) {
            if (ferror(in))
                fatal("error reading ciphertext file");
            break;
        }
        chacha_encrypt_bytes(ctx, buffer[0], buffer[1], z);
        sha256_update(hash, buffer[1], z);
        if (!fwrite(buffer[1], z, 1, out))
            fatal("error writing plaintext file");

        /* Move last SHA256_BLOCK_SIZE bytes to the front. */
        memmove(buffer[0], buffer[0] + z, SHA256_BLOCK_SIZE);

        if (z < sizeof(buffer[0]) - SHA256_BLOCK_SIZE)
            break;
    }

    sha256_final(hash, msghash);
    sha256_init(hash);
    sha256_update(hash, key, 32);
    sha256_update(hash, msghash, sizeof(msghash));
    sha256_final(hash, msghash);

    if (memcmp(buffer[0], msghash, SHA256_BLOCK_SIZE) != 0)
        fatal("checksum mismatch!");
    if (fflush(out))
        fatal("error flushing to plaintext file");

}

static void
prepend_home(char *buf, size_t buflen, char *file)
{
    size_t filelen = strlen(file);
    char *home = getenv("HOME");
    size_t homelen;

    if (!home)
        fatal("no HOME environment, can't figure out public file");
    homelen = strlen(home);
    if (homelen + 1 + filelen + 1 > buflen)
        fatal("HOME is too long");

    memcpy(buf, home, homelen);
    buf[homelen] = '/';
    memcpy(buf + homelen + 1, file, filelen + 1);
}

static char *
default_pubfile(void)
{
    static char buf[4096];
    prepend_home(buf, sizeof(buf), ".enchive.pub");
    return buf;
}

static char *
default_secfile(void)
{
    static char buf[4096];
    prepend_home(buf, sizeof(buf), ".enchive.sec");
    return buf;
}

static void
write_pubkey(char *file, u8 *key)
{
    FILE *f = fopen(file, "wb");
    if (!f)
        fatal("failed to open key file for writing -- %s", file);
    cleanup_register(f, file);
    if (!fwrite(key, 32, 1, f))
        fatal("failed to write key file -- %s", file);
    if (fclose(f))
        fatal("failed to flush key file -- %s", file);
}

static void
write_seckey(char *file, u8 *seckey, int encrypt)
{
    FILE *secfile;
    chacha_ctx cha[1];
    SHA256_CTX sha[1];
    u8 buf[8 + 24 + 32] = {0};
    u8 key[32];

    if (encrypt) {
        char pass[2][256];
        get_passphrase(pass[0], sizeof(pass[0]),
                       "passphrase (empty for none): ");
        get_passphrase(pass[1], sizeof(pass[0]),
                       "passphrase (repeat): ");
        if (strcmp(pass[0], pass[1]) != 0)
            fatal("passphrases don't match");
        if (!pass[0][0]) {

            encrypt = 0;
        }  else {
            key_derive(pass[0], key, KEY_DERIVE_ITERATIONS);

            sha256_init(sha);
            sha256_update(sha, key, 32);
            sha256_final(sha, buf + 8);

            secure_entropy(buf, 8);
        }
    }

    if (encrypt) {
        chacha_keysetup(cha, key, 256);
        chacha_ivsetup(cha, buf);
        chacha_encrypt_bytes(cha, seckey, buf + 32, 32);
    } else {
        memcpy(buf + 32, seckey, 32);
    }

    secfile = secure_creat(file);
    if (!secfile)
        fatal("failed to open key file for writing -- %s", file);
    cleanup_register(secfile, file);
    if (!fwrite(buf, sizeof(buf), 1, secfile))
        fatal("failed to write key file -- %s", file);
    if (fclose(secfile))
        fatal("failed to flush key file -- %s", file);
}

static void
load_pubkey(char *file, u8 *key)
{
    FILE *f = fopen(file, "rb");
    if (!f)
        fatal("failed to open key file for reading -- %s", file);
    if (!fread(key, 32, 1, f))
        fatal("failed to read key file -- %s", file);
    fclose(f);
}

static void
load_seckey(char *file, u8 *seckey)
{
    FILE *secfile;
    chacha_ctx cha[1];
    SHA256_CTX sha[1];
    u8 buf[8 + 24 + 32];
    u8 empty[8] = {0};
    u8 keyhash[SHA256_BLOCK_SIZE];
    u8 key[32];

    secfile = fopen(file, "rb");
    if (!secfile)
        fatal("failed to open key file for reading -- %s", file);
    if (!fread(buf, sizeof(buf), 1, secfile))
        fatal("failed to read key file -- %s", file);
    fclose(secfile);

    if (memcmp(buf, empty, sizeof(empty)) != 0) {
        char pass[256];
        get_passphrase(pass, sizeof(pass), "passphrase: ");
        key_derive(pass, key, KEY_DERIVE_ITERATIONS);

        sha256_init(sha);
        sha256_update(sha, key, 32);
        sha256_final(sha, keyhash);
        if (memcmp(keyhash, buf + 8, 24) != 0)
            fatal("wrong passphrase");

        chacha_keysetup(cha, key, 256);
        chacha_ivsetup(cha, buf);
        chacha_encrypt_bytes(cha, buf + 32, seckey, 32);
    } else {
        memcpy(seckey, buf + 32, 32);
    }
}


enum command {
    COMMAND_UNKNOWN = -2,
    COMMAND_AMBIGUOUS = -1,
    COMMAND_KEYGEN,
    COMMAND_ARCHIVE,
    COMMAND_EXTRACT,
    COMMAND_HELP
};

static const char command_names[][8] = {
    "keygen", "archive", "extract", "help"
};

static enum command
parse_command(char *command)
{
    int found = -2;
    size_t len = strlen(command);
    int i;
    for (i = 0; i < 4; i++) {
        if (strncmp(command, command_names[i], len) == 0) {
            if (found >= 0)
                return COMMAND_AMBIGUOUS;
            found = i;
        }
    }
    return found;
}

static void
command_keygen(struct optparse *options)
{
    static const struct optparse_long keygen[] = {
        {"derive", 'd', OPTPARSE_NONE},
        {"force",  'f', OPTPARSE_NONE},
        {"plain",  'u', OPTPARSE_NONE},
        {0}
    };

    char *pubfile = global_pubkey;
    char *secfile = global_seckey;
    u8 public[32];
    u8 secret[32];
    int clobber = 0;
    int encrypt = 1;
    int derive = 0;

    int option;
    while ((option = optparse_long(options, keygen, 0)) != -1) {
        switch (option) {
            case 'd':
                derive = 1;
                break;
            case 'f':
                clobber = 1;
                break;
            case 'u':
                encrypt = 0;
                break;
            default:
                fatal("%s", options->errmsg);
        }
    }

    if (!pubfile)
        pubfile = default_pubfile();
    if (!clobber && fopen(pubfile, "r"))
        fatal("operation would clobber %s", pubfile);
    if (!secfile)
        secfile = default_secfile();
    if (!clobber && fopen(secfile, "r"))
        fatal("operation would clobber %s", secfile);

    /* Generate secret key. */
    if (derive) {
        char pass[2][256];
        get_passphrase(pass[0], sizeof(pass[0]),
                       "secret key passphrase: ");
        get_passphrase(pass[1], sizeof(pass[0]),
                       "secret key passphrase (repeat): ");
        if (strcmp(pass[0], pass[1]) != 0)
            fatal("passphrases don't match");
        key_derive(pass[0], secret, SECKEY_DERIVE_ITERATIONS);
    } else {
        generate_secret(secret);
    }

    compute_public(public, secret);
    write_pubkey(pubfile, public);
    write_seckey(secfile, secret, encrypt);
}

static void
command_archive(struct optparse *options)
{
    static const struct optparse_long archive[] = {
        {"delete", 'd', OPTPARSE_NONE},
        {0}
    };

    char *infile;
    char *outfile;
    FILE *in = stdin;
    FILE *out = stdout;
    char *pubfile = global_pubkey;
    u8 public[32];
    u8 esecret[32];
    u8 epublic[32];
    u8 shared[32];
    u8 iv[8];
    int delete = 0;

    int option;
    while ((option = optparse_long(options, archive, 0)) != -1) {
        switch (option) {
            case 'd':
                delete = 1;
                break;
            default:
                fatal("%s", options->errmsg);
        }
    }

    if (!pubfile)
        pubfile = default_pubfile();
    load_pubkey(pubfile, public);

    infile = optparse_arg(options);
    if (infile) {
        in = fopen(infile, "rb");
        if (!in)
            fatal("could not open input file -- %s", infile);
    }

    outfile = optparse_arg(options);
    if (!outfile && infile) {
        static const char suffix[] = ".enchive";
        size_t len = strlen(infile);
        outfile = malloc(len + sizeof(suffix));
        if (!outfile)
            fatal("out of memory");
        memcpy(outfile, infile, len);
        memcpy(outfile + len, suffix, sizeof(suffix));
    }
    if (outfile) {
        out = fopen(outfile, "wb");
        if (!out)
            fatal("could not open output file -- %s", infile);
        cleanup_register(out, outfile);
    }

    /* Generare ephemeral keypair. */
    generate_secret(esecret);
    compute_public(epublic, esecret);

    compute_shared(shared, esecret, public);
    secure_entropy(iv, sizeof(iv));
    if (!fwrite(iv, sizeof(iv), 1, out))
        fatal("failed to write IV to archive");
    if (!fwrite(epublic, sizeof(epublic), 1, out))
        fatal("failed to write ephemeral key to archive");
    symmetric_encrypt(in, out, shared, iv);

    if (in != stdin)
        fclose(in);
    if (out != stdout)
        fclose(out); /* already flushed */

    if (delete && infile)
        remove(infile);
}

static void
command_extract(struct optparse *options)
{
    static const struct optparse_long extract[] = {
        {"delete", 'd', OPTPARSE_NONE},
        {0}
    };

    char *infile;
    char *outfile;
    FILE *in = stdin;
    FILE *out = stdout;
    char *secfile = global_seckey;
    u8 secret[32];
    u8 epublic[32];
    u8 shared[32];
    u8 iv[8];
    int delete = 0;

    int option;
    while ((option = optparse_long(options, extract, 0)) != -1) {
        switch (option) {
            case 'd':
                delete = 1;
                break;
            default:
                fatal("%s", options->errmsg);
        }
    }

    if (!secfile)
        secfile = default_secfile();
    load_seckey(secfile, secret);

    infile = optparse_arg(options);
    if (infile) {
        in = fopen(infile, "rb");
        if (!in)
            fatal("could not open input file -- %s", infile);
    }

    outfile = optparse_arg(options);
    if (!outfile && infile) {
        static const char suffix[] = ".enchive";
        size_t slen = sizeof(suffix) - 1;
        size_t len = strlen(infile);
        if (len <= slen || strcmp(suffix, infile + len - slen) != 0)
            fatal("could not determine output filename from %s", infile);
        outfile = malloc(len - slen);
        if (!outfile)
            fatal("out of memory");
        memcpy(outfile, infile, len - slen);
        outfile[len - slen] = 0;
    }
    if (outfile) {
        out = fopen(outfile, "wb");
        if (!out)
            fatal("could not open output file -- %s", infile);
        cleanup_register(out, outfile);
    }

    if (!(fread(iv, sizeof(iv), 1, in)))
        fatal("failed to read IV from archive");
    if (!(fread(epublic, sizeof(epublic), 1, in)))
        fatal("failed to read ephemeral key from archive");
    compute_shared(shared, secret, epublic);
    symmetric_decrypt(in, out, shared, iv);

    if (in != stdin)
        fclose(in);
    if (out != stdout)
        fclose(out); /* already flushed */

    if (delete && infile)
        remove(infile);
}

static void
command_help(struct optparse *options)
{
    static const struct optparse_long help[] = {
        {0}
    };

    char *command;

    int option;
    while ((option = optparse_long(options, help, 0)) != -1) {
        switch (option) {
            default:
                fatal("%s", options->errmsg);
        }
    }

    command = optparse_arg(options);
    if (!command)
        command = "help";

    switch (parse_command(command)) {
        case COMMAND_UNKNOWN:
        case COMMAND_AMBIGUOUS:
            fatal("unknown command -- %s\n", command);
            break;
        case COMMAND_KEYGEN:
            fputs(docs_keygen, stdout);
            break;
        case COMMAND_ARCHIVE:
            fputs(docs_archive, stdout);
            break;
        case COMMAND_EXTRACT:
            fputs(docs_extract, stdout);
            break;
        case COMMAND_HELP:
            fputs(docs_help, stdout);
            break;
    }
}

static void
print_usage(FILE *f)
{
    fputs(docs_usage, f);
}

int
main(int argc, char **argv)
{
    static const struct optparse_long global[] = {
        {"random-device", 'r', OPTPARSE_REQUIRED},
        {"pubkey",        'p', OPTPARSE_REQUIRED},
        {"seckey",        's', OPTPARSE_REQUIRED},
        {0}
    };

    int option;
    char *command;
    struct optparse options[1];
    optparse_init(options, argv);
    options->permute = 0;
    (void)argc;

   while ((option = optparse_long(options, global, 0)) != -1) {
        switch (option) {
            case 'r':
                #ifdef _WIN32
                fprintf(stderr, "warning: --random-device ignored\n");
                #endif
                global_random_device = options->optarg;
                break;
            case 'p':
                global_pubkey = options->optarg;
                break;
            case 's':
                global_seckey = options->optarg;
                break;
            default:
                fatal("%s", options->errmsg);
        }
    }

    command = optparse_arg(options);
    options->permute = 1;
    if (!command) {
        fprintf(stderr, "enchive: missing command\n");
        print_usage(stderr);
        exit(EXIT_FAILURE);
    }

    switch (parse_command(command)) {
        case COMMAND_UNKNOWN:
        case COMMAND_AMBIGUOUS:
            fprintf(stderr, "enchive: unknown command, %s\n", command);
            print_usage(stderr);
            exit(EXIT_FAILURE);
            break;
        case COMMAND_KEYGEN:
            command_keygen(options);
            break;
        case COMMAND_ARCHIVE:
            command_archive(options);
            break;
        case COMMAND_EXTRACT:
            command_extract(options);
            break;
        case COMMAND_HELP:
            command_help(options);
            break;
    }
    return 0;
}
