#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define OPTPARSE_IMPLEMENTATION
#include "docs.h"
#include "sha256.h"
#include "chacha.h"
#include "optparse.h"

int curve25519_donna(u8 *p, const u8 *s, const u8 *b);

static void
fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "enchive: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

/* Global options. */
static char *global_random_device = "/dev/urandom";
static char *global_pubkey = 0;
static char *global_seckey = 0;

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
    u8 sha256[SHA256_BLOCK_SIZE];
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

    sha256_final(hash, sha256);
    if (!fwrite(sha256, SHA224_BLOCK_SIZE, 1, out))
        fatal("error writing checksum to ciphertext file");
    if (fflush(out))
        fatal("error flushing to ciphertext file");
}

static void
symmetric_decrypt(FILE *in, FILE *out, u8 *key, u8 *iv)
{
    static u8 buffer[2][CHACHA_BLOCKLENGTH * 1024 + SHA224_BLOCK_SIZE];
    u8 sha256[SHA256_BLOCK_SIZE];
    SHA256_CTX hash[1];
    chacha_ctx ctx[1];
    chacha_keysetup(ctx, key, 256);
    chacha_ivsetup(ctx, iv);
    sha256_init(hash);

    /* Always keep SHA224_BLOCK_SIZE bytes in the buffer. */
    if (!(fread(buffer[0], SHA224_BLOCK_SIZE, 1, in))) {
        if (ferror(in))
            fatal("cannot read ciphertext file");
        else
            fatal("ciphertext file too short");
    }

    for (;;) {
        u8 *p = buffer[0] + SHA224_BLOCK_SIZE;
        size_t z = fread(p, 1, sizeof(buffer[0]) - SHA224_BLOCK_SIZE, in);
        if (!z) {
            if (ferror(in))
                fatal("error reading ciphertext file");
            break;
        }
        chacha_encrypt_bytes(ctx, buffer[0], buffer[1], z);
        sha256_update(hash, buffer[1], z);
        if (!fwrite(buffer[1], z, 1, out))
            fatal("error writing plaintext file");

        /* Move last SHA224_BLOCK_SIZE bytes to the front. */
        memmove(buffer[0], buffer[0] + z, SHA224_BLOCK_SIZE);

        if (z < sizeof(buffer[0]) - SHA224_BLOCK_SIZE)
            break;
    }

    sha256_final(hash, sha256);
    if (memcmp(buffer[0], sha256, SHA224_BLOCK_SIZE) != 0)
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
load_key(const char *file, u8 *key)
{
    FILE *f = fopen(file, "rb");
    if (!f)
        fatal("failed to open key file for reading -- %s", file);
    if (!fread(key, 32, 1, f))
        fatal("failed to read key file -- %s", file);
    fclose(f);
}

static void
write_key(const char *file, const u8 *key, int clobber)
{
    FILE *f;

    if (!clobber && fopen(file, "r"))
        fatal("operation would clobber %s", file);
    f = fopen(file, "wb");
    if (!f)
        fatal("failed to open key file for writing -- %s", file);
    if (!fwrite(key, 32, 1, f))
        fatal("failed to write key file -- %s", file);
    fclose(f);
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
        {"force", 'f', OPTPARSE_NONE},
        {0}
    };

    char *pubfile = global_pubkey;
    char *secfile = global_seckey;
    u8 public[32];
    u8 secret[32];
    int clobber = 0;

    int option;
    while ((option = optparse_long(options, keygen, 0)) != -1) {
        switch (option) {
            case 'f':
                clobber = 1;
                break;
            default:
                fatal("%s", options->errmsg);
        }
    }

    if (!pubfile)
        pubfile = default_pubfile();
    if (!secfile)
        secfile = default_secfile();

    generate_secret(secret);
    compute_public(public, secret);
    write_key(pubfile, public, clobber);
    write_key(secfile, secret, clobber);
}

static void
command_archive(struct optparse *options)
{
    static const struct optparse_long archive[] = {
        {0}
    };

    char *pubfile = global_pubkey;
    u8 public[32];
    u8 esecret[32];
    u8 epublic[32];
    u8 shared[32];
    u8 iv[8];

    int option;
    while ((option = optparse_long(options, archive, 0)) != -1) {
        switch (option) {
            default:
                fatal("%s", options->errmsg);
        }
    }

    if (!pubfile)
        pubfile = default_pubfile();
    load_key(pubfile, public);

    /* Generare ephemeral keypair. */
    generate_secret(esecret);
    compute_public(epublic, esecret);

    compute_shared(shared, esecret, public);
    secure_entropy(iv, sizeof(iv));
    if (!fwrite(iv, sizeof(iv), 1, stdout))
        fatal("failed to write IV to archive");
    if (!fwrite(epublic, sizeof(epublic), 1, stdout))
        fatal("failed to write ephemeral key to archive");
    symmetric_encrypt(stdin, stdout, shared, iv);
}

static void
command_extract(struct optparse *options)
{
    static const struct optparse_long extract[] = {
        {0}
    };

    char *secfile = global_seckey;
    u8 secret[32];
    u8 epublic[32];
    u8 shared[32];
    u8 iv[8];

    int option;
    while ((option = optparse_long(options, extract, 0)) != -1) {
        switch (option) {
        }
    }

    if (!secfile)
        secfile = default_secfile();
    load_key(secfile, secret);

    if (!(fread(iv, sizeof(iv), 1, stdin)))
        fatal("failed to read IV from archive");
    if (!(fread(epublic, sizeof(epublic), 1, stdin)))
        fatal("failed to read ephemeral key from archive");
    compute_shared(shared, secret, epublic);
    symmetric_decrypt(stdin, stdout, shared, iv);
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
