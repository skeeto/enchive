#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define OPTPARSE_IMPLEMENTATION
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

static void
secure_entropy(void *buf, size_t len)
{
    FILE *r = fopen("/dev/urandom", "rb");
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
    static u8 buffer[2][64 * 1024];
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
                fatal("error reading source file");
            break;
        }
        sha256_update(hash, buffer[0], z);
        chacha_encrypt_bytes(ctx, buffer[0], buffer[1], z);
        if (!fwrite(buffer[1], z, 1, out))
            fatal("error writing destination file");
    }

    sha256_final(hash, sha256);
    if (!fwrite(sha256, SHA224_BLOCK_SIZE, 1, out))
        fatal("error writing checksum to destination file");
    if (fflush(out))
        fatal("error flushing to destination");
}

static void
symmetric_decrypt(FILE *in, FILE *out, u8 *key, u8 *iv)
{
    static u8 buffer[2][64 * 1024];
    u8 sha256[SHA256_BLOCK_SIZE];
    SHA256_CTX hash[1];
    chacha_ctx ctx[1];
    chacha_keysetup(ctx, key, 256);
    chacha_ivsetup(ctx, iv);
    sha256_init(hash);

    /* Always keep SHA224_BLOCK_SIZE bytes in the buffer. */
    if (!(fread(buffer[0], SHA224_BLOCK_SIZE, 1, in))) {
        if (ferror(in))
            fatal("error initially reading source file");
        else
            fatal("source file missing checksum");
    }

    for (;;) {
        u8 *p = buffer[0] + SHA224_BLOCK_SIZE;
        size_t z = fread(p, 1, sizeof(buffer[0]) - SHA224_BLOCK_SIZE, in);
        if (!z) {
            if (ferror(in))
                fatal("error reading source file");
            break;
        }
        chacha_encrypt_bytes(ctx, buffer[0], buffer[1], z);
        sha256_update(hash, buffer[1], z);
        if (!fwrite(buffer[1], z, 1, out))
            fatal("error writing destination file");

        /* Move last SHA224_BLOCK_SIZE bytes to the front. */
        memmove(buffer[0], buffer[0] + z, SHA224_BLOCK_SIZE);
    }
    if (fflush(out))
        fatal("error flushing to destination");

    sha256_final(hash, sha256);
    if (memcmp(buffer[0], sha256, SHA224_BLOCK_SIZE) != 0)
        fatal("checksum mismatch!");
}

static const char *
default_pubfile(void)
{
    return "key.pub";
}

static const char *
default_secfile(void)
{
    return "key.sec";
}

static void
load_key(const char *file, u8 *key)
{
    FILE *f = fopen(file, "rb");
    if (!f)
        fatal("failed to open key file, %s", file);
    if (!fread(key, 32, 1, f))
        fatal("failed to read key file, %s", file);
    fclose(f);
}

static void
write_key(const char *file, const u8 *key)
{
    FILE *f = fopen(file, "wb");
    if (!f)
        fatal("failed to open key file, %s", file);
    if (!fwrite(key, 32, 1, f))
        fatal("failed to write key file, %s", file);
    fclose(f);
}

static void
command_keygen(struct optparse *options)
{
    static const struct optparse_long keygen[] = {
        {0}
    };

    const char *pubfile = default_pubfile();
    const char *secfile = default_secfile();
    u8 public[32];
    u8 secret[32];

    int option;
    while ((option = optparse_long(options, keygen, 0)) != -1) {
        switch (option) {
        }
    }

    generate_secret(secret);
    compute_public(public, secret);
    write_key(pubfile, public);
    write_key(secfile, secret);
}

static void
command_archive(struct optparse *options)
{
    static const struct optparse_long archive[] = {
        {0}
    };

    const char *pubfile = default_pubfile();
    u8 public[32];
    u8 esecret[32];
    u8 epublic[32];
    u8 shared[32];
    u8 iv[8];

    int option;
    while ((option = optparse_long(options, archive, 0)) != -1) {
        switch (option) {
        }
    }

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

    const char *secfile = default_secfile();
    u8 secret[32];
    u8 epublic[32];
    u8 shared[32];
    u8 iv[8];

    int option;
    while ((option = optparse_long(options, extract, 0)) != -1) {
        switch (option) {
        }
    }

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

    int option;
    while ((option = optparse_long(options, help, 0)) != -1) {
        switch (option) {
        }
    }
}

int
main(int argc, char **argv)
{
    static const struct optparse_long global[] = {
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
        }
    }

    command = optparse_arg(options);
    options->permute = 1;

    if (!command) {
        command_help(options);
        fatal("missing command");
    } else if (strcmp(command, "keygen") == 0) {
         command_keygen(options);
    } else if (strcmp(command, "archive") == 0) {
        command_archive(options);
    } else if (strcmp(command, "extract") == 0) {
        command_extract(options);
    } else {
        command_help(options);
        fatal("unknown command, %s", command);
    }
    return 0;
}
