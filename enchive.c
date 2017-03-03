#include <stdio.h>
#include "chacha.h"

int
main(void)
{
    static u8 key[32];
    static u8 iv[8];
    static u8 buffer[2][4096 * 4096];
    size_t in = fread(buffer[0], 1, sizeof(buffer[0]), stdin);
    chacha_ctx ctx[1];
    chacha_keysetup(ctx, key, 256);
    chacha_ivsetup(ctx, iv);
    chacha_encrypt_bytes(ctx, buffer[0], buffer[1], in);
    fwrite(buffer[1], 1, in, stdout);
    return 0;
}
