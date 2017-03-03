#include <stdio.h>
#include "ecrypt-sync.h"

int
main(void)
{
    static u8 key[32];
    static u8 iv[8];
    static u8 buffer[2][4096 * 4096];
    size_t in = fread(buffer[0], 1, sizeof(buffer[0]), stdin);
    ECRYPT_ctx ctx[1];
    ECRYPT_keysetup(ctx, key, 256, 64);
    ECRYPT_ivsetup(ctx, iv);
    ECRYPT_encrypt_bytes(ctx, buffer[0], buffer[1], in);
    fwrite(buffer[1], 1, in, stdout);
    return 0;
}
