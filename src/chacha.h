#ifndef CHACHA_H
#define CHACHA_H

#include "../config.h"

#define CHACHA_BLOCKLENGTH 64

typedef struct {
    u32 input[16];
} chacha_ctx;

void chacha_keysetup(chacha_ctx *x,const u8 *k,u32 kbits);
void chacha_ivsetup(chacha_ctx *x,const u8 *iv);
void chacha_encrypt_bytes(chacha_ctx *x,const u8 *m,u8 *c,u32 bytes);

#endif /* CHACHA_H */
