#ifndef CHACHA_H
#define CHACHA_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;

typedef struct
{
  u32 input[16];
} chacha_ctx;

void chacha_keysetup(chacha_ctx *x,const u8 *k,u32 kbits);
void chacha_ivsetup(chacha_ctx *x,const u8 *iv);
void chacha_encrypt_bytes(chacha_ctx *x,const u8 *m,u8 *c,u32 bytes);
void chacha_decrypt_bytes(chacha_ctx *x,const u8 *c,u8 *m,u32 bytes);
void chacha_keystream_bytes(chacha_ctx *x,u8 *stream,u32 bytes);

#endif /* CHACHA_H */
