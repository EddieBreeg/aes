#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C"{
#endif

#include "mult.h"

typedef struct aes128 aes128;
typedef struct aes192 aes192;
typedef struct aes256 aes256;

aes128 *aes128_init(const void *key);
aes192 *aes192_init(const void *key);
aes256 *aes256_init(const void *key);

void aes128_encrypt_block(const void *in, void *out, const aes128* aes);
void aes192_encrypt_block(const void *in, void *out, const aes192* aes);
void aes256_encrypt_block(const void *in, void *out, const aes256* aes);


void aes128_done(aes128 *aes);
void aes192_done(aes192 *aes);
void aes256_done(aes256 *aes);

#ifdef __cplusplus
}
#endif

#endif