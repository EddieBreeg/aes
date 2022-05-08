/* 
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
*/
#ifndef AES_H
#define AES_H

#ifndef __cplusplus

#include <stdlib.h>

typedef struct aes128 aes128;
typedef struct aes192 aes192;
typedef struct aes256 aes256;

aes128 *aes128_init(const void *key);
aes192 *aes192_init(const void *key);
aes256 *aes256_init(const void *key);

void aes128_set_key(aes128* aes, const void *key);
void aes192_set_key(aes192* aes, const void *key);
void aes256_set_key(aes256* aes, const void *key);

void aes128_encrypt_block(const void *in, void *out, const aes128* aes);
void aes192_encrypt_block(const void *in, void *out, const aes192* aes);
void aes256_encrypt_block(const void *in, void *out, const aes256* aes);

void aes128_decrypt_block(const void* in, void *out, const aes128* aes);
void aes192_decrypt_block(const void* in, void *out, const aes192* aes);
void aes256_decrypt_block(const void* in, void *out, const aes256* aes);

#define aes_done(aes)   free(aes)

#else

#include <inttypes.h>

class aes128{
    uint8_t _w[176];
public:
    aes128(const void *key);
    aes128(const aes128& other) = delete;
    void encrypt_block(const void *in, void *out) const;
    void decrypt_block(const void *in, void *out) const;
    void set_key(const void *key);
};
class aes192{
    uint8_t _w[208];
public:
    aes192(const void *key);
    aes192(const aes192& other) = delete;
    void encrypt_block(const void *in, void *out) const;
    void decrypt_block(const void *in, void *out) const;
    void set_key(const void *key);
};
class aes256{
    uint8_t _w[240];
public:
    aes256(const void *key);
    aes256(const aes256& other) = delete;
    void encrypt_block(const void *in, void *out) const;
    void decrypt_block(const void *in, void *out) const;
    void set_key(const void *key);
};

#endif

#endif