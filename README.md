# AES

Couldn't more straightforward: this is a C/C++ implementation of the Advanced Encryption Standard,
as defined in the [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf).

Optimizations have been made, as suggested in the original [AES Proposal: Rijndael article](http://www.cryptosoft.de/docs/Rijndael.pdf). Note, however,
that this implementation (currently) doesn't make use of the AES instruction sets available on various CPUs.

## C Interface

```c
typedef struct aes128 aes128;
typedef struct aes192 aes192;
typedef struct aes256 aes256;

aes128 *aes128_init(const void *key);
aes192 *aes192_init(const void *key);
aes256 *aes256_init(const void *key);

void aes128_encrypt_block(const void *in, void *out, const aes128* aes);
void aes192_encrypt_block(const void *in, void *out, const aes192* aes);
void aes256_encrypt_block(const void *in, void *out, const aes256* aes);

void aes128_decrypt_block(const void* in, void *out, const aes128* aes);
void aes192_decrypt_block(const void* in, void *out, const aes192* aes);
void aes256_decrypt_block(const void* in, void *out, const aes256* aes);

#define aes_done(aes)   free(aes)
```

The init functions allocate memory for the AES key schedule, and return a pointer that should 
be freed when all AES operations are complete. The AES structures have been made opaque for
safety reasons.

### Usage

```c
#include "aes/aes.h"
#include <stdint.h>

int main(int argc, char const *argv[])
{
    const uint8_t in[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t out[16] = {0};
    uint8_t out2[16] = {0};
    uint8_t k[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    
    aes128 *aes = aes128_init(k);

    aes128_encrypt_block(in, out, aes);
    aes128_decrypt_block(out, out2, aes);
    aes_done(aes);
    return 0;
}
```

## C++ interface

```cpp
class aes128{
    uint8_t _w[176];
public:
    aes128(const void *key);
    void encrypt_block(const void *in, void *out) const;
    void decrypt_block(const void *in, void *out) const;
};
class aes192{
    uint8_t _w[208];
public:
    aes192(const void *key);
    void encrypt_block(const void *in, void *out) const;
    void decrypt_block(const void *in, void *out) const;
};
class aes256{
    uint8_t _w[240];
public:
    aes256(const void *key);
    void encrypt_block(const void *in, void *out) const;
    void decrypt_block(const void *in, void *out) const;
};
```

### Usage

```cpp
#include "aes/aes.h"
#include <stdint.h>

int main(int argc, char const *argv[])
{
    const uint8_t in[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t out[16] = {0};
    uint8_t out2[16] = {0};
    /* keys */
    uint8_t k[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

    aes128 aes(k);

    aes.encrypt_block(in, out);
    aes.decrypt_block(out, out2);

    return 0;
}
```

## Tests

Both the C and C++ version come with test programs, to ensure the implementation's validity using test vectors from the [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf).

### C Test

For the full test code, refer to [test.c](test.c).

```
$ ./build/test
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f  
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17  
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f  
================
0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a  
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff  
AES 128 ok
0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91  
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff  
AES 192 ok
0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89  
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff  
AES 256 ok
```

### C++ Test

For the full test code, refer to [test.cpp](test.cpp).

```
$ ./build/cpp_test 
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f  
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17  
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f  
================
0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a  
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff  
AES 128 ok
0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91  
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff  
AES 192 ok
0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89  
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff  
AES 256 ok
```
