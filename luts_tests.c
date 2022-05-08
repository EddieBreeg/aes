#include "aes/endian.h"
#include "aes/luts.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if __BYTE_ORDER != __LITTLE_ENDIAN

#define RotWord(x, k)   (((x) << (k)) | ((x) >> (32 - (k))))

#else

#define RotWord(x, k)   (((x) >> (k)) | ((x) << (32 - (k))))

#endif

static inline uint8_t xtime(uint8_t x){
    return (x << 1) ^ ((x >> 7) * 0x1B);
}

uint32_t mix(uint8_t x){
    x = sbox[x];
    uint8_t b[] = {
        xtime(x),
        x,
        x,
        xtime(x) ^ x,
    };
    return *(uint32_t*)b;
}
static inline uint8_t mult8(uint8_t a, uint8_t b){
    uint8_t inter = a;
    uint8_t res = (b&1) * a;
    b >>= 1;
    for (int i = 0; i < 7; i++)
    {
        inter = xtime(inter);
        res ^= (b & 1) * inter;
        b >>= 1;
    }
    return res;
}
uint32_t inv_mix(uint8_t x){
    uint8_t b[] = {
        mult8(x, 0x0e),
        mult8(x, 0x09),
        mult8(x, 0x0d),
        mult8(x, 0x0b),
    };
    return *(uint32_t*)b;
}
#define mix_column(a, b, c, d, T)   ((T)[(a)] ^  RotWord((T)[(b)], 24) ^ RotWord((T)[(c)], 16) ^ RotWord((T)[(d)],  8))

#define inverse_full_round(s, k, T){\
    uint32_t c0 = mix_column(   \
        (k)[0] ^ inv_sbox[(s)[0]],  \
        (k)[1] ^ inv_sbox[(s)[13]],     \
        (k)[2] ^  inv_sbox[(s)[10]],    \
        (k)[3] ^  inv_sbox[(s)[7]], (T));   \
    uint32_t c1 = mix_column(   \
        (k)[4] ^ inv_sbox[(s)[4]],  \
        (k)[5] ^ inv_sbox[(s)[1]],  \
        (k)[6] ^  inv_sbox[(s)[14]],    \
        (k)[7] ^  inv_sbox[(s)[11]], (T));  \
    uint32_t c2 = mix_column(   \
        (k)[8] ^ inv_sbox[(s)[8]],  \
        (k)[9] ^ inv_sbox[(s)[5]],  \
        (k)[10] ^  inv_sbox[(s)[2]],    \
        (k)[11] ^  inv_sbox[(s)[15]], (T)); \
    uint32_t c3 = mix_column(   \
        (k)[12] ^ inv_sbox[(s)[12]],    \
        (k)[13] ^ inv_sbox[(s)[9]],     \
        (k)[14] ^  inv_sbox[(s)[6]],    \
        (k)[15] ^  inv_sbox[(s)[3]], (T));  \
    ((uint32_t*)(s))[0] = c0; \
    ((uint32_t*)(s))[1] = c1; \
    ((uint32_t*)(s))[2] = c2; \
    ((uint32_t*)(s))[3] = c3; \
}

int main(int argc, char const *argv[])
{
    uint8_t s[] = {
        0x7a, 0xd5, 0xfd, 0xa7, 0x89, 0xef, 0x4e, 0x27, 0x2b, 0xca, 0x10, 0x0b, 0x3d, 0x9f, 0xf5, 0x9f
    };
    uint8_t k[] = {0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68, 0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e};
    
    inverse_full_round(s, k, (uint32_t*)inv_round_lut);
    

    for (int i = 0; i < 16; i++)
        printf("%02x", s[i]);
    printf("\n");    
    return 0;
}
