#include "aes/mult.h"
#include "aes/endian.h"
#include <stdio.h>

#if __BYTE_ORDER != __LITTLE_ENDIAN

#define RotWord(x, k)   (((x) << (k)) | ((x) >> (32 - (k))))

#else

#define RotWord(x, k)   (((x) >> (k)) | ((x) << (32 - (k))))

#define xtime2(x)   ((x) ^ xtime_lut[(x)])

#endif

uint32_t mix(uint8_t x){
    x = sbox_lut[x];
    uint8_t b[] = {
        xtime_lut[x],
        x,
        x,
        xtime_lut[x] ^ x,
    };
    return *(uint32_t*)b;
}

int main(int argc, char const *argv[])
{
    uint8_t s[] = {
        0x19, 0x3d, 0xe3, 0xbe,
        0xa0, 0xf4, 0xe2, 0x2b, 
        0x9a, 0xc6, 0x8d, 0x2a, 
        0xe9, 0xf8, 0x48, 0x08,
    };
    uint8_t k[] = {
        0xa0, 0xfa, 0xfe, 0x17,
        0x88, 0x54, 0x2c, 0xb1,
        0x23, 0xa3, 0x39, 0x39,
        0x2a, 0x6c, 0x76, 0x05,
    };
    uint8_t out[16];
    uint32_t *T = (uint32_t*)round_lut;

    uint32_t c0 = ((uint32_t*)k)[0] ^ T[(s)[0]] ^ RotWord(T[(s)[5]], 24) ^ RotWord(T[(s)[10]], 16) ^ RotWord(T[(s)[15]], 8);
    uint32_t c1 = ((uint32_t*)k)[1] ^ T[(s)[4]] ^ RotWord(T[(s)[9]], 24) ^ RotWord(T[(s)[14]], 16) ^ RotWord(T[(s)[3]], 8);
    uint32_t c2 = ((uint32_t*)k)[2] ^ T[(s)[8]] ^ RotWord(T[(s)[13]], 24) ^ RotWord(T[(s)[2]], 16) ^ RotWord(T[(s)[7]], 8);
    uint32_t c3 = ((uint32_t*)k)[3] ^ T[(s)[12]] ^ RotWord(T[(s)[1]], 24) ^ RotWord(T[(s)[6]], 16) ^ RotWord(T[(s)[11]], 8);

    ((uint32_t*)s)[0] = c0;
    ((uint32_t*)s)[1] = c1;
    ((uint32_t*)s)[2] = c2;
    ((uint32_t*)s)[3] = c3;

    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", s[i]);
    }
    
    printf("\n");

    return 0;
}
