#include "aes/aes.h"
#include "aes/mult.h"
#include "aes/endian.h"
#include <string.h>
#include <stdlib.h>


#define AES128_SCHED_SIZE   176
#define AES192_SCHED_SIZE   208
#define AES256_SCHED_SIZE   240

typedef struct aes128{
    uint8_t w[AES128_SCHED_SIZE];
} aes128;
typedef struct aes192{
    uint8_t w[AES192_SCHED_SIZE];
} aes192;
typedef struct aes256{
    uint8_t w[AES256_SCHED_SIZE];
} aes256;





#define SubBytes(s, n){\
    for (int i = 0; i < (n); i++)     \
        (s)[i] = sbox_lut[(s)[i]];      \
}
#define InvSubBytes(s, n){\
    for (int i = 0; i < (n); i++)     \
        (s)[i] = inv_sbox_lut[(s)[i]];  \
}

static inline uint32_t SubWord(uint32_t x){
    uint8_t *b = (uint8_t*)&x;
    SubBytes(b, 4);
    return x;
}

#if __BYTE_ORDER != __LITTLE_ENDIAN

static inline uint32_t lendian32(uint32_t x){
    uint8_t b[] = {
        (uint8_t)x,
        (uint8_t)(x >> 8),
        (uint8_t)(x >> 16),
        (uint8_t)(x >> 24)
    };
    return *(uint32_t*)b;
}
#define RotWord(x, k)   (((x) << (k)) | ((x) >> (32 - (k))))

#else

static inline uint32_t lendian32(uint32_t x){ return x; }
#define RotWord(x, k)   (((x) >> (k)) | ((x) << (32 - (k))))

#endif


#define aes_mix_column(c){\
    uint8_t x = xtime_lut[(c)[0]] ^ (c)[1] ^ xtime_lut[(c)[1]] ^ (c)[2] ^ (c)[3];   \
    uint8_t y = xtime_lut[(c)[1]] ^ (c)[2] ^ xtime_lut[(c)[2]] ^ (c)[3] ^ (c)[0];   \
    uint8_t z = xtime_lut[(c)[2]] ^ (c)[3] ^ xtime_lut[(c)[3]] ^ (c)[0] ^ (c)[1];   \
    (c)[3] = xtime_lut[(c)[3]] ^ (c)[0] ^ xtime_lut[(c)[0]] ^ (c)[1] ^ (c)[2];   \
    (c)[0] = x; (c)[1] = y; (c)[2] = z; \
}

static inline void aes128_key_expansion(const void* k, aes128* aes)
{
    memcpy(aes->w, k, 16);
    const uint8_t Rcon[] = {0,1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    for (int i = 4; i < (AES128_SCHED_SIZE>>2); i++)
    {
        uint32_t temp = ((uint32_t*)aes->w)[i-1];
        if(!(i & 3)){
            #if __BYTE_ORDER == __LITTLE_ENDIAN
            temp = SubWord(RotWord(temp, 8)) ^ Rcon[i>>2];
            #else
            temp = SubWord(RotWord(temp)) ^ (Rcon[i>>2] << 24);
            #endif
        }
        ((uint32_t*)aes->w)[i] = ((uint32_t*)aes->w)[i-4] ^ temp;
    }
}
static inline void aes192_key_expansion(const void* k, aes192* aes)
{
    const uint8_t Rcon[] = {0,1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80};
    memcpy(aes->w, k, 24);
    for (int i = 6; i < (AES192_SCHED_SIZE>>2); i++)
    {
        uint32_t temp = ((uint32_t*)aes->w)[i-1];
        if(!(i % 6)){
            #if __BYTE_ORDER == __LITTLE_ENDIAN
            temp = SubWord(RotWord(temp, 8)) ^ Rcon[i / 6];
            #else
            temp = SubWord(RotWord(temp)) ^ (Rcon[i/6] << 24);
            #endif
        }
        ((uint32_t*)aes->w)[i] = ((uint32_t*)aes->w)[i-6] ^ temp;
    }
}
static inline void aes256_key_expansion(const void* k, aes256* aes)
{
    const uint8_t Rcon[] = {0,1, 2, 4, 8, 0x10, 0x20, 0x40};
    memcpy(aes->w, k, 32);
    for (int i = 8; i < (AES256_SCHED_SIZE>>2); i++)
    {
        uint32_t temp = ((uint32_t*)aes->w)[i-1];
        if(!(i & 7)){
            #if __BYTE_ORDER == __LITTLE_ENDIAN
            temp = SubWord(RotWord(temp, 8)) ^ Rcon[i>>3];
            #else
            temp = SubWord(RotWord(temp)) ^ (Rcon[i>>3] << 24);
            #endif
        }
        else if(i & 7 == 4)
            temp = SubWord(temp);
        ((uint32_t*)aes->w)[i] = ((uint32_t*)aes->w)[i-8] ^ temp;
    }
}
static inline void aes_full_round(uint8_t *s, const uint8_t *k){
    uint32_t *T = (uint32_t*)round_lut;

    uint32_t c0 = ((uint32_t*)k)[0] ^ T[s[0]] ^ RotWord(T[s[5]], 24) ^ RotWord(T[s[10]], 16) ^ RotWord(T[s[15]], 8);
    uint32_t c1 = ((uint32_t*)k)[1] ^ T[s[4]] ^ RotWord(T[s[9]], 24) ^ RotWord(T[s[14]], 16) ^ RotWord(T[s[3]], 8);
    uint32_t c2 = ((uint32_t*)k)[2] ^ T[s[8]] ^ RotWord(T[s[13]], 24) ^ RotWord(T[s[2]], 16) ^ RotWord(T[s[7]], 8);
    uint32_t c3 = ((uint32_t*)k)[3] ^ T[s[12]] ^ RotWord(T[s[1]], 24) ^ RotWord(T[s[6]], 16) ^ RotWord(T[s[11]], 8);

    ((uint32_t*)s)[0] = c0;
    ((uint32_t*)s)[1] = c1;
    ((uint32_t*)s)[2] = c2;
    ((uint32_t*)s)[3] = c3;
}
#define aes_last_round(state, k){   \
    uint8_t tmp[] = {   \
        sbox_lut[state[0]], sbox_lut[state[5]], sbox_lut[state[10]], sbox_lut[state[15]],   \
        sbox_lut[state[4]], sbox_lut[state[9]], sbox_lut[state[14]], sbox_lut[state[3]],    \
        sbox_lut[state[8]], sbox_lut[state[13]], sbox_lut[state[2]], sbox_lut[state[7]],    \
        sbox_lut[state[12]], sbox_lut[state[1]], sbox_lut[state[6]], sbox_lut[state[11]],   \
    };  \
    *(uint32_t*)(state) = *(uint32_t*)(k)  ^ *(uint32_t*)(tmp); \
    *(uint32_t*)(state+4) = *(uint32_t*)(k+4) ^ *(uint32_t*)(tmp+4); \
    *(uint32_t*)(state+8) = *(uint32_t*)(k+8) ^ *(uint32_t*)(tmp+8); \
    *(uint32_t*)(state+12) = *(uint32_t*)(k+12) ^ *(uint32_t*)(tmp+12);   \
}

aes128 *aes128_init(const void *key){
    aes128 *aes = malloc(sizeof(*aes));
    if(!aes) return NULL;
    aes128_key_expansion((uint8_t*)key, aes);
    return aes;
}
void aes128_done(aes128 *aes){ free(aes); }

void aes128_encrypt_block(const void *in, void *out, const aes128* aes)
{
    uint8_t *state = (uint8_t*)out;
    // copy the input to the output
    for(int i=0; i<16; ++i) 
        state[i] = ((uint8_t*)in)[i] ^ aes->w[i];

    for(int i=1; i<10; ++i)
        aes_full_round(state, aes->w + (i<<4));
    aes_last_round(state, aes->w + 160);
}