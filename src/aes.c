#include "aes/aes.h"
#include "aes/luts.h"
#include "aes/endian.h"
#include <string.h>

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
        (s)[i] = sbox[(s)[i]];      \
}

static inline uint32_t SubWord(uint32_t x){
    uint8_t *b = (uint8_t*)&x;
    SubBytes(b, 4);
    return x;
}

#if __BYTE_ORDER != __LITTLE_ENDIAN

#define RotWord(x, k)   (((x) << (k)) | ((x) >> (32 - (k))))

#else

#define RotWord(x, k)   (((x) >> (k)) | ((x) << (32 - (k))))

#endif


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
        else if(!(i & 3))
            temp = SubWord(temp);
        ((uint32_t*)aes->w)[i] = ((uint32_t*)aes->w)[i-8] ^ temp;
    }
}

#define mix_column(a, b, c, d, T) ((T)[(a)] ^ RotWord((T)[(b)], 24) ^ RotWord((T)[(c)], 16) ^ RotWord((T)[(d)], 8))

static inline void full_round(uint8_t *s, const uint8_t *k){
    uint32_t *T = (uint32_t*)round_lut;

    uint32_t c0 = ((uint32_t*)k)[0] ^ mix_column(s[0], s[5], s[10], s[15], T);
    uint32_t c1 = ((uint32_t*)k)[1] ^ mix_column(s[4], s[9], s[14], s[3], T);
    uint32_t c2 = ((uint32_t*)k)[2] ^ mix_column(s[8], s[13], s[2], s[7], T);
    uint32_t c3 = ((uint32_t*)k)[3] ^ mix_column(s[12], s[1], s[6], s[11], T);

    ((uint32_t*)s)[0] = c0;
    ((uint32_t*)s)[1] = c1;
    ((uint32_t*)s)[2] = c2;
    ((uint32_t*)s)[3] = c3;
}
#define last_round(state, k){   \
    uint8_t tmp[] = {   \
        sbox[state[0]], sbox[state[5]], sbox[state[10]], sbox[state[15]],   \
        sbox[state[4]], sbox[state[9]], sbox[state[14]], sbox[state[3]],    \
        sbox[state[8]], sbox[state[13]], sbox[state[2]], sbox[state[7]],    \
        sbox[state[12]], sbox[state[1]], sbox[state[6]], sbox[state[11]],   \
    };  \
    *(uint32_t*)(state) = *(uint32_t*)(k)  ^ *(uint32_t*)(tmp); \
    *(uint32_t*)(state+4) = *(uint32_t*)(k+4) ^ *(uint32_t*)(tmp+4); \
    *(uint32_t*)(state+8) = *(uint32_t*)(k+8) ^ *(uint32_t*)(tmp+8); \
    *(uint32_t*)(state+12) = *(uint32_t*)(k+12) ^ *(uint32_t*)(tmp+12);   \
}
#define inverse_full_round(s, k){\
    uint32_t c0 = mix_column(   \
        (k)[0] ^ inv_sbox[(s)[0]],  \
        (k)[1] ^ inv_sbox[(s)[13]],     \
        (k)[2] ^  inv_sbox[(s)[10]],    \
        (k)[3] ^  inv_sbox[(s)[7]], (uint32_t*)inv_round_lut);   \
    uint32_t c1 = mix_column(   \
        (k)[4] ^ inv_sbox[(s)[4]],  \
        (k)[5] ^ inv_sbox[(s)[1]],  \
        (k)[6] ^  inv_sbox[(s)[14]],    \
        (k)[7] ^  inv_sbox[(s)[11]], (uint32_t*)inv_round_lut);  \
    uint32_t c2 = mix_column(   \
        (k)[8] ^ inv_sbox[(s)[8]],  \
        (k)[9] ^ inv_sbox[(s)[5]],  \
        (k)[10] ^  inv_sbox[(s)[2]],    \
        (k)[11] ^  inv_sbox[(s)[15]], (uint32_t*)inv_round_lut); \
    uint32_t c3 = mix_column(   \
        (k)[12] ^ inv_sbox[(s)[12]],    \
        (k)[13] ^ inv_sbox[(s)[9]],     \
        (k)[14] ^  inv_sbox[(s)[6]],    \
        (k)[15] ^  inv_sbox[(s)[3]], (uint32_t*)inv_round_lut);  \
    ((uint32_t*)(s))[0] = c0; \
    ((uint32_t*)(s))[1] = c1; \
    ((uint32_t*)(s))[2] = c2; \
    ((uint32_t*)(s))[3] = c3; \
}
#define inv_last_round(state, k){   \
    uint8_t tmp[] = {   \
        inv_sbox[state[0]], inv_sbox[state[13]], inv_sbox[state[10]], inv_sbox[state[7]],   \
        inv_sbox[state[4]], inv_sbox[state[1]], inv_sbox[state[14]], inv_sbox[state[11]],    \
        inv_sbox[state[8]], inv_sbox[state[5]], inv_sbox[state[2]], inv_sbox[state[15]],    \
        inv_sbox[state[12]], inv_sbox[state[9]], inv_sbox[state[6]], inv_sbox[state[3]],   \
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
aes192 *aes192_init(const void *key){
    aes192 *aes = malloc(sizeof(*aes));
    if(!aes) return NULL;
    aes192_key_expansion((uint8_t*)key, aes);
    return aes;
}
aes256 *aes256_init(const void *key){
    aes256 *aes = malloc(sizeof(*aes));
    if(!aes) return NULL;
    aes256_key_expansion((uint8_t*)key, aes);
    return aes;
}

void aes128_set_key(aes128* aes, const void *key)
{
    aes128_key_expansion(key, aes);
}
void aes192_set_key(aes192* aes, const void *key)
{
    aes192_key_expansion(key, aes);
}
void aes256_set_key(aes256* aes, const void *key)
{
    aes256_key_expansion(key, aes);
}

#define encrypt_block(in, out, aes, nRounds){ \
    uint8_t *state = (uint8_t*)out; \
    for(int i=0; i<16; ++i) \
        state[i] = ((uint8_t*)in)[i] ^ aes->w[i];\
    for(int i=1; i<(nRounds); ++i)\
        full_round(state, aes->w + (i<<4));\
    last_round(state, aes->w + (nRounds<<4));\
}
#define decrypt_block(in, out, aes, nRounds){\
    uint8_t *state = (uint8_t*)out; \
    for(int i=0; i<16; ++i) \
        state[i] = ((uint8_t*)in)[i] ^ aes->w[(nRounds<<4) + i];    \
    for(int i=nRounds-1; i>0; --i)  \
        inverse_full_round(state, aes->w + (i<<4))    \
    inv_last_round(state, aes->w)   \
}

void aes128_encrypt_block(const void *in, void *out, const aes128* aes)
{
    encrypt_block(in, out, aes, 10);
}
void aes192_encrypt_block(const void *in, void *out, const aes192* aes)
{
    encrypt_block(in, out, aes, 12);
}
void aes256_encrypt_block(const void *in, void *out, const aes256* aes)
{
    encrypt_block(in, out, aes, 14);
}
void aes128_decrypt_block(const void* in, void *out, const aes128* aes)
{
    decrypt_block(in, out, aes, 10);
}
void aes192_decrypt_block(const void* in, void *out, const aes192* aes)
{
    decrypt_block(in, out, aes, 12);
}
void aes256_decrypt_block(const void* in, void *out, const aes256* aes)
{
    decrypt_block(in, out, aes, 14);
}