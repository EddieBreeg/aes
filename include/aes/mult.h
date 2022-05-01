#ifndef AES_MULT_H
#define AES_MULT_H


#ifdef __cplusplus
extern "C"{
#endif

#include "luts.h"

static inline uint8_t mult8(uint8_t a, uint8_t b){
    uint8_t inter = a;
    uint8_t res = (b&1) * a;
    b >>= 1;
    for (int i = 0; i < 7; i++)
    {
        inter = xtime_lut[inter];
        res ^= (b & 1) * inter;
        b >>= 1;
    }
    return res;
}

#ifdef __cplusplus
}
#endif

#endif