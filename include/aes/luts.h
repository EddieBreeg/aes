#ifndef AES_LUTS_H
#define AES_LUTS_H


#if defined(__cplusplus)
extern "C"{
#endif // __cplusplus

#include <stdint.h>

extern uint8_t sbox[256];
extern uint8_t inv_sbox[256];
extern uint8_t round_lut[1024];
extern uint8_t inv_round_lut[1024];

#if defined(__cplusplus)
}
#endif

#endif