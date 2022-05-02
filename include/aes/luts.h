#ifndef AES_LUTS_H
#define AES_LUTS_H


#if defined(__cplusplus)
extern "C"{
#endif // __cplusplus

#include <stdint.h>

extern uint8_t xtime_lut[256]; /* soon to be removed */
extern uint8_t sbox_lut[256];
extern uint8_t inv_sbox_lut[256];
extern uint8_t round_lut[1024];

#if defined(__cplusplus)
}
#endif

#endif