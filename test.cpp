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
#include "aes/aes.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define STYLE_ERROR "\033[1;31m"
#define STYLE_GOOD "\033[1;32m"
#define STYLE_DEFAULT "\033[0m"

void printBlock(uint8_t b[16], int n){
    for (int i = 0; i < n; i++){
        printf("0x%02x, ", b[i]);
    }
    printf("\b\b \n");
}
int check(const uint8_t *expected, const uint8_t *actual){
    for (int i = 0; i < 16; i++)
        if(expected[i] != actual[i]) return i;
    return -1;    
}

int main(int argc, char const *argv[])
{
    const uint8_t in[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t out[16] = {0};
    uint8_t out2[16] = {0};
    /* keys */
    uint8_t k[16];
    uint8_t k2[24];
    uint8_t k3[32] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};

    const uint8_t exp1[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    const uint8_t exp2[] = {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91};
    const uint8_t exp3[] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};
    
    memcpy(k, k3, 16);
    memcpy(k2, k3, 24);

    printBlock(k, 16);
    printBlock(k2, 24);
    printBlock(k3, 32);
    printf("================\n");

    aes128 aes(k);
    aes192 aes2(k2);
    aes256 aes3(k3);

    int r;

    aes.encrypt_block(in, out);
    printBlock(out, 16);
    if((r = check(exp1, out)) >= 0){
        printf(STYLE_ERROR "Error with AES 128 encrypt at index %i: expected %02x, got %02x" STYLE_DEFAULT "\n", 
            r, exp1[r], out[r]);
        return 1;
    }
    aes.decrypt_block(out, out2);
    printBlock(out2, 16);
    if((r = check(in, out2)) >= 0){
        printf(STYLE_ERROR "Error with AES 128 decrypt at index %i: expected %02x, got %02x" STYLE_DEFAULT "\n", 
            r, in[r], out2[r]);
        return 1;
    }
    printf(STYLE_GOOD "AES 128 ok" STYLE_DEFAULT "\n");

    aes2.encrypt_block(in, out);
    printBlock(out, 16);
    if((r = check(exp2, out)) >= 0){
        printf(STYLE_ERROR "Error with AES 192 encrypt at index %i: expected %02x, got %02x" STYLE_DEFAULT "\n", 
            r, exp2[r], out[r]);
        return 1;
    }
    aes2.decrypt_block(out, out2);
    printBlock(out2, 16);
    if((r = check(in, out2)) >= 0){
        printf(STYLE_ERROR "Error with AES 192 decrypt at index %i: expected %02x, got %02x" STYLE_DEFAULT "\n", 
            r, in[r], out2[r]);
        return 1;
    }
    printf(STYLE_GOOD "AES 192 ok" STYLE_DEFAULT "\n");

    aes3.encrypt_block(in, out);
    printBlock(out, 16);
    if((r = check(exp3, out)) >= 0){
        printf(STYLE_ERROR "Error with AES 256 encrypt at index %i: expected %02x, got %02x" STYLE_DEFAULT "\n", 
            r, exp3[r], out[r]);
        return 1;
    }
    aes3.decrypt_block(out, out2);
    printBlock(out2, 16);
    if((r = check(in, out2)) >= 0){
        printf(STYLE_ERROR "Error with AES 256 decrypt at index %i: expected %02x, got %02x" STYLE_DEFAULT "\n", 
            r, in[r], out2[r]);
        return 1;
    }
    printf(STYLE_GOOD "AES 256 ok" STYLE_DEFAULT "\n");

    return 0;
}
