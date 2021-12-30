// https://github.com/iamwhcn
// 2021/5/24
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#ifndef DES_H
#define DES_H

#define LB32_MASK 0x00000001
#define LB64_MASK 0x0000000000000001
#define L64_MASK 0x00000000ffffffff

typedef enum
{
    e,
    d
} mode_t;

typedef union
{
    char c[8];
    uint64_t l;
} Block;

void key_generation(uint64_t key, uint64_t sub_keys[]);
uint64_t des(uint64_t input, uint64_t key, mode_t mode);

#endif //DES_H
