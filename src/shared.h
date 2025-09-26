#ifndef SHARED_H
#define SHARED_H

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

extern const int H;
extern const int N;
extern const int Lamport_len;
extern const int nb_leaves;

// ZKBoo parameters & needed values
extern bool first;
extern const int COMMIT_KEY_LEN;
extern const int NUM_ROUNDS;
extern const int mpc_sha256_size;
extern const int mpc_sha256_runs;
extern int ySize;
extern const int output_nb_in_uint32;
extern int Random_Bytes_Needed;
extern const int sha256_extened_blocks_runs;

/* 16740 bytes = COMMIT_KEY_LEN (32 bytes) + leaf_index (4 bytes) + Sigma_size (512*32 bytes) + PATH (10*32 bytes) */
extern const int INPUT_LEN;

#define RIGHTROTATE(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b) x = (b) & 1 ? (x) | (1 << (i)) : (x) & (~(1 << (i)))

extern const uint32_t hA[8];

extern const uint32_t k[64];

typedef struct
{
    unsigned char x[16740];
    uint32_t *y;
} View;

typedef struct
{
    uint32_t yp[3][8];
    unsigned char h[3][32];
} a;

typedef struct
{
    unsigned char ke[32];
    unsigned char ke1[32];
    View ve;
    View ve1;
    unsigned char re[32];
    unsigned char re1[32];
} z;

int prf_aes256_ctr_32(const unsigned char sk_seed[32], uint32_t leaf, uint32_t j, unsigned char out32[32]);

int sha256_once(const unsigned char *in, size_t inlen, unsigned char out32[32]);

void getAllRandomness(unsigned char key[32], unsigned char *randomness);

uint32_t getRandom32(unsigned char randomness[Random_Bytes_Needed], int randCount);

#endif