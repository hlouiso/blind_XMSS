#ifndef SHARED_H
#define SHARED_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "omp.h"

#define VERBOSE FALSE

extern bool first;
extern const int COMMIT_KEY_LEN;
extern const int COMMIT_LEN;
extern const int NUM_ROUNDS;
extern const int mpc_sha256_size;
extern const int mpc_sha256_runs;
extern int ySize;
extern const int output_nb_in_uint32;
extern int Random_Bytes_Needed;

/* 8247 bytes = COMMIT_KEY_LEN (23 bytes) + Digest len (32 bytes) + Sigma size (wots signature: 256 * 32 bytes) */
extern const int INPUT_LEN;

#define RIGHTROTATE(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b) x = (b) & 1 ? (x) | (1 << (i)) : (x) & (~(1 << (i)))

extern const uint32_t hA[8];

extern const uint32_t k[64];

typedef struct
{
    unsigned char x[8247];
    uint32_t *y;
} View;

typedef struct
{
    uint32_t yp[3][257 * 8];
    unsigned char h[3][32];
} a;

typedef struct
{
    unsigned char ke[16];
    unsigned char ke1[16];
    View ve;
    View ve1;
    unsigned char re[4];
    unsigned char re1[4];
} z;

void printbits(uint32_t n);

void handleErrors(void);

EVP_CIPHER_CTX setupAES(unsigned char key[16]);

void getAllRandomness(unsigned char key[16], unsigned char *randomness, int Bytes_Needed);

uint32_t getRandom32(unsigned char randomness[Random_Bytes_Needed], int randCount);

void H(unsigned char k[16], View v, unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]);

void H3(uint32_t y[8], a *as, int s, int *es);

#endif // SHARED_H