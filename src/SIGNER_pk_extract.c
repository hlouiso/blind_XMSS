#include "SIGNER_pk_extract.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define H 10
#define N 32
#define Lamport_len 512
#define nb_leaves (1u << H)

void prf_derive32_aes(const AES_KEY *aes, uint32_t leaf, uint32_t j, unsigned char out32[32])
{
    unsigned char iv[16] = {0};
    iv[0] = 0xA5;
    iv[1] = 0xA5;
    iv[2] = 0xA5;
    iv[3] = 0xA5;
    memcpy(iv + 4, &leaf, 4);
    memcpy(iv + 8, &j, 4);

    unsigned char block[16];

    AES_encrypt(iv, block, aes);
    memcpy(out32, block, 16);

    iv[15]++;
    AES_encrypt(iv, block, aes);
    memcpy(out32 + 16, block, 16);
}

void compute_root(const unsigned char *all)
{
    unsigned char *level = malloc((size_t)nb_leaves * N);
    unsigned char *next = malloc((size_t)(nb_leaves / 2) * N);

    if (!level || !next)
    {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }

    // Computing all the leaves = H(pk_1), H(pk_2), ..., H(pk_nb_leaves)
    const unsigned char *p = all;
    for (uint32_t leaf = 0; leaf < nb_leaves; leaf++)
    {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        for (uint32_t j = 0; j < 2 * N; j++)
        {
            unsigned char pk[N];
            SHA256(p, N, pk);
            SHA256_Update(&ctx, pk, N);
            p += N;
        }

        SHA256_Final(level + (size_t)leaf * N, &ctx);
    }

    // Computing the root
    uint32_t nodes = nb_leaves;
    while (nodes > 1)
    {
        for (uint32_t i = 0; i < nodes; i += 2)
        {
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, level + (size_t)i * N, N);
            SHA256_Update(&ctx, level + (size_t)(i + 1) * N, N);
            SHA256_Final(next + (size_t)(i / 2) * N, &ctx);
        }
        unsigned char *tmp = level;
        level = next;
        next = tmp;
        nodes >>= 1;
    }

    for (size_t i = 0; i < N; i++)
        printf("%02X", level[i]);
    printf("\n");

    free(level);
    free(next);
}

void pk_extract(unsigned char sk_seed[32])
{
    AES_KEY aes;
    if (AES_set_encrypt_key(sk_seed, 256, &aes) != 0)
    {
        fprintf(stderr, "AES_set_encrypt_key failed\n");
        exit(1);
    }

    size_t total = (size_t)nb_leaves * Lamport_len * N;

    unsigned char *all = malloc(total);
    if (!all)
    {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }

    unsigned char *p = all;
    for (uint32_t leaf = 0; leaf < nb_leaves; leaf++)
    {
        for (uint32_t j = 0; j < Lamport_len; j++)
        {
            prf_derive32_aes(&aes, leaf, j, p);
            p += N;
        }
    }

    compute_root(all);
}