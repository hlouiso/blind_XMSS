#include "building_views.h"
#include "MPC_prove_functions.h"
#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

a building_views(unsigned char digest[32], unsigned char shares[3][INPUT_LEN], unsigned char *randomness[3],
                 View views[3], unsigned char public_key[8192], bool *error)
{
    // Declaring the output a
    a a;
    int index_in_a = 0;
    int index_in_pub_key = 0;
    int bit_pos = 0;

    // First grab the share of (digest||commitment_key)
    unsigned char *inputs[3];
    for (int i = 0; i < 3; i++)
    {
        inputs[i] = calloc(55, 1);
        memcpy(inputs[i] + 32, shares[i], 23);
    }
    memcpy(inputs[0], digest, 32); // digest isn't secret so don´t need to be shared

    int *countY = calloc(1, sizeof(int));
    int *randCount = calloc(1, sizeof(int));
    unsigned char *results[3];
    results[0] = malloc(32);
    results[1] = malloc(32);
    results[2] = malloc(32);

    // Computing sha256(digest||commit-key)
    mpc_sha256(inputs, 55 * 8, randomness, results, views, countY, randCount);

    // xoring with secret commitment
    uint32_t t0[3], t1[3], tmp[3];

    for (int i = 0; i < 8; i++)
    {
        for (int j = 0; j < 3; j++)
        {
            memcpy(&t0[j], shares[j] + 23 + 4 * i, 4);
            memcpy(&t1[j], results[j] + 4 * i, 4);
        }

        mpc_XOR(t0, t1, tmp);

        for (int j = 0; j < 3; j++)
        {
            memcpy(&a.yp[j][index_in_a], &tmp[j], 4);
        }
        index_in_a++;
    }

    // Verifying signature
    for (int j = 0; j < 3; j++)
    {
        free(inputs[j]);
        inputs[j] = malloc(32);
    }

    for (int i = 0; i < 256; i++)
    {
        int index_in_input = 55 + 32 * i;
        index_in_pub_key = 32 * i;

        // Computing SHA256 of WOTS_signature[i]
        for (int j = 0; j < 3; j++)
        {
            memcpy(inputs[j], shares[j] + index_in_input, 32);
        }

        mpc_sha256(inputs, SHA256_DIGEST_LENGTH * 8, randomness, results, views, countY, randCount);

        uint32_t verif_result[3][8];

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], shares[k] + index_in_input + 4 * j, 4);
                memcpy(&t1[k], results[k] + 4 * j, 4);
            }

            mpc_XOR(t0, t1, tmp);

            for (int k = 0; k < 3; k++)
            {
                verif_result[k][j] = tmp[k];
            }
        }

        // Building MASK: getting a share of i-th bit of the shared commitment and extending it in 32bits word
        uint32_t mask[3];
        int byte = i >> 3;

        for (int j = 0; j < 3; j++)
        {
            uint8_t v = shares[j][23 + byte];
            bit_pos = 7 - (i & 7);
            uint32_t b = (v >> bit_pos) & 1;
            mask[j] = 0u - b;
        }

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], &verif_result[k][j], 4);
            }

            mpc_AND(t0, mask, tmp, randomness, randCount, views, countY);

            for (int k = 0; k < 3; k++)
            {
                verif_result[k][j] = tmp[k];
            }
        }

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], &verif_result[k][j], 4);
                memcpy(&t1[k], results[k] + 4 * j, 4);
            }

            mpc_XOR(t0, t1, tmp);

            for (int k = 0; k < 3; k++)
            {
                verif_result[k][j] = tmp[k];
            }
        }

        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                memcpy(&t0[k], &verif_result[k][j], 4);
            }
            memset(t1, 0, sizeof(t1));
            memcpy(&t1[0], public_key + index_in_pub_key + 4 * j, 4);

            mpc_XOR(t0, t1, tmp);

            for (int k = 0; k < 3; k++)
            {
                memcpy(&a.yp[k][index_in_a], &tmp[k], 4);
            }
            index_in_a++;
        }
    }

    for (int i = 0; i < 3; i++)
    {
        free(inputs[i]);
        free(results[i]);
    }

    uint32_t xor_val;
    for (int i = 0; i < 257 * 8; i++)
    {
        xor_val = a.yp[0][i] ^ a.yp[1][i] ^ a.yp[2][i];
        if (xor_val != 0)
        {
            printf("unexpected non-zero XOR at %d: %08x\n", i, xor_val);
            *error = true;
        }
    }

    free(randCount);
    free(countY);

    return a;
}
