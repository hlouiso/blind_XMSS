#include "MPC_prove_functions.h"
#include "building_views.h"
#include "shared.h"

#include <omp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

#define CH(e, f, g) ((e & f) ^ ((~e) & g)) // Chooses f if e = 0 and g if e = 1

z prove(int e, unsigned char keys[3][32], unsigned char rs[3][32], View views[3])
{
    z z;
    memcpy(z.ke, keys[e], 32);
    memcpy(z.ke1, keys[(e + 1) % 3], 32);
    z.ve = views[e];
    z.ve1 = views[(e + 1) % 3];
    memcpy(z.re, rs[e], 32);
    memcpy(z.re1, rs[(e + 1) % 3], 32);

    return z;
}

int main(int argc, char *argv[])
{
    // help display
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("\nThis binary is on the CLIENT side.\n"
               "It builds a ZKBoo-based zero-knowledge proof of knowledge of a WOTS signature of a secretly known "
               "256 bits message commitment, which one we know the key.\n"
               "The result will be saved in 'proof.bin'.\n"
               "You will need to run the MPC verifier to verify the proof.\n");
        return 0;
    }

    // Getting m
    char *message = NULL;
    size_t bufferSize = 0;

    printf("\nPlease enter your message:\n");
    int length = getline(&message, &bufferSize, stdin);

    message[strlen(message) - 1] = '\0'; // to remove '\n' at the end

    // Computing message digest
    unsigned char message_digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), message_digest);
    free(message);

    // Getting commitment key
    char hexInput[2 * COMMIT_KEY_LEN + 2];
    unsigned char commitment_key[COMMIT_KEY_LEN];

    bool read_error = false;

    printf("\nEnter your commitment key in UPPERCASE hexadecimal (64 hex chars):\n");
    if (fgets(hexInput, sizeof(hexInput), stdin) == NULL)
    {
        read_error = true;
    }

    for (int i = 0; i < COMMIT_KEY_LEN; i++)
    {
        unsigned int byte;
        sscanf(&hexInput[i * 2], "%2x", &byte);
        commitment_key[i] = (unsigned char)byte;
    }

    // Getting MSS signature
    int c1;
    int c2;
    FILE *f = fopen("signature.txt", "r");

    // getting leaf index
    unsigned char leaf_index_bytes[4];
    char buf[32];
    fgets(buf, sizeof(buf), f);
    uint32_t leaf_index = (uint32_t)strtoul(buf, NULL, 10);
    leaf_index_bytes[0] = (leaf_index >> 24) & 0xFF;
    leaf_index_bytes[1] = (leaf_index >> 16) & 0xFF;
    leaf_index_bytes[2] = (leaf_index >> 8) & 0xFF;
    leaf_index_bytes[3] = (leaf_index) & 0xFF;
        
    // Lamport signature
    unsigned char sigma[Lamport_len * SHA256_DIGEST_LENGTH];

    for (int i = 0; i < 512; i++)
    {
        for (int j = 0; j < 32; j++)
        {
            c1 = fgetc(f);
            while (c1 == '\n')
            {
                c1 = fgetc(f);
            }

            c2 = fgetc(f);
            while (c2 == '\n')
            {
                c2 = fgetc(f);
            }

            c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
            c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

            sigma[i * 32 + j] = (char)((c1 << 4) | c2);
        }
    }

    // PATH
    unsigned char PATH[10 * SHA256_DIGEST_LENGTH];
    for (int i = 0; i < 10 * SHA256_DIGEST_LENGTH; i++)
    {
        c1 = fgetc(f);
        while (c1 == '\n')
        {
            c1 = fgetc(f);
        }

        c2 = fgetc(f);
        while (c2 == '\n')
        {
            c2 = fgetc(f);
        }

        c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
        c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

        PATH[i] = (char)((c1 << 4) | c2);
    }

    // Building input
    unsigned char input[INPUT_LEN];
    memcpy(input, commitment_key, 32);
    memcpy(input + 32, leaf_index_bytes, 4);
    memcpy(input + 32 + 4, sigma, Lamport_len * SHA256_DIGEST_LENGTH);
    memcpy(input + 32 + 4 + Lamport_len * SHA256_DIGEST_LENGTH, PATH, 10 * SHA256_DIGEST_LENGTH);

    const int r_index = 0;
    const int leaf_index_index = 32;
    const int sigma_index = 36;
    const int path_index = 36 + Lamport_len * SHA256_DIGEST_LENGTH;

    fclose(f);

    // Generating keys
    unsigned char keys[NUM_ROUNDS][3][32];

    if (RAND_bytes((unsigned char *)keys, NUM_ROUNDS * 3 * 16) != 1)
    {
        perror("RAND_bytes failed crypto, aborting\n");
        return 1;
    }

    // Getting public_key
    f = fopen("public_key.txt", "r");
    unsigned char public_key[SHA256_DIGEST_LENGTH];
    for (int j = 0; j < 32; ++j)
    {
        c1 = fgetc(f);
        while (c1 == '\n')
        {
            c1 = fgetc(f);
        }

        c2 = fgetc(f);
        while (c2 == '\n')
        {
            c2 = fgetc(f);
        }

        c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
        c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

        public_key[j] = (char)((c1 << 4) | c2);
    }
    fclose(f);

    // Sharing secrets
    unsigned char shares[NUM_ROUNDS][3][INPUT_LEN];
    if (RAND_bytes((unsigned char *)shares, NUM_ROUNDS * 3 * INPUT_LEN) != 1)
    {
        perror("RAND_bytes failed crypto, aborting\n");
        return 1;
    }

    View localViews[NUM_ROUNDS][3];

#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        for (int j = 0; j < INPUT_LEN; j++)
        {
            shares[k][2][j] = input[j] ^ shares[k][0][j] ^ shares[k][1][j];
        }
        for (int j = 0; j < 3; j++)
        {
            memcpy(localViews[k][j].x, shares[k][j], INPUT_LEN);
        }
    }

    // Generating randomness
    unsigned char *randomness[NUM_ROUNDS][3];
#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        for (int j = 0; j < 3; j++)
        {
            randomness[k][j] = malloc(Random_Bytes_Needed * sizeof(unsigned char));
            getAllRandomness(keys[k][j], randomness[k][j]);
            localViews[k][j].y = malloc(ySize * sizeof(uint32_t));
        }
    }

    /* ============================================== Running Circuit ============================================== */

    a *as = calloc(NUM_ROUNDS, sizeof(a));
    bool error = false;

#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        as[k] = building_views(digest, shares[k], randomness[k], localViews[k], public_key, &error);
        for (int j = 0; j < 3; j++)
        {
            free(randomness[k][j]);
        }
    }

    /* ============================================================================================================ */

    // Committing the views
    unsigned char rs[NUM_ROUNDS][3][4]; // Commit keys
    if (RAND_bytes((unsigned char *)rs, NUM_ROUNDS * 3 * 4) != 1)
    {
        perror("RAND_bytes failed crypto, aborting\n");
        free(as);
        return 1;
    }

#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++)
    {
        unsigned char hash1[SHA256_DIGEST_LENGTH];
        H(keys[k][0], localViews[k][0], rs[k][0], hash1);
        memcpy(as[k].h[0], hash1, 32);
        H(keys[k][1], localViews[k][1], rs[k][1], hash1);
        memcpy(as[k].h[1], hash1, 32);
        H(keys[k][2], localViews[k][2], rs[k][2], hash1);
        memcpy(as[k].h[2], hash1, 32);
    }

    // Generating e
    int es[NUM_ROUNDS];
    uint32_t y[8];
    memcpy(y, digest, 32);
    H3(y, as, NUM_ROUNDS, es);

    // Packing Z
    z *zs = malloc(sizeof(z) * NUM_ROUNDS);

#pragma omp parallel for
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        zs[i] = prove(es[i], keys[i], rs[i], localViews[i]);
    }

    // Writing to file
    FILE *file = fopen("proof.bin", "wb");

    fwrite(as, sizeof(a), NUM_ROUNDS, file);

    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        fwrite(&zs[i], sizeof(z), 1, file);

        fwrite(zs[i].ve.y, sizeof(uint32_t), ySize, file);
        fwrite(zs[i].ve1.y, sizeof(uint32_t), ySize, file);
    }

    fclose(file);
    free(as);
    free(zs);
    openmp_thread_cleanup();
    cleanup_EVP();

    printf("================================================================\n");
    if (error)
    {
        frintf(stderr, "\nError: invalid signature\n\n");
        exit(EXIT_FAILURE);
    }
    printf("\nProof generated successfully in 'proof.bin'.\n\n");
    return EXIT_SUCCESS;
}