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

#define CH(e, f, g) ((e & f) ^ ((~e) & g)) // Chooses f if e = 0 and g if e = 1

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4], View views[3])
{
    z z;
    memcpy(z.ke, keys[e], 16);
    memcpy(z.ke1, keys[(e + 1) % 3], 16);
    z.ve = views[e];
    z.ve1 = views[(e + 1) % 3];
    memcpy(z.re, rs[e], 4);
    memcpy(z.re1, rs[(e + 1) % 3], 4);

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

    setbuf(stdout, NULL);
    srand((unsigned)time(NULL));
    init_EVP();
    openmp_thread_setup(); // OpenMP = Multi Threading

    unsigned char garbage[4];
    if (RAND_bytes(garbage, 4) != 1)
    {
        perror("RAND_bytes failed crypto, aborting\n");
        return 1;
    }

    // Getting m
    char *message = NULL;
    size_t bufferSize = 0;

    printf("\nPlease enter your message:\n");
    int length = getline(&message, &bufferSize, stdin);
    if (length == -1)
    {
        perror("Error reading input");
        free(message);
        return 1;
    }

    message[strlen(message) - 1] = '\0'; // to remove '\n' at the end

    // Computing message digest
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), digest);
    free(message);

    // Getting commitment key
    char hexInput[2 * COMMIT_KEY_LEN + 2];
    unsigned char commitment_key[COMMIT_KEY_LEN];

    bool read_error = false;

    printf("\nEnter your commitment key in UPPERCASE hexadecimal (46 hex chars):\n");
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

    // Getting commitment
    char hexInput2[2 * COMMIT_LEN + 2];
    unsigned char commitment[COMMIT_LEN];

    printf("\nEnter the commitment in UPPERCASE hexadecimal (64 hex chars):\n");
    if (fgets(hexInput2, sizeof(hexInput2), stdin) == NULL)
    {
        read_error = true;
    }

    if (read_error)
    {
        printf("Error reading input. Please ensure you enter the commitment key and commitment correctly.\n");
        return 1;
    }

    for (int i = 0; i < COMMIT_LEN; i++)
    {
        unsigned int byte;
        sscanf(&hexInput2[i * 2], "%2x", &byte);
        commitment[i] = (unsigned char)byte;
    }
    printf("\n");

    // Getting WOTS signature
    int c1;
    int c2;
    FILE *fp = fopen("signature.txt", "r");
    unsigned char sigma[8192];
    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 32; j++)
        {
            c1 = fgetc(fp);
            while (c1 == '\n')
            {
                c1 = fgetc(fp);
            }

            c2 = fgetc(fp);
            while (c2 == '\n')
            {
                c2 = fgetc(fp);
            }

            c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
            c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

            sigma[i * 32 + j] = (char)((c1 << 4) | c2);
        }
    fclose(fp);

    // Building input
    unsigned char input[INPUT_LEN];
    memcpy(input, commitment_key, 23);
    memcpy(input + 23, commitment, 32);
    memcpy(input + 55, sigma, 8192);

    // Generating keys
    unsigned char keys[NUM_ROUNDS][3][16];

    if (RAND_bytes((unsigned char *)keys, NUM_ROUNDS * 3 * 16) != 1)
    {
        perror("RAND_bytes failed crypto, aborting\n");
        return 1;
    }

    // Getting public_key
    fp = fopen("public_key.txt", "r");
    unsigned char public_key[8192];
    for (int i = 0; i < 256; ++i)
        for (int j = 0; j < 32; ++j)
        {
            c1 = fgetc(fp);
            while (c1 == '\n')
            {
                c1 = fgetc(fp);
            }

            c2 = fgetc(fp);
            while (c2 == '\n')
            {
                c2 = fgetc(fp);
            }

            c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
            c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

            public_key[i * 32 + j] = (char)((c1 << 4) | c2);
        }
    fclose(fp);

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
            getAllRandomness(keys[k][j], randomness[k][j], Random_Bytes_Needed);
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
        fprintf(stderr, "\nError: invalid signature\n\n");
        exit(EXIT_FAILURE);
    }
    printf("\nProof generated successfully in 'proof.bin'.\n\n");
    return EXIT_SUCCESS;
}