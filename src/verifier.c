#include "MPC_verify_functions.h"
#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    // help display
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf(
            "\nThis binary is used by anyone to verify the zero-knowledge proof of knowledge stored in 'proof.bin'.\n"
            "This proof is used as a blind signature for a WOTS signature of a secretly known 256 bits message "
            "commitment.\n"
            "To verify the proof, we need the public key, stored in 'public_key.txt'.\n");
        return 0;
    }

    setbuf(stdout, NULL);
    init_EVP();
    openmp_thread_setup();

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
    printf("\n");

    // Computing message digest
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), digest);
    free(message);

    FILE *file;

    // Getting public_key
    int c1;
    int c2;
    file = fopen("public_key.txt", "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return 1;
    }

    unsigned char public_key[8192];
    for (int i = 0; i < 256; ++i)
    {
        for (int j = 0; j < 32; ++j)
        {
            c1 = fgetc(file);
            while (c1 == '\n')
            {
                c1 = fgetc(file);
            }

            c2 = fgetc(file);
            while (c2 == '\n')
            {
                c2 = fgetc(file);
            }

            c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
            c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

            public_key[i * 32 + j] = (char)((c1 << 4) | c2);
        }
    }
    fclose(file);

    char outputFile[3 * sizeof(int) + 8];
    sprintf(outputFile, "proof.bin");
    file = fopen(outputFile, "rb");
    if (file == NULL)
    {
        perror("Error opening file");
        return 1;
    }

    /* ============================================== Reading Proof ============================================== */
    a *as = malloc(NUM_ROUNDS * sizeof(a));
    z *zs = malloc(NUM_ROUNDS * sizeof(z));

    bool read_error = false;

    size_t items_read = fread(as, sizeof(a), NUM_ROUNDS, file);

    if (items_read != NUM_ROUNDS)
    {
        read_error = true;
    }

    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        items_read = fread(&zs[i], sizeof(z), 1, file);
        if (items_read != 1)
        {
            read_error = true;
        }

        zs[i].ve.y = malloc(ySize * sizeof(uint32_t));
        zs[i].ve1.y = malloc(ySize * sizeof(uint32_t));

        items_read = fread(zs[i].ve.y, sizeof(uint32_t), ySize, file);
        if (items_read != ySize)
        {
            read_error = true;
            break;
        }

        items_read = fread(zs[i].ve1.y, sizeof(uint32_t), ySize, file);
        if (items_read != ySize)
        {
            read_error = true;
            break;
        }
    }

    fclose(file);

    if (read_error)
    {
        perror("Error in proof.bin\n");
        free(as);
        free(zs);
        return 1;
    }

    /* ============================================================================================================= */

    /* ============================================== Verifying proof ============================================== */

    // Verifying Circuit Output
    uint32_t xor_val;
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        for (int j = 0; j < 257 * 8; j++)
        {
            xor_val = as[i].yp[0][j] ^ as[i].yp[1][j] ^ as[i].yp[2][j];
            if (xor_val != 0)
            {
                printf("Unexpected non-zero output at round %d\n", xor_val);
                fprintf(stderr, "Error: invalid signature\n");
                free(as);
                free(zs);
                exit(EXIT_FAILURE);
            }
        }
    }

    // Generating e
    int es[NUM_ROUNDS];
    uint32_t y[8];
    memcpy(y, digest, 32);
    H3(y, as, NUM_ROUNDS, es);
    bool error = false;

#pragma omp parallel for
    for (int i = 0; i < NUM_ROUNDS; i++)
    {
        verify(digest, public_key, &error, as[i], es[i], zs[i]);
    }

    /* ============================================================================================================= */

    free(as);
    free(zs);
    openmp_thread_cleanup();
    cleanup_EVP();

    printf("================================================================\n");

    if (error)
    {
        fprintf(stderr, "\nError: invalid signature proof\n\n");
        exit(EXIT_FAILURE);
    }

    printf("\nSignature proof verified successfully.\n\n");

    return EXIT_SUCCESS;
}
