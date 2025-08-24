#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEED_LEN 32
#define NUM_BITS 256

static int hexval(char c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('A' <= c && c <= 'F')
        return 10 + (c - 'A');
    return -1; /* invalid */
}

static void write_hex_line(FILE *fp, const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        fprintf(fp, "%02X", data[i]);
    fputc('\n', fp);
}

int main(int argc, char *argv[])
{
    // help display
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf(
            "\nThis binary is on the SERVER side and generates a WOTS signature for a given commitment.\n"
            "It will sign your previously-generated 256-bits commitment, using a WOTS algorithm.\n"
            "To this end, it will generate a random private key and a public key.\n"
            "Only the public key will be saved in 'public_key.txt', and you will need to build/verify the final blind "
            "signature.\n"
            "Also, it will generate a file 'signature.txt' with the WOTS signature.\n"
            "You can then use the MPC prover to generate a proof of knowledge of the signature.\n");
        return 0;
    }

    char hex_input[65] = {0};
    int bits[NUM_BITS] = {0};

    printf("Enter the commitment in UPPERCASE hexadecimal (64 hex chars):\n");
    if (scanf("%64s", hex_input) != 1)
    {
        fprintf(stderr, "Error : file reading failed.\n");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < 64; i++)
    {
        int v = hexval(hex_input[i]);
        for (int b = 0; b < 4; ++b)
            bits[i * 4 + b] = (v >> (3 - b)) & 1;
    }

    unsigned char priv[NUM_BITS][SEED_LEN] = {0};
    unsigned char pub[NUM_BITS][SHA256_DIGEST_LENGTH] = {0};

    for (int i = 0; i < NUM_BITS; i++)
    {
        if (RAND_bytes(priv[i], SEED_LEN) != 1)
        {
            fprintf(stderr, "Error : RAND_bytes has failed.\n");
            return EXIT_FAILURE;
        }
        SHA256(priv[i], SEED_LEN, pub[i]);
    }

    FILE *fp = fopen("signature.txt", "w");
    if (fp == NULL)
    {
        perror("Error opening file");
        return 1;
    }

    for (int i = 0; i < NUM_BITS; i++)
    {
        if (bits[i] == 0)
            write_hex_line(fp, priv[i], SEED_LEN);
        else
            write_hex_line(fp, pub[i], SHA256_DIGEST_LENGTH);
    }
    fclose(fp);

    fp = fopen("public_key.txt", "w");
    if (fp == NULL)
    {
        perror("Error opening file");
        return 1;
    }

    for (int i = 0; i < NUM_BITS; i++)
        write_hex_line(fp, pub[i], SHA256_DIGEST_LENGTH);

    fclose(fp);
    printf("\nsignature.txt generated.\n");
    return EXIT_SUCCESS;
}
