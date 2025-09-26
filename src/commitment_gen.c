#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define R_LEN 23

void print_hex(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

int main(int argc, char *argv[])
{
    // help display
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("\nThis binary is on the CLIENT side\n"
               "It will get a random commitment key 'r' and print it in UPPERCASE hexadecimal (46 "
               "characters).\nAfter that, it will compute the commitment = SHA256(SHA256(m) || r) and print it in "
               "UPPERCASE hexadecimal (64 characters).\n"
               "No file.txt will be generated, you have to copy the output manually.\n");
        return 0;
    }

    char message[1024];
    unsigned char r[R_LEN] = {0};
    unsigned char digest1[SHA256_DIGEST_LENGTH] = {0};
    unsigned char final_input[SHA256_DIGEST_LENGTH + R_LEN] = {0};
    unsigned char commitment[SHA256_DIGEST_LENGTH] = {0};

    printf("Enter your message: ");
    if (!fgets(message, sizeof(message), stdin))
    {
        fprintf(stderr, "Input error\n");
        return EXIT_FAILURE;
    }

    size_t len = strlen(message);
    if (message[len - 1] == '\n')
        message[len - 1] = '\0';

    if (RAND_bytes(r, R_LEN) != 1)
    {
        fprintf(stderr, "RAND_bytes failed\n");
        return EXIT_FAILURE;
    }

    printf("\nCommitment key r (23 bytes):\n");
    print_hex(r, R_LEN);

    SHA256((unsigned char *)message, strlen(message), digest1);

    memcpy(final_input, digest1, SHA256_DIGEST_LENGTH);
    memcpy(final_input + SHA256_DIGEST_LENGTH, r, R_LEN);

    SHA256(final_input, SHA256_DIGEST_LENGTH + R_LEN, commitment);

    print_hex(commitment, SHA256_DIGEST_LENGTH);

    unsigned char final_commitment[2 * SHA256_DIGEST_LENGTH] = {0};
    memcpy(final_commitment, commitment, SHA256_DIGEST_LENGTH);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        final_commitment[SHA256_DIGEST_LENGTH + i] = ~commitment[i];
    }

    printf("\nFinal commitment = (commitment || ~commitment):\n");
    printf("\nWith commitment = SHA256(SHA256(m) || r)\n");
    printf("\n\nFinal commitment (64 bytes):\n");
    print_hex(final_commitment, 2 * SHA256_DIGEST_LENGTH);

    return 0;
}
