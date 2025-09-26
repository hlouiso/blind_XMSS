#include "shared.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

void build_path(unsigned char sk_seed[32], uint32_t leaf_idx, FILE *f)
{
    unsigned char *level = (unsigned char *)malloc(nb_leaves * SHA256_DIGEST_LENGTH);

    for (uint32_t leaf = 0; leaf < nb_leaves; leaf++)
    {
        unsigned char leaf_buf[Lamport_len * SHA256_DIGEST_LENGTH];
        unsigned char sigma[SHA256_DIGEST_LENGTH];

        for (uint32_t i = 0; i < Lamport_len; ++i)
        {
            prf_aes256_ctr_32(sk_seed, leaf, i, sigma);
            sha256_once(sigma, SHA256_DIGEST_LENGTH, leaf_buf + i * SHA256_DIGEST_LENGTH);
        }

        sha256_once(leaf_buf, Lamport_len * SHA256_DIGEST_LENGTH, level + leaf * SHA256_DIGEST_LENGTH);
    }

    unsigned char *cur = level;
    uint32_t curN = nb_leaves;

    for (uint32_t h = 0; h < H; h++)
    {
        uint32_t node_idx = (leaf_idx >> h);
        uint32_t sib_idx = (node_idx ^ 1u);
        unsigned char *sib = cur + sib_idx * SHA256_DIGEST_LENGTH;

        for (int b = 0; b < SHA256_DIGEST_LENGTH; b++)
            fprintf(f, "%02X", sib[b]);
        fprintf(f, "\n");

        if (h == H - 1)
            break;

        uint32_t nextN = (curN >> 1);
        unsigned char *next = (unsigned char *)malloc(nextN * SHA256_DIGEST_LENGTH);

        for (uint32_t k = 0; k < nextN; k++)
        {
            const unsigned char *base = cur + (2 * k) * SHA256_DIGEST_LENGTH;
            sha256_once(base, 2 * SHA256_DIGEST_LENGTH, next + k * SHA256_DIGEST_LENGTH);
        }

        free(cur);
        cur = next;
        curN = nextN;
    }

    free(cur);
}

int main(void)
{
    /* ============================== Getting keys ============================== */
    FILE *f = fopen("MSS_secret_key.txt", "r");

    unsigned char sk_seed[32];
    uint32_t leaf_idx;
    int c1, c2;

    for (int i = 0; i < 32; i++)
    {
        c1 = fgetc(f);
        c2 = fgetc(f);
        c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
        c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

        sk_seed[i] = (unsigned char)((c1 << 4) | c2);
    }

    c1 = fgetc(f); // newline
    fscanf(f, "%u", &leaf_idx);
    if (leaf_idx >= (1u << H))
    {
        fprintf(stderr, "Error: leaf_idx out of bounds\n");
        fclose(f);
        return EXIT_FAILURE;
    }

    fclose(f);

    /* ============================== Signing ============================== */

    f = fopen("MSS_signature.txt", "w");
    fprintf(f, "%d\n\n", leaf_idx);

    // Getting blinded_message
    char *message = NULL;
    size_t bufferSize = 0;

    printf("\nPlease enter the blinded message sent by the CLIENT (64 bytes long):\n");
    int length = getline(&message, &bufferSize, stdin);

    unsigned char message_bits[2 * SHA256_DIGEST_LENGTH];

    for (int i = 0; i < 2 * SHA256_DIGEST_LENGTH; i++)
    {
        unsigned int byte;
        sscanf(message + 2 * i, "%2X", &byte);
        message_bits[i] = (unsigned char)byte;
    }

    unsigned char sigma[SHA256_DIGEST_LENGTH];
    for (int i = 0; i < Lamport_len; i++)
    {
        prf_aes256_ctr_32(sk_seed, leaf_idx, i, sigma);
        if (((message_bits[i / 8] >> (7 - (i % 8))) & 1) == 1)
        {
            // If bit is 1, hash
            sha256_once(sigma, SHA256_DIGEST_LENGTH, sigma);
        }
        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
        {
            fprintf(f, "%02X", sigma[j]);
        }
        fprintf(f, "\n");
    }

    fprintf(f, "\n");

    /* ============================== PATH  ============================== */

    build_path(sk_seed, leaf_idx, f);

    fclose(f);
    free(message);

    return 0;
}