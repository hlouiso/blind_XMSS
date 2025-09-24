#include "SIGNER_pk_extract.h"
#include "shared.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define H 10
#define N 32
#define Lamport_len 512
#define nb_leaves (1u << H)

void pk_extract(unsigned char sk_seed[32])
{
    /* Leaves generation */
    unsigned char *level = malloc(nb_leaves * N);
    unsigned char *leafbuf = malloc(Lamport_len * N);

    for (uint32_t leaf = 0; leaf < nb_leaves; leaf++)
    {
        unsigned char sk[N], pk[N];
        unsigned char *w = leafbuf;
        for (uint32_t j = 0; j < Lamport_len; j++)
        {
            prf_aes256_ctr_32(sk_seed, leaf, j, sk);
            sha256_once(sk, N, pk);
            memcpy(w, pk, N);
            w += N;
        }
        sha256_once(leafbuf, Lamport_len * N, level + leaf * N);
    }

    /* Merkle tree root computation */
    unsigned char *next = malloc((nb_leaves / 2) * N);

    uint32_t nodes = nb_leaves;
    while (nodes > 1)
    {
        for (uint32_t i = 0; i < nodes; i += 2)
        {
            unsigned char buf[2 * N];
            memcpy(buf, level + i * N, N);
            memcpy(buf + N, level + (i + 1) * N, N);
            sha256_once(buf, sizeof buf, next + (i / 2) * N);
        }
        unsigned char *tmp = level;
        level = next;
        next = tmp;
        nodes >>= 1;
    }

    /* Public key writing */
    FILE *f = fopen("MSS_public_key.txt", "w");
    for (size_t i = 0; i < N; i++)
        fprintf(f, "%02X", level[i]);
    fprintf(f, "\n");
    fclose(f);

    printf("======================================================================\n\n");
    printf("MSS_public_key.txt generated\n");
    printf("Reminder: MSS_pk = Merkle Tree root)\n");
    printf("Your public key is:\n");
    for (size_t i = 0; i < N; i++)
    {
        printf("%02X", level[i]);
    }
    printf("\n\n");

    free(leafbuf);
    free(level);
    free(next);
}
