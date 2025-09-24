#include "SIGNER_pk_extract.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

#define H 10

int main(int argc, char *argv[])
{
    unsigned char sk_seed[32] = {0};

    if (RAND_bytes(sk_seed, 32) != 1)
    {
        fprintf(stderr, "Error with RAND_bytes\n");
        return 1;
    }

    FILE *f = fopen("MSS_secret_key.txt", "w");
    if (f == NULL)
    {
        fprintf(stderr, "Error with fopen\n");
        return 1;
    }

    for (size_t i = 0; i < 32; i++)
        fprintf(f, "%02X", sk_seed[i]);
    fprintf(f, "\n");

    fprintf(f, "0\n"); // index set to 0

    fclose(f);
    printf("======================================================================\n\n");
    printf("MSS_secret_key.txt generated\n");
    printf("Reminder: MSS_sk = (sk_seed, leaf_index)\n");
    printf("Your secret key is:\nsk_seed = ");
    for (size_t i = 0; i < 32; i++)
    {
        printf("%02X", sk_seed[i]);
    }
    printf("\nleaf_index set to 0\n\n");

    pk_extract(sk_seed); // call to pk_gen function to generate the public key and save it in MSS_public_key.txt

    return 0;
}
