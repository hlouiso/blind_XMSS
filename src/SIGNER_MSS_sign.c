

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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

    fclose(f);

    unsigned char public_key[32];
    f = fopen("MSS_public_key.txt", "r");
    for (int i = 0; i < 32; i++)
    {
        c1 = fgetc(f);
        c2 = fgetc(f);
        c1 = (c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
        c2 = (c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;

        public_key[i] = (unsigned char)((c1 << 4) | c2);
    }

    fclose(f);

    /* ============================== Signing ============================== */

    // Getting blinded_message
    char *message = NULL;
    size_t bufferSize = 0;

    printf("\nPlease enter your message:\n");
    int length = getline(&message, &bufferSize, stdin);
    message[strlen(message) - 1] = '\0';

    return 0;
}