#include "shared.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>

int prf_aes256_ctr_32(const unsigned char sk_seed[32], uint32_t leaf, uint32_t j, unsigned char out32[32])
{
    unsigned char iv[16] = {0};

    iv[0] = iv[1] = iv[2] = iv[3] = 0xA5;

    iv[4] = (unsigned char)(leaf >> 24);
    iv[5] = (unsigned char)(leaf >> 16);
    iv[6] = (unsigned char)(leaf >> 8);
    iv[7] = (unsigned char)(leaf);

    iv[8] = (unsigned char)(j >> 24);
    iv[9] = (unsigned char)(j >> 16);
    iv[10] = (unsigned char)(j >> 8);
    iv[11] = (unsigned char)(j);

    iv[12] = iv[13] = iv[14] = iv[15] = 0;

    unsigned char zeros[32] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    int tmplen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, sk_seed, iv);
    EVP_EncryptUpdate(ctx, out32, &outl, zeros, sizeof zeros);
    EVP_EncryptFinal_ex(ctx, out32 + outl, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int sha256_once(const unsigned char *in, size_t inlen, unsigned char out32[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int outl = 0;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestFinal_ex(ctx, out32, &outl);
    EVP_MD_CTX_free(ctx);
    return 1;
}
