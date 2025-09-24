#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include "omp.h"
#include <openssl/rand.h>

bool first = true;
const int COMMIT_KEY_LEN = 23;
const int COMMIT_LEN = 32;
const int NUM_ROUNDS = 137; // Usually 137
const int mpc_sha256_size = 736;
const int mpc_sha256_runs = 257;
int ySize = mpc_sha256_runs * mpc_sha256_size + 8 * 256;
const int output_nb_in_uint32 = 257 * 8; // knowing that one output = 256 bits = 8 uint32_t
int Random_Bytes_Needed = 2912 * mpc_sha256_runs + 256 * 8 * 4;

/* 8247 bytes = COMMIT_KEY_LEN (23 bytes) + Digest len (32 bytes) + Sigma size (wots signature: 256 * 32 bytes) */
const int INPUT_LEN = 8247;

const uint32_t hA[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

const uint32_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void printbits(uint32_t n)
{
    if (n)
    {
        printbits(n >> 1);
        printf("%d", n & 1);
    }
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_CIPHER_CTX setupAES(unsigned char key[16])
{
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"01234567890123456";

    if (1 != EVP_EncryptInit_ex(&ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();

    return ctx;
}

void getAllRandomness(unsigned char key[16], unsigned char *randomness, int Bytes_Needed)
{
    // Generate randomness: We will use 728*32 bit of randomness per key.
    // Since AES block size is 128 bit, we need to run 728*32/128 = 182 iterations

    int iterations = Bytes_Needed * 8 / 128;
    EVP_CIPHER_CTX ctx;
    ctx = setupAES(key);
    unsigned char *plaintext = (unsigned char *)"0000000000000000";
    int len;
    for (int j = 0; j < iterations; j++)
    {
        if (1 != EVP_EncryptUpdate(&ctx, &randomness[j * 16], &len, plaintext, strlen((char *)plaintext)))
            handleErrors();
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
}

uint32_t getRandom32(unsigned char randomness[Random_Bytes_Needed], int randCount)
{
    uint32_t ret;
    memcpy(&ret, &randomness[randCount], 4);
    return ret;
}

void init_EVP()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void cleanup_EVP()
{
    EVP_cleanup();
    ERR_free_strings();
}

void H(unsigned char k[16], View v, unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH])
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    SHA256_Update(&ctx, k, 16);
    SHA256_Update(&ctx, v.x, 64);
    SHA256_Update(&ctx, v.y, ySize * sizeof(uint32_t));
    SHA256_Update(&ctx, r, 4);

    SHA256_Final(hash, &ctx);
}

void H3(uint32_t y[8], a *as, int s, int *es)
{

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, y, 32);
    SHA256_Update(&ctx, as, sizeof(a) * s);
    SHA256_Final(hash, &ctx);

    // Pick bits from hash
    int i = 0;
    int bitTracker = 0;
    while (i < s)
    {
        if (bitTracker >= SHA256_DIGEST_LENGTH * 8)
        { // Generate new hash as we have run out of bits in the previous hash
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, hash, sizeof(hash));
            SHA256_Final(hash, &ctx);
            bitTracker = 0;
        }

        int b1 = GETBIT(hash[bitTracker / 8], bitTracker % 8);
        int b2 = GETBIT(hash[(bitTracker + 1) / 8], (bitTracker + 1) % 8);
        if (b1 == 0)
        {
            if (b2 == 0)
            {
                es[i] = 0;
                bitTracker += 2;
                i++;
            }
            else
            {
                es[i] = 1;
                bitTracker += 2;
                i++;
            }
        }
        else
        {
            if (b2 == 0)
            {
                es[i] = 2;
                bitTracker += 2;
                i++;
            }
            else
            {
                bitTracker += 2;
            }
        }
    }
}