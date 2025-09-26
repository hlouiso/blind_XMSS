#include "shared.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

const int H = 10;
const int N = 32;
const int Lamport_len = 512;
const int nb_leaves = (1u << H);

// ZKBoo parameters & needed values
bool first = true;
const int COMMIT_KEY_LEN = 32;
const int NUM_ROUNDS = 1; // Usually 137
const int mpc_sha256_size = 736;
const int mpc_sha256_runs = 512;
const int sha256_extened_blocks_runs = 259;
int ySize = (mpc_sha256_runs + sha256_extened_blocks_runs) * mpc_sha256_size + 8 * 256;
int Random_Bytes_Needed = 2912 * (mpc_sha256_runs + sha256_extened_blocks_runs) + 256 * 8 * 4;

/* 16740 bytes = COMMIT_KEY_LEN (32 bytes) + leaf_index (4 bytes) + Sigma_size (512 * 32 bytes) + PATH (10*32 bytes) */
const int INPUT_LEN = 16740;

const uint32_t hA[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

const uint32_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};


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

    unsigned char zeros[32] = {0}; // The ciphered input is 32 bytes of zeros
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

void getAllRandomness(unsigned char key[32], unsigned char *randomness)
{
    unsigned char iv[16] = {0};
    iv[0] = iv[1] = iv[2] = iv[3] = 0xA5;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);

    size_t total = Random_Bytes_Needed;
    size_t offset = 0;
    unsigned char zeros[32] = {0};
    int outl = 0;

    while (offset < total) {
        size_t chunk = (total - offset > 32) ? 32 : (total - offset);
        unsigned char out[32];
        EVP_EncryptUpdate(ctx, out, &outl, zeros, 32);
        memcpy(randomness + offset, out, chunk);
        offset += chunk;
    }

    EVP_CIPHER_CTX_free(ctx);
}

uint32_t getRandom32(unsigned char *randomness, int randCount)
{
    uint32_t ret;
    memcpy(&ret, &randomness[randCount], 4);
    return ret;
}
