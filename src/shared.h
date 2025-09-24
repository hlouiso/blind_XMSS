#include <stdint.h>
#include <string.h>

int prf_aes256_ctr_32(const unsigned char sk_seed[32], uint32_t leaf, uint32_t j, unsigned char out32[32]);

int sha256_once(const unsigned char *in, size_t inlen, unsigned char out32[32]);