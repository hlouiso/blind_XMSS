#include "MPC_verify_functions.h"
#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1,
                   unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY)
{
    uint32_t r[2] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount)};
    *randCount += 4;

    uint32_t t = 0;

    t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
    if (ve.y[*countY] != t)
    {
        return 1;
    }
    z[0] = t;
    z[1] = ve1.y[*countY];

    (*countY)++;
    return 0;
}

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1,
                   unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY)
{
    uint32_t r[2] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount)};
    *randCount += 4;

    uint8_t a[2], b[2];

    uint8_t t;

    for (int i = 0; i < 31; i++)
    {
        a[0] = GETBIT(x[0] ^ ve.y[*countY], i);
        a[1] = GETBIT(x[1] ^ ve1.y[*countY], i);

        b[0] = GETBIT(y[0] ^ ve.y[*countY], i);
        b[1] = GETBIT(y[1] ^ ve1.y[*countY], i);

        t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
        if (GETBIT(ve.y[*countY], i + 1) != (t ^ (a[0] & b[0]) ^ GETBIT(ve.y[*countY], i) ^ GETBIT(r[0], i)))
        {
            return 1;
        }
    }

    z[0] = x[0] ^ y[0] ^ ve.y[*countY];
    z[1] = x[1] ^ y[1] ^ ve1.y[*countY];
    (*countY)++;
    return 0;
}

void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[])
{
    z[0] = RIGHTROTATE(x[0], i);
    z[1] = RIGHTROTATE(x[1], i);
}

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2])
{
    z[0] = x[0] >> i;
    z[1] = x[1] >> i;
}

int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3], View ve, View ve1,
                   unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY)
{
    uint32_t t0[3];
    uint32_t t1[3];

    mpc_XOR2(a, b, t0);
    mpc_XOR2(a, c, t1);
    if (mpc_AND_verify(t0, t1, z, ve, ve1, randomness, randCount, countY) == 1)
    {
        return 1;
    }
    mpc_XOR2(z, a, z);
    return 0;
}

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View ve, View ve1,
                  unsigned char randomness[2][Random_Bytes_Needed], int *randCount, int *countY)
{

    uint32_t t0[3];
    mpc_XOR2(f, g, t0);
    if (mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1)
    {
        return 1;
    }
    mpc_XOR2(t0, g, z);

    return 0;
}

void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2])
{
    z[0] = x[0] ^ y[0];
    z[1] = x[1] ^ y[1];
}

void mpc_NEGATE2(uint32_t x[2], uint32_t z[2])
{
    z[0] = ~x[0];
    z[1] = ~x[1];
}

int mpc_sha256_verify(uint32_t w[64][2], unsigned char *results[2], int numBits, int *randCount, int *countY,
                      unsigned char randomness[2][Random_Bytes_Needed], z z)
{
    int chars = numBits >> 3;
    chars = chars;

    for (int i = 0; i < 2; i++)
    {
        w[15][i] = numBits;
        w[chars / 4][i] = w[chars / 4][i] ^ (0x80 << (24 - (chars % 4) * 8));
    }

    uint32_t s0[2], s1[2];
    uint32_t t0[2], t1[2];
    for (int j = 16; j < 64; j++)
    {
        // s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
        mpc_RIGHTROTATE2(w[j - 15], 7, t0);
        mpc_RIGHTROTATE2(w[j - 15], 18, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTSHIFT2(w[j - 15], 3, t1);
        mpc_XOR2(t0, t1, s0);

        // s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
        mpc_RIGHTROTATE2(w[j - 2], 17, t0);
        mpc_RIGHTROTATE2(w[j - 2], 19, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTSHIFT2(w[j - 2], 10, t1);
        mpc_XOR2(t0, t1, s1);

        // w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];

        if (mpc_ADD_verify(w[j - 16], s0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, j);
            return 1;
        }

        if (mpc_ADD_verify(w[j - 7], t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, j);
            return 1;
        }
        if (mpc_ADD_verify(t1, s1, w[j], z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, j);
            return 1;
        }
    }

    uint32_t va[2] = {hA[0], hA[0]};
    uint32_t vb[2] = {hA[1], hA[1]};
    uint32_t vc[2] = {hA[2], hA[2]};
    uint32_t vd[2] = {hA[3], hA[3]};
    uint32_t ve[2] = {hA[4], hA[4]};
    uint32_t vf[2] = {hA[5], hA[5]};
    uint32_t vg[2] = {hA[6], hA[6]};
    uint32_t vh[2] = {hA[7], hA[7]};
    uint32_t temp1[3], temp2[3], maj[3];
    for (int i = 0; i < 64; i++)
    {
        // s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
        mpc_RIGHTROTATE2(ve, 6, t0);
        mpc_RIGHTROTATE2(ve, 11, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTROTATE2(ve, 25, t1);
        mpc_XOR2(t0, t1, s1);

        // ch = (e & f) ^ ((~e) & g);
        // temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

        // t0 = h + s1

        if (mpc_ADD_verify(vh, s1, t0, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        if (mpc_CH_verify(ve, vf, vg, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        // t1 = t0 + t1 (h+s1+ch)
        if (mpc_ADD_verify(t0, t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        t0[0] = k[i];
        t0[1] = k[i];
        if (mpc_ADD_verify(t1, t0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        if (mpc_ADD_verify(t1, w[i], temp1, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        // s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
        mpc_RIGHTROTATE2(va, 2, t0);
        mpc_RIGHTROTATE2(va, 13, t1);
        mpc_XOR2(t0, t1, t0);
        mpc_RIGHTROTATE2(va, 22, t1);
        mpc_XOR2(t0, t1, s0);

        // maj = (a & (b ^ c)) ^ (b & c);
        //(a & b) ^ (a & c) ^ (b & c)

        if (mpc_MAJ_verify(va, vb, vc, maj, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        // temp2 = s0+maj;
        if (mpc_ADD_verify(s0, maj, temp2, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        memcpy(vh, vg, sizeof(uint32_t) * 2);
        memcpy(vg, vf, sizeof(uint32_t) * 2);
        memcpy(vf, ve, sizeof(uint32_t) * 2);
        // e = d+temp1;
        if (mpc_ADD_verify(vd, temp1, ve, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }

        memcpy(vd, vc, sizeof(uint32_t) * 2);
        memcpy(vc, vb, sizeof(uint32_t) * 2);
        memcpy(vb, va, sizeof(uint32_t) * 2);
        // a = temp1+temp2;

        if (mpc_ADD_verify(temp1, temp2, va, z.ve, z.ve1, randomness, randCount, countY) == 1)
        {
            printf("Failing at %d, iteration %d", __LINE__, i);
            return 1;
        }
    }

    uint32_t hHa[8][3] = {{hA[0], hA[0], hA[0]}, {hA[1], hA[1], hA[1]}, {hA[2], hA[2], hA[2]}, {hA[3], hA[3], hA[3]},
                          {hA[4], hA[4], hA[4]}, {hA[5], hA[5], hA[5]}, {hA[6], hA[6], hA[6]}, {hA[7], hA[7], hA[7]}};
    if (mpc_ADD_verify(hHa[0], va, hHa[0], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[1], vb, hHa[1], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[2], vc, hHa[2], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[3], vd, hHa[3], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[4], ve, hHa[4], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[5], vf, hHa[5], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[6], vg, hHa[6], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }
    if (mpc_ADD_verify(hHa[7], vh, hHa[7], z.ve, z.ve1, randomness, randCount, countY) == 1)
    {
        printf("Failing at %d", __LINE__);
        return 1;
    }

    for (int i = 0; i < 8; i++)
    {
        mpc_RIGHTSHIFT2(hHa[i], 24, t0);
        results[0][i * 4] = t0[0];
        results[1][i * 4] = t0[1];
        mpc_RIGHTSHIFT2(hHa[i], 16, t0);
        results[0][i * 4 + 1] = t0[0];
        results[1][i * 4 + 1] = t0[1];
        mpc_RIGHTSHIFT2(hHa[i], 8, t0);
        results[0][i * 4 + 2] = t0[0];
        results[1][i * 4 + 2] = t0[1];

        results[0][i * 4 + 3] = hHa[i][0];
        results[1][i * 4 + 3] = hHa[i][1];
    }
    *countY += 8;

    return 0;
}

void verify(unsigned char digest[32], unsigned char public_key[8192], bool *error, a a, int e, z z)
{
    // Verifying views' commitments
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);
    H(z.ke, z.ve, z.re, hash);
    if (memcmp(a.h[e], hash, 32) != 0)
    {
        printf("Failing at %d", __LINE__);
        *error = true;
    }

    H(z.ke1, z.ve1, z.re1, hash);
    if (memcmp(a.h[(e + 1) % 3], hash, 32) != 0)
    {
        printf("Failing at %d", __LINE__);
        *error = true;
    }
    free(hash);

    unsigned char randomness[2][Random_Bytes_Needed];
    getAllRandomness(z.ke, randomness[0], Random_Bytes_Needed);
    getAllRandomness(z.ke1, randomness[1], Random_Bytes_Needed);

    int *randCount = calloc(1, sizeof(int));
    int *countY = calloc(1, sizeof(int));

    /* Verifying Circuit */
    int index_in_x = 0;
    uint32_t w[64][2] = {0};
    int index_in_a = 0;
    unsigned char *results[2];
    results[0] = malloc(32);
    results[1] = malloc(32);

    // Verifying signature's commitment proof
    if (e == 0)
    {
        for (int i = 0; i < 8; i++)
        {
            w[i][0] = (digest[i * 4] << 24) | (digest[i * 4 + 1] << 16) | (digest[i * 4 + 2] << 8) | digest[i * 4 + 3];
        }
    }

    if (e == 2)
    {
        for (int i = 0; i < 8; i++)
        {
            w[i][1] = (digest[i * 4] << 24) | (digest[i * 4 + 1] << 16) | (digest[i * 4 + 2] << 8) | digest[i * 4 + 3];
        }
    }

    for (int i = 0; i < 5; i++)
    {
        w[8 + i][0] = (z.ve.x[i * 4] << 24) | (z.ve.x[i * 4 + 1] << 16) | (z.ve.x[i * 4 + 2] << 8) | z.ve.x[i * 4 + 3];

        w[8 + i][1] =
            (z.ve1.x[i * 4] << 24) | (z.ve1.x[i * 4 + 1] << 16) | (z.ve1.x[i * 4 + 2] << 8) | z.ve1.x[i * 4 + 3];
    }

    w[8 + 5][0] = (z.ve.x[5 * 4] << 24) | (z.ve.x[5 * 4 + 1] << 16) | (z.ve.x[5 * 4 + 2] << 8);

    w[8 + 5][1] = (z.ve1.x[5 * 4] << 24) | (z.ve1.x[5 * 4 + 1] << 16) | (z.ve1.x[5 * 4 + 2] << 8);

    if (mpc_sha256_verify(w, results, 55 * 8, randCount, countY, randomness, z) == 1)
    {
        *error = true;
        printf("Failing at %d", __LINE__);
    }

    // xoring with secret commitment
    uint32_t t0[2], t1[2], tmp[2];
    index_in_x = 23;

    for (int i = 0; i < 8; i++)
    {
        memcpy(&t0[0], results[0] + i * 4, 4);
        memcpy(&t0[1], results[1] + i * 4, 4);

        memcpy(&t1[0], z.ve.x + index_in_x + i * 4, 4);
        memcpy(&t1[1], z.ve1.x + index_in_x + i * 4, 4);

        mpc_XOR2(t0, t1, tmp);

        if ((tmp[0] != a.yp[e][index_in_a]) || (tmp[1] != a.yp[(e + 1) % 3][index_in_a]))
        {
            *error = true;
            printf("Failing at %d, index_in_a = %d\n", __LINE__, index_in_a);
        }
        index_in_a++;
    }

    // Verifying Signature
    uint32_t verif_result[2][8];
    int index_in_pub_key = 0;

    for (int i = 0; i < 256; i++)
    {
        index_in_x = 55 + 32 * i;
        memset(w, 0, sizeof(w));

        for (int j = 0; j < 8; j++)
        {
            w[j][0] = (z.ve.x[index_in_x + 4 * j] << 24) | (z.ve.x[index_in_x + 4 * j + 1] << 16) |
                      (z.ve.x[index_in_x + 4 * j + 2] << 8) | z.ve.x[index_in_x + 4 * j + 3];

            w[j][1] = (z.ve1.x[index_in_x + 4 * j] << 24) | (z.ve1.x[index_in_x + 4 * j + 1] << 16) |
                      (z.ve1.x[index_in_x + 4 * j + 2] << 8) | z.ve1.x[index_in_x + 4 * j + 3];
        }

        if (mpc_sha256_verify(w, results, 32 * 8, randCount, countY, randomness, z) == 1)
        {
            *error = true;
            printf("Failing at %d", __LINE__);
        }

        for (int j = 0; j < 8; j++)
        {
            memcpy(&t0[0], results[0] + j * 4, 4);
            memcpy(&t0[1], results[1] + j * 4, 4);

            memcpy(&t1[0], z.ve.x + index_in_x + j * 4, 4);
            memcpy(&t1[1], z.ve1.x + index_in_x + j * 4, 4);

            mpc_XOR2(t0, t1, tmp);

            for (int k = 0; k < 2; k++)
            {
                verif_result[k][j] = tmp[k];
            }
        }

        uint32_t mask[2];
        int byte = i >> 3;
        int bit_pos;

        uint8_t v = z.ve.x[23 + byte];
        bit_pos = 7 - (i & 7);
        uint32_t b = (v >> bit_pos) & 1;
        mask[0] = 0u - b;

        v = z.ve1.x[23 + byte];
        bit_pos = 7 - (i & 7);
        b = (v >> bit_pos) & 1;
        mask[1] = 0u - b;

        for (int j = 0; j < 8; j++)
        {
            t0[0] = verif_result[0][j];
            t0[1] = verif_result[1][j];

            if (mpc_AND_verify(t0, mask, tmp, z.ve, z.ve1, randomness, randCount, countY) == 1)
            {
                *error = true;
                printf("Failing at %d", __LINE__);
            }
            for (int k = 0; k < 2; k++)
            {
                verif_result[k][j] = tmp[k];
            }
        }

        // Xoring with sha256 of WOTS_signature[i]
        for (int j = 0; j < 8; j++)
        {
            t0[0] = verif_result[0][j];
            t0[1] = verif_result[1][j];

            memcpy(&t1[0], results[0] + 4 * j, 4);
            memcpy(&t1[1], results[1] + 4 * j, 4);

            mpc_XOR2(t0, t1, tmp);

            for (int k = 0; k < 2; k++)
            {
                verif_result[k][j] = tmp[k];
            }
        }

        // Xoring with public_key[i]
        for (int j = 0; j < 8; j++)
        {
            if (e == 0)
            {
                t0[0] = verif_result[0][j];
                memcpy(&t1[0], public_key + index_in_pub_key + 4 * j, 4);

                tmp[0] = t0[0] ^ t1[0];

                verif_result[0][j] = tmp[0];
            }

            if (e == 2)
            {
                t0[0] = verif_result[1][j];

                memcpy(&t1[0], public_key + index_in_pub_key + 4 * j, 4);

                tmp[0] = t0[0] ^ t1[0];

                verif_result[1][j] = tmp[0];
            }

            tmp[0] = verif_result[0][j];
            tmp[1] = verif_result[1][j];

            if ((tmp[0] != a.yp[e][index_in_a]) || (tmp[1] != a.yp[(e + 1) % 3][index_in_a]))
            {
                *error = true;
                printf("Failing at %d, index_in_a = %d\n", __LINE__, index_in_a);
            }
            index_in_a++;
        }
        index_in_pub_key += 32;
    }

    free(results[0]);
    free(results[1]);
    free(randCount);
    free(countY);
    return;
}
