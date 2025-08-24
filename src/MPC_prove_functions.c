#include "MPC_prove_functions.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3])
{
    z[0] = x[0] ^ y[0];
    z[1] = x[1] ^ y[1];
    z[2] = x[2] ^ y[2];
}

void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int *randCount, View views[3],
             int *countY)
{
    uint32_t r[3] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount),
                     getRandom32(randomness[2], *randCount)};
    *randCount += 4; // Because 32 bits = 4 octets
    uint32_t t[3] = {0};

    t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
    t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
    t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
    z[0] = t[0];
    z[1] = t[1];
    z[2] = t[2];
    views[0].y[*countY] = z[0];
    views[1].y[*countY] = z[1];
    views[2].y[*countY] = z[2];
    (*countY)++;
}

void mpc_NEGATE(uint32_t x[3], uint32_t z[3])
{
    z[0] = ~x[0];
    z[1] = ~x[1];
    z[2] = ~x[2];
}

void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int *randCount, View views[3],
             int *countY)
{
    uint32_t c[3] = {0};
    uint32_t r[3] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount),
                     getRandom32(randomness[2], *randCount)};

    // if (first)
    // {
    //     printf("r[0] = %08X, r[1] = %08X, r[2] = %08X\n", r[0], r[1], r[2]);
    // }

    *randCount += 4;
    uint8_t a[3], b[3];

    uint8_t t;

    for (int i = 0; i < 31; i++)
    {
        a[0] = GETBIT(x[0] ^ c[0], i);
        a[1] = GETBIT(x[1] ^ c[1], i);
        a[2] = GETBIT(x[2] ^ c[2], i);

        b[0] = GETBIT(y[0] ^ c[0], i);
        b[1] = GETBIT(y[1] ^ c[1], i);
        b[2] = GETBIT(y[2] ^ c[2], i);

        t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
        SETBIT(c[0], i + 1, t ^ (a[0] & b[0]) ^ GETBIT(c[0], i) ^ GETBIT(r[0], i));

        t = (a[1] & b[2]) ^ (a[2] & b[1]) ^ GETBIT(r[2], i);
        SETBIT(c[1], i + 1, t ^ (a[1] & b[1]) ^ GETBIT(c[1], i) ^ GETBIT(r[1], i));

        t = (a[2] & b[0]) ^ (a[0] & b[2]) ^ GETBIT(r[0], i);
        SETBIT(c[2], i + 1, t ^ (a[2] & b[2]) ^ GETBIT(c[2], i) ^ GETBIT(r[2], i));
    }

    z[0] = x[0] ^ y[0] ^ c[0];
    z[1] = x[1] ^ y[1] ^ c[1];
    z[2] = x[2] ^ y[2] ^ c[2];

    views[0].y[*countY] = c[0];
    views[1].y[*countY] = c[1];
    views[2].y[*countY] = c[2];
    *countY += 1;
}

void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3], unsigned char *randomness[3], int *randCount, View views[3],
              int *countY)
{
    uint32_t c[3] = {0};
    uint32_t r[3] = {getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount),
                     getRandom32(randomness[2], *randCount)};
    *randCount += 4;

    uint8_t a[3], b[3];

    uint8_t t;

    for (int i = 0; i < 31; i++)
    {
        a[0] = GETBIT(x[0] ^ c[0], i);
        a[1] = GETBIT(x[1] ^ c[1], i);
        a[2] = GETBIT(x[2] ^ c[2], i);

        b[0] = GETBIT(y ^ c[0], i);
        b[1] = GETBIT(y ^ c[1], i);
        b[2] = GETBIT(y ^ c[2], i);

        t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
        SETBIT(c[0], i + 1, t ^ (a[0] & b[0]) ^ GETBIT(c[0], i) ^ GETBIT(r[0], i));

        t = (a[1] & b[2]) ^ (a[2] & b[1]) ^ GETBIT(r[2], i);
        SETBIT(c[1], i + 1, t ^ (a[1] & b[1]) ^ GETBIT(c[1], i) ^ GETBIT(r[1], i));

        t = (a[2] & b[0]) ^ (a[0] & b[2]) ^ GETBIT(r[0], i);
        SETBIT(c[2], i + 1, t ^ (a[2] & b[2]) ^ GETBIT(c[2], i) ^ GETBIT(r[2], i));
    }

    z[0] = x[0] ^ y ^ c[0];
    z[1] = x[1] ^ y ^ c[1];
    z[2] = x[2] ^ y ^ c[2];

    views[0].y[*countY] = c[0];
    views[1].y[*countY] = c[1];
    views[2].y[*countY] = c[2];
    *countY += 1;
}

void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[])
{
    z[0] = RIGHTROTATE(x[0], i);
    z[1] = RIGHTROTATE(x[1], i);
    z[2] = RIGHTROTATE(x[2], i);
}

void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3])
{
    z[0] = x[0] >> i;
    z[1] = x[1] >> i;
    z[2] = x[2] >> i;
} // shift means leaving zeros on the left

void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3], unsigned char *randomness[3], int *randCount,
             View views[3], int *countY)
{
    uint32_t t0[3];
    uint32_t t1[3];

    mpc_XOR(a, b, t0);
    mpc_XOR(a, c, t1);
    mpc_AND(t0, t1, z, randomness, randCount, views, countY);
    mpc_XOR(z, a, z);
} // maj means choosing 0 if 0 is in majority beyound 3 bits (same goes for 1)

void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3], unsigned char *randomness[3], int *randCount,
            View views[3], int *countY)
{
    uint32_t t0[3];

    // e & (f^g) ^ g
    mpc_XOR(f, g, t0);
    mpc_AND(e, t0, t0, randomness, randCount, views, countY);
    mpc_XOR(t0, g, z);
}

void mpc_sha256(unsigned char *inputs[3], int numBits, unsigned char *randomness[3], unsigned char *results[3],
                View views[3], int *countY, int *randCount)
{
    int chars = numBits >> 3; // Dividing by 8 = getting Bytes number
    unsigned char *chunks[3];
    uint32_t w[64][3];

    for (int i = 0; i < 3; i++)
    {
        chunks[i] = calloc(64, 1); // 512 bits
        memcpy(chunks[i], inputs[i], chars);
        chunks[i][chars] = 0x80;
        chunks[i][62] = numBits >> 8;
        chunks[i][63] = numBits;

        for (int j = 0; j < 16; j++)
        {
            w[j][i] = (chunks[i][j * 4] << 24) | (chunks[i][j * 4 + 1] << 16) | (chunks[i][j * 4 + 2] << 8) |
                      chunks[i][j * 4 + 3];
        }
        free(chunks[i]);
    }

    uint32_t s0[3], s1[3];
    uint32_t t0[3], t1[3];

    for (int j = 16; j < 64; j++)
    {
        mpc_RIGHTROTATE(w[j - 15], 7, t0);
        mpc_RIGHTROTATE(w[j - 15], 18, t1);
        mpc_XOR(t0, t1, t0);
        mpc_RIGHTSHIFT(w[j - 15], 3, t1);
        mpc_XOR(t0, t1, s0);
        mpc_RIGHTROTATE(w[j - 2], 17, t0);
        mpc_RIGHTROTATE(w[j - 2], 19, t1);
        mpc_XOR(t0, t1, t0);
        mpc_RIGHTSHIFT(w[j - 2], 10, t1);
        mpc_XOR(t0, t1, s1);
        mpc_ADD(w[j - 16], s0, t1, randomness, randCount, views, countY);
        mpc_ADD(w[j - 7], t1, t1, randomness, randCount, views, countY);
        mpc_ADD(t1, s1, w[j], randomness, randCount, views, countY);
    }

    uint32_t a[3] = {hA[0], hA[0], hA[0]};
    uint32_t b[3] = {hA[1], hA[1], hA[1]};
    uint32_t c[3] = {hA[2], hA[2], hA[2]};
    uint32_t d[3] = {hA[3], hA[3], hA[3]};
    uint32_t e[3] = {hA[4], hA[4], hA[4]};
    uint32_t f[3] = {hA[5], hA[5], hA[5]};
    uint32_t g[3] = {hA[6], hA[6], hA[6]};
    uint32_t h[3] = {hA[7], hA[7], hA[7]};
    uint32_t temp1[3], temp2[3], maj[3];

    for (int i = 0; i < 64; i++)
    {
        mpc_RIGHTROTATE(e, 6, t0);
        mpc_RIGHTROTATE(e, 11, t1);
        mpc_XOR(t0, t1, t0);
        mpc_RIGHTROTATE(e, 25, t1);
        mpc_XOR(t0, t1, s1);
        mpc_ADD(h, s1, t0, randomness, randCount, views, countY);
        mpc_CH(e, f, g, t1, randomness, randCount, views, countY);
        mpc_ADD(t0, t1, t1, randomness, randCount, views, countY);
        mpc_ADDK(t1, k[i], t1, randomness, randCount, views, countY);
        mpc_ADD(t1, w[i], temp1, randomness, randCount, views, countY);
        mpc_RIGHTROTATE(a, 2, t0);
        mpc_RIGHTROTATE(a, 13, t1);
        mpc_XOR(t0, t1, t0);
        mpc_RIGHTROTATE(a, 22, t1);
        mpc_XOR(t0, t1, s0);
        mpc_MAJ(a, b, c, maj, randomness, randCount, views, countY);
        mpc_ADD(s0, maj, temp2, randomness, randCount, views, countY);
        memcpy(h, g, sizeof(uint32_t) * 3);
        memcpy(g, f, sizeof(uint32_t) * 3);
        memcpy(f, e, sizeof(uint32_t) * 3);
        mpc_ADD(d, temp1, e, randomness, randCount, views, countY);
        memcpy(d, c, sizeof(uint32_t) * 3);
        memcpy(c, b, sizeof(uint32_t) * 3);
        memcpy(b, a, sizeof(uint32_t) * 3);
        mpc_ADD(temp1, temp2, a, randomness, randCount, views, countY);
    }

    uint32_t hHa[8][3] = {{hA[0], hA[0], hA[0]}, {hA[1], hA[1], hA[1]}, {hA[2], hA[2], hA[2]}, {hA[3], hA[3], hA[3]},
                          {hA[4], hA[4], hA[4]}, {hA[5], hA[5], hA[5]}, {hA[6], hA[6], hA[6]}, {hA[7], hA[7], hA[7]}};
    mpc_ADD(hHa[0], a, hHa[0], randomness, randCount, views, countY);
    mpc_ADD(hHa[1], b, hHa[1], randomness, randCount, views, countY);
    mpc_ADD(hHa[2], c, hHa[2], randomness, randCount, views, countY);
    mpc_ADD(hHa[3], d, hHa[3], randomness, randCount, views, countY);
    mpc_ADD(hHa[4], e, hHa[4], randomness, randCount, views, countY);
    mpc_ADD(hHa[5], f, hHa[5], randomness, randCount, views, countY);
    mpc_ADD(hHa[6], g, hHa[6], randomness, randCount, views, countY);
    mpc_ADD(hHa[7], h, hHa[7], randomness, randCount, views, countY);

    for (int i = 0; i < 8; i++)
    {
        mpc_RIGHTSHIFT(hHa[i], 24, t0);
        results[0][i * 4] = t0[0];
        results[1][i * 4] = t0[1];
        results[2][i * 4] = t0[2];
        mpc_RIGHTSHIFT(hHa[i], 16, t0);
        results[0][i * 4 + 1] = t0[0];
        results[1][i * 4 + 1] = t0[1];
        results[2][i * 4 + 1] = t0[2];
        mpc_RIGHTSHIFT(hHa[i], 8, t0);
        results[0][i * 4 + 2] = t0[0];
        results[1][i * 4 + 2] = t0[1];
        results[2][i * 4 + 2] = t0[2];

        results[0][i * 4 + 3] = hHa[i][0];
        results[1][i * 4 + 3] = hHa[i][1];
        results[2][i * 4 + 3] = hHa[i][2];
    }

    for (int i = 0; i < 8; i++)
    {
        views[0].y[*countY] = (results[0][i * 4] << 24) | (results[0][i * 4 + 1] << 16) | (results[0][i * 4 + 2] << 8) |
                              results[0][i * 4 + 3];
        views[1].y[*countY] = (results[1][i * 4] << 24) | (results[1][i * 4 + 1] << 16) | (results[1][i * 4 + 2] << 8) |
                              results[1][i * 4 + 3];
        views[2].y[*countY] = (results[2][i * 4] << 24) | (results[2][i * 4 + 1] << 16) | (results[2][i * 4 + 2] << 8) |
                              results[2][i * 4 + 3];
        *countY += 1;
    }
}
