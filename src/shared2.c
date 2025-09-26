void getAllRandomness(unsigned char key[32], unsigned char *randomness, int Bytes_Needed)
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