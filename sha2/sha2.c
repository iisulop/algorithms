/*
 * Library for calculating the SHA256 hash over data.
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#ifndef NDEBUG
#define DBG_PRINT(...) do {printf (__VA_ARGS__);} while (0)
#else
#define DBG_PRINT(...)
#endif


/* The first thirty-two bits of the fractional parts of
   the cube roots of the first sixty-four prime numbers. */
static uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Rotate right */
static uint32_t
rotr (uint32_t x, uint8_t n)
{
  static uint32_t WORD_LENGTH = 32;
  assert (n < WORD_LENGTH && "n has to be smaller than bits in input");
  return ((x >> n) | (x << (WORD_LENGTH - n)));
}

static uint32_t
ch (uint32_t x, uint32_t y, uint32_t z)
{
  return ((x & y) ^ ((~x) & z));
}

static uint32_t
maj (uint32_t x, uint32_t y, uint32_t z)
{
  return ((x & y) ^ (x & z) ^ (y & z));
}

/* Capital sigma 0 */
static uint32_t
S0 (uint32_t x)
{
  return (rotr (x, 2) ^ rotr (x, 13) ^ rotr (x, 22));
}

/* Capital sigma 1 */
static uint32_t
S1 (uint32_t x)
{
  return (rotr (x, 6) ^ rotr (x, 11) ^ rotr (x, 25));
}

/* Lower-case sigma 0 */
static uint32_t
s0 (uint32_t x)
{
  return (rotr (x, 7) ^ rotr (x, 18) ^ (x >> 3));
}

/* Lower-case sigma 1 */
static uint32_t
s1 (uint32_t x)
{
  return (rotr (x, 17) ^ rotr (x, 19) ^ (x >> 10));
}

static uint8_t
preprocess (uint8_t* buf_in, uint64_t len_in,
            uint32_t** M, uint64_t* M_len,
            uint32_t** H, uint8_t* H_len)
{
  uint8_t ret = 255;
  uint64_t len_bits_in = len_in * 8;
  uint16_t num_pad = 0;
  uint8_t* buf_padded = NULL;
  uint64_t len_padded = 0;
  uint64_t i = 0;

  if (M == NULL || M_len == NULL ||
      H == NULL || H_len == NULL)
    {
      goto out;
    }

  /* Pad the message */
  /* num_pad = (448 - (len_in % 512) - 1); */
  num_pad = (64 - ((len_in + 8 + 1) % 64));

  len_padded = len_in + 1 + num_pad + sizeof (uint64_t);

  DBG_PRINT ("input buffer length: %llu\n", len_in);
  DBG_PRINT ("padding length: %u\n", num_pad);
  DBG_PRINT ("output buffer length: %llu\n\n", len_padded);

  buf_padded = calloc (len_padded, 1);
  if (buf_padded == NULL)
    {
      goto out;
    }

  memcpy (buf_padded, buf_in, len_in);

  buf_padded[len_in] = 0x80;

  DBG_PRINT ("Adding %d bytes of length starting at %llu\n",
          sizeof (len_in), len_in + 1 + num_pad);
  for (i = 0; i < sizeof (len_in); ++i)
    {
      buf_padded[len_in + 1 + num_pad + sizeof (len_in) - i - 1] =
        ((uint8_t*)&len_bits_in)[i];
    }

  /* Parse the message */
  *M_len = len_padded / 4;
  *M = malloc(*M_len * sizeof (uint32_t));
  for (i = 0; i < *M_len; ++i)
    {
      (*M)[i] = buf_padded[i * 4 + 0] << 3 * 8;
      (*M)[i] |= buf_padded[i * 4 + 1] << 2 * 8;
      (*M)[i] |= buf_padded[i * 4 + 2] << 1 * 8;
      (*M)[i] |= buf_padded[i * 4 + 3];

      DBG_PRINT ("M[%02llu]: %08X\n", i, (*M)[i]);
    }
  DBG_PRINT ("\n");

  /* Set the initial hash value */
  *H = malloc (8 * sizeof (uint32_t));
  if (*H == NULL)
    {
      goto out;
    }
  (*H)[0] = 0x6a09e667;
  (*H)[1] = 0xbb67ae85;
  (*H)[2] = 0x3c6ef372;
  (*H)[3] = 0xa54ff53a;
  (*H)[4] = 0x510e527f;
  (*H)[5] = 0x9b05688c;
  (*H)[6] = 0x1f83d9ab;
  (*H)[7] = 0x5be0cd19;

 *H_len = 8;

  /* Success */
  ret = 0;

out:
  free (buf_padded);
  buf_padded = NULL;

  return ret;
}

static uint8_t
compute_hash (uint32_t* M, uint64_t M_len,
              uint32_t* H, uint8_t H_len)
{
  uint8_t ret = 255;
  uint32_t W[64];
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t T[2] = {0};
  uint64_t i, j;

  if (M == NULL ||
      H == NULL || H_len != 8)
    {
      goto out;
    }

  for (i = 0; i < (M_len / 16); ++i)
    {
      memset (W, 0, sizeof (W));

      for (j = 0; j < 16; ++j)
        {
          W[j] = M[i * 16 + j];
          DBG_PRINT ("W[%llu]: %08X\n", j, W[j]);
        }
      for (j = 16; j < 64; ++j)
        {
          W[j] = s1 (W[j - 2]) +
            W[j - 7] +
            s0 (W[j - 15]) +
            W[j - 16];
          DBG_PRINT ("W[%llu]: %08X\n", j, W[j]);
        }
      DBG_PRINT("\n");

      a = H[0]; b = H[1]; c = H[2]; d = H[3];
      e = H[4]; f = H[5]; g = H[6]; h = H[7];

      DBG_PRINT ("a: %08X, b: %08X, c: %08X, d: %08X, "
              "e: %08X, f: %08X, g: %08X, h: %08X\n",
              a, b, c, d, e, f, g, h);
      DBG_PRINT("\n");

      for (j = 0; j < 64; ++j)
        {
          T[0] = h + S1 (e) + ch (e, f, g) + K[j] + W[j];
          T[1] = S0 (a) + maj (a, b, c);
          h = g;
          g = f;
          f = e;
          e = d + T[0];
          d = c;
          c = b;
          b = a;
          a = T[0] + T[1];
          DBG_PRINT ("a: %08X, b: %08X, c: %08X, d: %08X, "
                  "e: %08X, f: %08X, g: %08X, h: %08X\n",
                  a, b, c, d, e, f, g, h);
        }
      DBG_PRINT("\n");

      for (j = 0; j < 8; ++j)
        {
          DBG_PRINT ("H-1[%llu]: %08X, ", j, H[j]);
        }
      DBG_PRINT("\n");

      DBG_PRINT ("\na: %08X, b: %08X, c: %08X, d: %08X, "
              "e: %08X, f: %08X, g: %08X, h: %08X\n",
              a, b, c, d, e, f, g, h);

      H[0] = a + H[0];
      H[1] = b + H[1];
      H[2] = c + H[2];
      H[3] = d + H[3];
      H[4] = e + H[4];
      H[5] = f + H[5];
      H[6] = g + H[6];
      H[7] = h + H[7];

      for (j = 0; j < 8; ++j)
        {
          DBG_PRINT ("H[%llu]: %02X, ", j, H[j]);
        }
      DBG_PRINT ("\nRound %llu/%llu\n", i, M_len/16);
    }

  ret = 0;

out:
  return ret;
}

uint8_t
calculate_sha256 (uint8_t* buf, uint64_t len,
                  uint8_t** hash, uint32_t* hash_len)
{
  uint8_t ret = 255;
  uint32_t *M = NULL;
  uint64_t M_len = 0;
  uint32_t *H = NULL;
  uint8_t H_len = 0;
  uint32_t i;

  if (hash == NULL || hash_len == NULL)
    {
      goto out;
    }

  ret = preprocess (buf, len, &M, &M_len, &H, &H_len);
  if (ret != 0)
    {
      goto out;
    }

  ret = compute_hash (M, M_len, H, H_len);
  if (ret != 0)
    {
      goto out;
    }

  *hash = malloc (H_len * sizeof (uint32_t));
  for (i = 0; i < H_len; ++i)
    {
      (*hash)[4 * i] = (uint8_t)(H[i] >> 3 * 8);
      (*hash)[4 * i + 1] = (uint8_t)(H[i] >> 2 * 8);
      (*hash)[4 * i + 2] = (uint8_t)(H[i] >> 1 * 8);
      (*hash)[4 * i + 3] = (uint8_t)(H[i]);
    }
  *hash_len = H_len * sizeof (uint32_t);

  /* Success */
  ret = 0;

out:
  free (M);
  M = NULL;
  free (H);
  H = NULL;

  return ret;
}
