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

#define BLOCK_SIZE 8
#define NUM_ROUNDS 16

uint8_t PC_1_TABLE[8 * BLOCK_SIZE - 1] =
  {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
  };

uint8_t IP_ENCODE_TABLE[8 * BLOCK_SIZE] =
  {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
  };

uint8_t IP_DECODE_TABLE[8 * BLOCK_SIZE] =
  {
    0
  };

uint8_t
get_permuted_byte (uint8_t* buf, uint8_t* table, uint8_t byte)
{
  uint8_t permuted = 0;
  uint8_t i;
  uint8_t bit_num;
  uint8_t byte_val;
  uint8_t bit;

  for (i = 0; i < 8; ++i)
    {
      bit_num = table[8 * byte + i];
      byte_val = buf[bit_num / 8];
      bit = ((byte_val >> (8 - (bit_num % 8))) & 0x01);

      permuted |= (bit << (7 - i));
    }

  return permuted;
}

static uint8_t
create_subkeys (uint8_t* key, uint8_t* (*subkeys)[16])
{
  uint8_t ret = 255;
  uint8_t* permuted_key = NULL;
  uint8_t i, j;

  permuted_key = malloc (BLOCK_SIZE - 1);
  if (permuted_key == NULL)
    {
      goto out;
    }

  for (i = 0; i < 7; ++i)
    {
      permuted_key[i] = get_permuted_byte (key, PC_1_TABLE, i);
    }
  DBG_PRINT ("\nPermuted key: %02x %02x %02x %02x %02x %02x %02x\n",
             permuted_key[0], permuted_key[1], permuted_key[2], permuted_key[3],
             permuted_key[4], permuted_key[5], permuted_key[6]);

  DBG_PRINT ("Subkeys: ");
  for (i = 0; i < BLOCK_SIZE; ++i)
    {
      for (j = 0; j < 8; ++j)
        {

        }
    }
  DBG_PRINT ("\n");

  ret = 0;

out:

  return ret;
}

static uint8_t
pad (uint8_t* buf, uint64_t len, uint8_t** padded, uint64_t* len_padded)
{
  uint8_t ret = 255;

  *len_padded = len + (len % BLOCK_SIZE);
  *padded = malloc(*len_padded);
  if (*padded == NULL)
    {
      goto out;
    }

  memcpy (*padded, buf, len);
  memset (*padded + len, 0, *len_padded - len);

  ret = 0;

out:
  return ret;
}

static uint8_t
ip_arrange (uint8_t* buf, uint64_t len, uint8_t** ip)
{
  uint8_t ret = 255;
  uint8_t i;

  *ip = malloc (BLOCK_SIZE);
  if (*ip == NULL)
    {
      goto out;
    }

  DBG_PRINT ("IP: ");
  for (i = 0; i < 8; ++i)
    {
      (*ip)[i] = get_permuted_byte (buf, IP_ENCODE_TABLE, i);
      DBG_PRINT ("%02x ", (*ip)[i]);
    }
  DBG_PRINT ("\n");

  ret = 0;

out:

  return ret;
}

static uint32_t
f (uint32_t r, uint8_t* k)
{
  uint32_t ret_val = 0;

  return ret_val;
}

static uint8_t
preoutput (uint8_t* l_in, uint8_t* r_in, uint8_t** subkeys, uint8_t** preout_but)
{
  uint8_t ret = 255;
  uint8_t i;
  uint32_t l;
  uint32_t r;
  uint32_t l_prev;

  memcpy (&l, l_in, BLOCK_SIZE / 2);
  memcpy (&r, r_in, BLOCK_SIZE / 2);
  /* TODO: endianness? */

  for (i = 0; i < NUM_ROUNDS; ++i)
    {
      l_prev = l;
      l = r;
      r = l_prev + (f (r, subkeys[i]));
    }

  ret = 0;

out:
  return ret;
}

uint8_t
calculate_des (uint8_t* buf, uint64_t len, uint8_t* key,
               uint8_t** ctx, uint64_t* ctx_len)
{
  uint8_t ret = 255;
  uint8_t* subkeys[NUM_ROUNDS] = {0};
  uint8_t* padded = NULL;
  uint64_t len_padded = 0;
  uint8_t* ip = NULL;
  uint8_t* preout_but = NULL;

  if (buf == NULL || key == NULL || ctx == NULL || ctx_len == NULL)
    {
      goto out;
    }

  ret = create_subkeys (key, &subkeys);
  if (ret != 0)
    {
      goto out;
    }

  ret = pad (buf, len, &padded, &len_padded);
  if (ret != 0)
    {
      goto out;
    }

  ret = ip_arrange (buf, len, &ip);
  if (ret != 0)
    {
      goto out;
    }

  ret = preoutput (ip, ip + (BLOCK_SIZE / 2), subkeys, &preout_but);
  if (ret != 0)
    {
      goto out;
    }

  /* Success */
  ret = 0;
out:
  return ret;
}
