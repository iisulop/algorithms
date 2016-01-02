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

uint8_t C_D_SHIFT_TABLE[NUM_ROUNDS] =
{
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
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

static uint32_t
rotl_28bit (uint32_t x, uint8_t n)
{
  uint32_t ret_val = (x << 1) | (x >> (32 - 1));
  uint8_t rotation = (ret_val & 0xF0000000) >> 28;
  ret_val &= 0x0FFFFFFF;
  ret_val |= rotation;

  if (n > 1)
    {
      ret_val = rotl_28bit (ret_val, n - 1);
    }

  return ret_val;
}
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

static uint32_t
swap_endianness_32bit (uint32_t val)
{
  uint32_t ret_val = 0;
  ret_val = (val & 0x000000FF) << 8 * 3;
  ret_val |= (val & 0x0000FF00) << 8 * 1;
  ret_val |= (val & 0x00FF0000) >> 8 * 1;
  ret_val |= (val & 0xFF000000) >> 8 * 3;

  return ret_val;
}

static uint8_t
create_subkeys (uint8_t* key, uint8_t* (*subkeys)[16])
{
  uint8_t ret = 255;
  uint8_t* permuted_key = NULL;
  uint8_t i, j;
  uint32_t c[NUM_ROUNDS], d[NUM_ROUNDS];
  uint32_t c_initial, d_initial;

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

  memcpy (&c_initial, permuted_key, sizeof(uint32_t));
  c_initial = swap_endianness_32bit (c_initial);
  c_initial >>= 4;

  memcpy (&d_initial, permuted_key + 3, sizeof(uint32_t));
  d_initial = swap_endianness_32bit (d_initial);
  d_initial &= 0x0FFFFFFF;

  DBG_PRINT ("c_initial: %08x\n", c_initial);
  DBG_PRINT ("d_initial: %08x\n", d_initial);

  c[0] = rotl_28bit (c_initial, C_D_SHIFT_TABLE[0]);
  d[0] = rotl_28bit (d_initial, C_D_SHIFT_TABLE[0]);

  DBG_PRINT ("c[0]: %08x\t", c[0]);
  DBG_PRINT ("d[0]: %08x\n", d[0]);

  for (i = 1; i < NUM_ROUNDS; ++i)
    {
      c[i] = rotl_28bit (c[i - 1], C_D_SHIFT_TABLE[i - 1]);
      d[i] = rotl_28bit (d[i - 1], C_D_SHIFT_TABLE[i - 1]);
      DBG_PRINT ("c[%d]: %08x\t", i, c[i]);
      DBG_PRINT ("d[%d]: %08x\n", i, d[i]);
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
