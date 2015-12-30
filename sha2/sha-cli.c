/*
 * Command line interface for the sha256 operation.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha2.h"


int main(int argc, char* argv[])
{
  uint8_t* buf = NULL;
  uint64_t len = sizeof (buf);
  uint8_t* hash = NULL;
  uint64_t hash_len = 0;
  uint8_t ret = 0;
  uint32_t i;

  if (argc != 2)
    {
      printf ("Usage: %s INPUT\n", argv[0]);
      return 1;
    }

  buf = (uint8_t*)argv[1];
  len = strlen ((const char*)buf);

  ret = calculate_sha256 (buf, len, &hash, &hash_len);

  for (i = 0; i < hash_len; ++i)
    {
      printf ("%02x", hash[i]);
    }
  printf ("\n");

  free (hash);
  hash = NULL;

  return ret;
}
