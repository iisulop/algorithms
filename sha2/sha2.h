#include <stdint.h>

uint8_t
calculate_sha256 (uint8_t* buf, uint64_t len,
                  uint8_t** hash, uint64_t* hash_len);
