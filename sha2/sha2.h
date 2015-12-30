#include <stdint.h>

/*
 * Calculate the SHA256 hash over the given input.
 *
 * @param buf The buffer of data to calculate the hash over.
 * @param len The length of the buf parameter in bytes.
 * @param hash The result of the hash.
 * @param hash_len The length of the result hash.
 *
 * @return Zero on success, non-zero on failure.
 *
 */
uint8_t
calculate_sha256 (uint8_t* buf, uint64_t len,
                  uint8_t** hash, uint64_t* hash_len);
