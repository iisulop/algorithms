#include <stdint.h>

/*
 * Calculate DES encrypted ciphertext of the given buffer using the given key.
 * @buf Plaintext input to encrypt.
 * @len Length of the plaintext input.
 * @key Key to use for encryption [8 bytes].
 * @ctx Encrypted ciphertext.
 * @ctx_len Length of the encrypted ciphertext.
 * @return Zero for success, non-zero otherwise.
 */
uint8_t
calculate_des (uint8_t* buf, uint64_t len, uint8_t* key,
               uint8_t** ctx, uint64_t* ctx_len);
