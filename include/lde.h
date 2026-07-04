#ifndef LDE_H
# define LDE_H

int lde_verify(const uint8_t *buf, size_t start, size_t end,
               const uint8_t *expected_key, size_t key_len);

#endif