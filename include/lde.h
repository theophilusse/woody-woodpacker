#ifndef LDE_H
# define LDE_H

typedef struct {
	const uint8_t *buf;
	size_t         pos;
	size_t         end;
} t_lde_dec;

int lde_verify(const uint8_t *buf, size_t start, size_t end,
		const uint8_t *expected_key, size_t key_len);

#endif