#include "woody.h"

int	crypto_generate_key(t_crypto_ctx *crypto)
{
	(void)crypto;
	/* TODO: getrandom() ou /dev/urandom pour remplir crypto->key,
	 * crypto->key_len = KEY_LEN */
	return (-1);
}

void	rc4_apply(uint8_t *data, size_t len, const uint8_t *key, size_t key_len)
{
	(void)data;
	(void)len;
	(void)key;
	(void)key_len;
	/* TODO: KSA puis PRGA (cf. blueprint), XOR octet par octet.
	 * Symétrique : sert au chiffrement ET au déchiffrement. */
}
