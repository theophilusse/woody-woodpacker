#include "woody.h"

int	crypto_generate_key(t_crypto_ctx *crypto)
{
	/* getrandom() ou /dev/urandom pour remplir crypto->key,
	 * crypto->key_len = KEY_LEN */
	ssize_t ret;

	if (!crypto)
		return (1);
	crypto->key_len = KEY_LEN;
	ret = getrandom(crypto->key, crypto->key_len, 0);
	if (ret < 0 || (size_t)ret != crypto->key_len)
	{
		FILE *f;

		f = fopen("/dev/urandom", "rb");
		if (!f)
			return (1);
		if (fread(crypto->key, 1, crypto->key_len, f) != crypto->key_len)
		{
			fclose(f);
			return (1);
		}
		fclose(f);
	}
	return (0);
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
