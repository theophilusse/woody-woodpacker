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
	uint8_t	s[256];
	uint8_t	tmp;
	size_t	i;
	size_t	j;
	size_t	k;

	i = 0;
	while (i < 256)
	{
		s[i] = (uint8_t)i;
		i++;
	}
	j = 0;
	i = 0;
	while (i < 256)
	{
		j = (j + s[i] + key[i % key_len]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		i++;
	}
	i = 0;
	j = 0;
	k = 0;
	while (k < len)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		data[k] ^= s[(s[i] + s[j]) % 256];
		k++;
	}
}
