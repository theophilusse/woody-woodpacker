#ifndef WOODY_H
# define WOODY_H

# include <stdio.h>
# include <string.h>
# include <stdlib.h>

# include <sys/types.h>
# include <sys/stat.h>
# include <sys/random.h>

# include <elf.h>
# include <stdint.h>
# include <stddef.h>

# include "emit.h"

# define KEY_LEN 16
# define WOODY_MSG "....WOODY....\n"
# define WOODY_MSG_LEN 14

typedef struct s_elf_ctx
{
	Elf64_Ehdr	*ehdr;
	Elf64_Phdr	*phdrs;
	uint8_t		*raw;
	size_t		size;
	int			target_phdr_idx;
}	t_elf_ctx;

typedef struct s_crypto_ctx
{
	uint8_t		key[KEY_LEN];
	size_t		key_len;
	uint8_t		*encrypted_text;
	size_t		text_len;
	uint64_t	text_vaddr;
}	t_crypto_ctx;

typedef struct s_stub
{
	uint8_t		*bytes;
	size_t		len;
	uint64_t	load_vaddr;
	uint64_t	original_oep;
	size_t		patch_jmp_oep;
}	t_stub;

/* elf_parser.c */
t_elf_ctx	*elf_load(const char *path);
int			elf_validate(t_elf_ctx *ctx);
void		elf_free(t_elf_ctx *ctx);

/* elf_inject.c */
int			elf_find_injection_point(t_elf_ctx *ctx);
size_t			padding_available(Elf64_Phdr *p);
int			elf_patch(t_elf_ctx *ctx, t_stub *stub, t_crypto_ctx *crypto);
int			elf_write(t_elf_ctx *ctx, const char *out_path);

/* crypto_rc4.c */
int			crypto_generate_key(t_crypto_ctx *crypto);
void		rc4_apply(uint8_t *data, size_t len, const uint8_t *key, size_t key_len);

/* stub_build.c */
t_stub		*stub_build(t_elf_ctx *ctx, t_crypto_ctx *crypto);
void		stub_free(t_stub *stub);

#endif
