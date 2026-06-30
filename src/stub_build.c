#include <stdlib.h>
#include "woody.h"

t_stub	*stub_build(t_elf_ctx *ctx, t_crypto_ctx *crypto)
{
	(void)ctx;
	(void)crypto;
	/* TODO: émettre, dans l'ordre, l'encodage machine x86_64 réel de :
	 *   1. write(1, MSG_WOODY, WOODY_MSG_LEN)
	 *   2. récupération RIP (lea reg, [rip+0])
	 *   3. mprotect(page, len, RWX)  -> rax=10
	 *   4. boucle de déchiffrement RC4 en place
	 *   5. jmp vers original_oep
	 * cf. blueprint pour la séquence logique détaillée */
	return (NULL);
}

void	stub_free(t_stub *stub)
{
	if (!stub)
		return ;
	free(stub->bytes);
	free(stub);
}
