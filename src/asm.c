#include "asm.h"

static const char *R64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12"};
static const char *R32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d"};
static const char *R8[]  = {"al","cl","dl","bl","r8b","r9b","r10b","r11b","r12b"};

static int	preg(const char *s, t_reg *r, int *sz)
{
	int	i;

	for (i = 0; i < 12; i++) {
		if (!strcmp(s,R64[i])) { *r=(t_reg)i; *sz=64; return 1; }
		if (!strcmp(s,R32[i])) { *r=(t_reg)i; *sz=32; return 1; }
	}
	for (i = 0; i < 8; i++)
		if (!strcmp(s,R8[i])) { *r=(t_reg)i; *sz=8; return 1; }
	return 0;
}

/* ── symboles ───────────────────────────────────────────────────── */
static int64_t	sym(t_asm *a, const char *n)
{
	int i;

	if (!strcmp(n,"prot_addr"))
		return (int64_t)(a->crypto->text_vaddr & ~(uint64_t)0xFFF);
	if (!strcmp(n,"prot_size"))
		return (int64_t)(((a->crypto->text_vaddr & 0xFFF)
				+ a->crypto->text_len + 0xFFF) & ~(size_t)0xFFF);
	if (!strcmp(n,"text_vaddr"))  return (int64_t)a->crypto->text_vaddr;
	if (!strcmp(n,"text_len"))    return (int64_t)a->crypto->text_len;
	if (!strcmp(n,"key_mask"))    return (int64_t)(a->crypto->key_len - 1);
	for (i = 0; i < a->nlabels; i++)
		if (!strcmp(a->labels[i].name, n)) return (int64_t)a->labels[i].off;
	return -1;
}

static void	deflabel(t_asm *a, const char *name)
{
	if (DEBUG_MODE)
		printf("deflabel: %s at %zu\n", name, a->out->e.len);
	if (a->nlabels >= MAX_LABELS) return;
	strncpy(a->labels[a->nlabels].name, name, 63);
	a->labels[a->nlabels].off = a->out->e.len;
	a->nlabels++;
}

//static void	fixup(t_asm *a, const char *name, size_t off, size_t end)
static void	addfixup(t_asm *a, const char *name, size_t off, size_t end, int is_rel8)
{
	if (a->nfixups >= MAX_FIXUPS) return;
	a->fixups[a->nfixups].off = off;
	a->fixups[a->nfixups].end = end;
	a->fixups[a->nfixups].is_rel8 = is_rel8;
	strncpy(a->fixups[a->nfixups].name, name, 63);
	a->nfixups++;
}

/* ── tokeniseur ─────────────────────────────────────────────────── */
/* retourne nb tokens, tokenise une ligne.
 * crochets [base+idx] = un seul token.
 * pas de lowercase dans les identifiants commencant par @. */
static int	tokenize(const char *line, char toks[][64], int max)
{
	const char	*p = line;
	int			n = 0;
	int			i;

	while (*p && *p != ';' && *p != '\n')
	{
		while (*p == ' ' || *p == '\t') p++;
		if (!*p || *p == ';' || *p == '\n') break;
		if (*p == ',') { p++; continue; }
		if (*p == '[')
		{
			char tmp[64]; i = 0; tmp[i++] = '['; p++;
			while (*p && *p != ']') tmp[i++] = tolower((unsigned char)*p++);
			if (*p == ']') { tmp[i++] = ']'; p++; }
			tmp[i] = '\0';
			if (n < max) { strncpy(toks[n++], tmp, 63); }
			continue;
		}
		if (*p)
		{
			char tmp[64]; i = 0;
			while (*p && *p != ' ' && *p != '\t' && *p != ',' && *p != '[' && *p != ']' && *p != ';' && *p != '\n')
				tmp[i++] = *p++;
			tmp[i] = '\0';
			if (i > 0 && n < max)
			{
				int j = 0;
				while (tmp[j]) { toks[n][j] = tolower((unsigned char)tmp[j]); j++; }
				toks[n][j] = '\0';
				n++;
			}
		}
	}
	return n;
}

/* ── parse memoire [base+idx] ou [label] ──────────────────────── */
/* retourne 1 = SIB, 2 = label RIP-relative, 0 = erreur */
static int pmem(const char *tok, t_reg *base, t_reg *idx, char *lbl, int8_t *disp)
{
    char inner[64];
    char *plus;
    t_reg r;
    int sz;

    if (tok[0] != '[') return 0;
    strncpy(inner, tok + 1, 63);
    int n = (int)strlen(inner);
    if (n > 0 && inner[n - 1] == ']') inner[n - 1] = '\0';

    // Supprimer les espaces
    char *dst = inner;
    for (char *src = inner; *src; src++) {
        if (*src != ' ') *dst++ = *src;
    }
    *dst = '\0';

    plus = strchr(inner, '+');
    if (plus)
    {
        *plus = '\0';
        if (!preg(inner, base, &sz)) return 0;
        if (preg(plus + 1, idx, &sz))
        {
            if (*idx == REG_RSP || *idx == REG_RBP || *base == REG_RSP || *base == REG_RBP)
                return 1; // SIB nécessaire
            return 1; // SIB (même si pas nécessaire)
        }
        *disp = (int8_t)strtoll(plus + 1, NULL, 0);
        return 4; // [base+disp8]
    }

    if (preg(inner, &r, &sz)) { *base = r; return 3; } // [base] seul
    strncpy(lbl, inner, 63);
    return 2; // [label] RIP-relative
}

/* ── lea avec label et fixup si necessaire ──────────────────────── */
static void	lea_label(t_asm *a, t_reg dst, const char *label)
{
	size_t	patch;
	int32_t	disp;
	int64_t	val;

	emit_lea_rip(&a->out->e, dst, &patch);
	val = sym(a, label);
	if (val >= 0)
	{
		disp = (int32_t)(val - (int64_t)(patch + 4));
		patch_disp32(&a->out->e, patch, disp);
	}
	else
		addfixup(a, label, patch, patch + 4, 0);
}

static uint8_t jcc_opcode(const char *m)
{
    if (!strcmp(m,"jne")||!strcmp(m,"jnz")) return 0x75;
    if (!strcmp(m,"je") ||!strcmp(m,"jz"))  return 0x74;
    if (!strcmp(m,"jl") ||!strcmp(m,"jnge"))return 0x7C;
    if (!strcmp(m,"jg") ||!strcmp(m,"jnle"))return 0x7F;
    if (!strcmp(m,"jle")||!strcmp(m,"jng")) return 0x7E;
    if (!strcmp(m,"jge")||!strcmp(m,"jnl")) return 0x7D;
    if (!strcmp(m,"jae")||!strcmp(m,"jnb")) return 0x73;
    if (!strcmp(m,"jbe")||!strcmp(m,"jna")) return 0x76;
	if (!strcmp(m,"jb") ||!strcmp(m,"jnae")||!strcmp(m,"jc")) return 0x72;
    return 0;
}

/* ── assemblage d une instruction ──────────────────────────────── */
static int	ainstr(t_asm *a, char toks[][64], int n)
{
	unsigned int		lsb_value;
	t_reg	r1, r2, base, idx;
	int		s1, s2;
	int64_t	val;
	char	lbl[64];
	int		mt;
	int8_t d8 = 0;
	uint8_t op;

	if (DEBUG_MODE)
	{
		for (int i = 0; i < n; i++)
			printf("%s ", toks[i]);
		printf("\n");
	}
	if (n == 0) return 0;
	base = idx = REG_RAX; s1 = s2 = 0; lbl[0] = '\0';
	lsb_value = a->crypto->key[(a->key_index / 8) % a->crypto->key_len] & (0x01 << a->key_index);
	if (!strcmp(toks[0], "syscall"))
		{ emit_syscall(&a->out->e); return 0; }
	if (!strcmp(toks[0], "rtdsc"))
		{ emit_rdtsc(&a->out->e); return 0; }
	if (n == 2 && (op = jcc_opcode(toks[0])))
	{
		int64_t lval = sym(a, toks[1]);
		if (lval >= 0)
		{
			int64_t disp = lval - (int64_t)(a->out->e.len + 2);
			if (disp >= -128 && disp <= 127)
			{
				emit_jcc_rel8_direct(&a->out->e, op, (int8_t)disp);
			}
			else
			{
				/* backward mais trop loin pour rel8 : forme near 0F 8x rel32 */
				int32_t d32 = (int32_t)(lval - (int64_t)(a->out->e.len + 6));
				uint8_t bytes[6] = {0x0F, (uint8_t)(0x80 | (op & 0x0F)), 0,0,0,0};
				memcpy(bytes + 2, &d32, 4);
				emit_raw(&a->out->e, bytes, 6);
			}
		}
		else
		{
			/* forward, distance inconnue : trampoline (condition inversée + jmp rel32) */
			uint8_t bytes[2] = { (uint8_t)(op ^ 1), 5 };
			emit_raw(&a->out->e, bytes, 2);
			size_t dummy;
			emit_jmp_rel32(&a->out->e, &dummy);
			addfixup(a, toks[1], dummy, dummy + 4, 0);   /* is_rel8 = 0 */
		}
		return 0;
	}
	if (!strcmp(toks[0], "push") && n == 2 && preg(toks[1], &r1, &s1))
		{ emit_push_r64(&a->out->e, r1); return 0; }

	if (!strcmp(toks[0], "pop") && n == 2 && preg(toks[1], &r1, &s1))
		{ emit_pop_r64(&a->out->e, r1); return 0; }

	if (!strcmp(toks[0], "inc") && n == 2 && preg(toks[1], &r1, &s1))
	{
		if (s1 == 8) emit_inc_r8(&a->out->e, r1);
		else emit_inc_r64(&a->out->e, r1);
		return 0;
	}
	if (!strcmp(toks[0], "dec") && n == 2 && preg(toks[1], &r1, &s1))
	{
		if (!preg(toks[1], &r1, &s1))
			return (-1);
		if (s1 == 8)       emit_dec_r8(&a->out->e, r1);
		else if (s1 == 32) emit_dec_r32(&a->out->e, r1);
		else               emit_dec_r64(&a->out->e, r1);
	}
	if (!strcmp(toks[0], "sub") && n == 3 && preg(toks[1], &r1, &s1) && r1 == REG_RSP)
		{ emit_sub_rsp_imm32(&a->out->e, (uint32_t)strtoll(toks[2], NULL, 0)); return 0; }
	if (!strcmp(toks[0], "xor") && n == 3)
	{
		/* Cas 1: xor [mem], reg8 (nouveau cas) */
		if (toks[1][0] == '[' && (mt = pmem(toks[1], &base, &idx, lbl, &d8)) == 1 &&
			toks[2][0] != '[' && preg(toks[2], &r2, &s2) && s2 == 8)
		{
			emit_xor_mem_sib_r8(&a->out->e, base, idx, r2);
			return 0;
		}

		/* Cas 2: xor reg, reg */
		if (toks[1][0] != '[' && toks[2][0] != '[' &&
			preg(toks[1], &r1, &s1) && preg(toks[2], &r2, &s2))
		{
			if (s1 == 8 && s2 == 8) { emit_xor_r8_r8(&a->out->e, r1, r2); return 0; }
			if (s1 == 32 && s2 == 32) { emit_xor_r32_r32(&a->out->e, r1, r2); return 0; }
			if (s1 == 64 && s2 == 64) { emit_xor_r64_r64(&a->out->e, r1, r2); return 0; }
		}

		/* Cas 3: xor [mem], reg */
		if (toks[1][0] == '[' && (mt = pmem(toks[1], &base, &idx, lbl, &d8)) == 1 &&
			preg(toks[2], &r2, &s2))
		{
			if (s2 == 8) { emit_xor_mem_sib_r8(&a->out->e, base, idx, r2); return 0; }
			if (s2 == 32) { emit_xor_mem_sib_r32(&a->out->e, base, idx, r2); return 0; }
			if (s2 == 64) { emit_xor_mem_sib_r64(&a->out->e, base, idx, r2); return 0; }
		}

		/* Cas 4: xor reg, [mem] */
		if (toks[1][0] != '[' && toks[2][0] == '[' &&
			preg(toks[1], &r1, &s1) && s1 == 8)
		{
			mt = pmem(toks[2], &base, &idx, lbl, &d8);
			if (mt == 1) { emit_xor_r8_mem_sib(&a->out->e, r1, base, idx); return 0; }
		}
	}

	if (!strcmp(toks[0], "or") && n == 3)
	{
		if (preg(toks[1], &r1, &s1) && s1 == 32)
		{
			val = sym(a, toks[2]);
			if (val < 0) val = strtoll(toks[2], NULL, 0);
			emit_or_r32_imm32(&a->out->e, r1, (uint32_t)val);
			return 0;
		}
		if (preg(toks[1], &r1, &s1) && s1 == 8 && preg(toks[2], &r2, &s2) && s2 == 8)
			{ emit_or_r8_r8(&a->out->e, r1, r2); return 0; }
		if (toks[1][0] == '[' && (mt = pmem(toks[1], &base, &idx, lbl, &d8)) == 1
			&& preg(toks[2], &r2, &s2) && s2 == 8)
		{
			if (base == REG_RBP)
				emit_or_mem_sib_disp8_r8(&a->out->e, base, idx, r2, 0);
			else
				emit_or_mem_sib_r8(&a->out->e, base, idx, r2);
			return 0;
		}
	}
	if (!strcmp(toks[0], "shl") && n == 3
		&& preg(toks[1], &r1, &s1) && s1 == 8
		&& !strcmp(toks[2], "cl"))
	{
		emit_shl_r8_cl(&a->out->e, r1);
		return 0;
	}
	if (!strcmp(toks[0], "shr") && n == 3 && preg(toks[1], &r1, &s1))
	{
		val = sym(a, toks[2]);
		if (val < 0) val = strtoll(toks[2], NULL, 0);
		if (s1 == 8)
		{
			emit_shr_r8_imm8(&a->out->e, s1, (uint8_t)val);
			return 0;
		}
		if (s1 == 32)
		{
			emit_shr_r32_imm8(&a->out->e, s1, (uint8_t)val);
			return 0;
		}
		if (s1 == 64)
		{
			emit_shr_r64_imm8(&a->out->e, s1, (uint8_t)val);
			return 0;
		}
		return 1;
	}
	if (!strcmp(toks[0], "sar") && n == 3)
	{
		if (toks[1][0] != '[' && toks[2][0] != '[')
		{
			t_reg r1;
			int size;
			if (preg(toks[1], &r1, &size) && size == 32) {
				char *end;
				long imm = strtoll(toks[2], &end, 0);
				if (*end == '\0' && imm >= 0 && imm <= 255) {
					emit_sar_r32_imm8(&a->out->e, r1, (uint8_t)imm);
					return 0;
				}
			}
		}
		else if (toks[1][0] == '[' && toks[2][0] != '[')
		{
			t_reg base = 0, idx = 0;
			int8_t disp = 0;
			char *lbl = NULL;
			int mt = 0;

			// Vérification que toks[1] n'est pas NULL
			if (toks[1] == NULL || strlen(toks[1]) < 3) {
				return -1;  // Format invalide
			}

			mt = pmem(toks[1], &base, &idx, lbl, &disp);
			if (mt != 1) {
				return -1;  // Échec de pmem
			}

			t_reg r2;
			int size = 0;
			if (!preg(toks[2], &r2, &size) || size != 8) {
				return -1;  // Registre invalide ou taille incorrecte
			}

			char *end = NULL;
			long imm = strtoll(toks[2], &end, 0);
			if (end == toks[2] || *end != '\0' || imm < 0 || imm > 255) {
				return -1;  // Immédiat invalide
			}

			emit_sar_mem_sib_imm8(&a->out->e, base, idx, (uint8_t)imm);
			return 0;
		}
		else if (toks[1][0] == '[' && toks[2][0] != '[' &&
				(mt = pmem(toks[1], &base, &idx, lbl, &d8)) == 1 &&
				preg(toks[2], &r2, &s2) && s2 == 8)
		{
			emit_sar_mem_sib_imm8_disp(&a->out->e, base, idx, d8, (uint8_t)strtoll(toks[2], NULL, 0));
			return 0;
		}
		else if (toks[1][0] != '[' && toks[2][0] != '[' &&
				preg(toks[1], &r1, &s1) && s1 == 32 &&
				preg(toks[2], &r2, &s2) && s2 == 8)
		{
			emit_sar_r32_r32(&a->out->e, r1, r2);
			return 0;
		}
		else if (toks[1][0] == '[' && toks[2][0] != '['
			&& (mt = pmem(toks[1], &base, &idx, lbl, &d8)) == 1
			&& preg(toks[2], &r2, &s2) && s2 == 8)
		{
			if (r2 != REG_RCX) {
				fprintf(stderr, "asm: sar [mem], r8 : seul cl est valide\n");
				return -1;
			}
			emit_sar_mem_sib_cl(&a->out->e, base, idx);
			return 0;
		}

		// Aucun cas valide trouvé → retourne -1 (échec)
		return -1;
	}
	if (!strcmp(toks[0], "and") && n == 3 && preg(toks[1], &r1, &s1))
	{
		if (s1 == 8)
		{
			val = sym(a, toks[2]);
			if (val < 0) val = strtoll(toks[2], NULL, 0);
			emit_and_r8_imm8(&a->out->e, r1, (uint8_t)val);
		}
		else if (s1 == 32)
		{
			val = sym(a, toks[2]);
			if (val < 0) val = strtoll(toks[2], NULL, 0);
			emit_and_r32_imm32(&a->out->e, r1, (uint32_t)val);
		}
		return 0;
	}
	if (!strcmp(toks[0], "add") && n == 3 && preg(toks[1], &r1, &s1) && r1 == REG_RSP)
		{ emit_add_rsp_imm32(&a->out->e, (uint32_t)strtoll(toks[2], NULL, 0)); return 0; }
	if (!strcmp(toks[0], "add") && n == 3)
	{
		if (toks[1][0] != '[' && toks[2][0] != '[' && preg(toks[1], &r1, &s1) && s1 == 8 && preg(toks[2], &r2, &s2) && s2 == 8)
			return emit_add_r8_r8(&a->out->e, r1, r2);
		if (toks[1][0] == '[' && (mt = pmem(toks[1], &base, &idx, lbl, &d8)) == 1 && preg(toks[2], &r2, &s2) && s2 == 8)
        		return emit_add_r8_mem_r8(&a->out->e, base, idx, r2);
		if (toks[2][0] == '[' && preg(toks[1], &r1, &s1) && s1 == 8 && (mt = pmem(toks[2], &base, &idx, lbl, &d8)) == 1)
			return emit_add_r8_mem_sib8(&a->out->e, r1, base, idx);
		if (toks[2][0] != '[' && preg(toks[1], &r1, &s1))
		{
			if (s1 == 8)
			{
				val = sym(a, toks[2]);
				if (val < 0) val = strtoll(toks[2], NULL, 0);
				if (val >= -128 && val <= 127)
            		return emit_add_r8_imm8(&a->out->e, r1, (uint8_t)val);
			}
			else if (s1 == 32)
			{
				val = sym(a, toks[2]);
				if (val < 0) val = strtoll(toks[2], NULL, 0);
				return emit_add_r32_imm32(&a->out->e, r1, (uint32_t)val);
			}
			else if (s1 == 64)
			{
				val = sym(a, toks[2]);
				if (val < 0) val = strtoll(toks[2], NULL, 0);
				return emit_add_r64_imm8(&a->out->e, r1, (int64_t)val);
			}        
		}
	}
	if (!strcmp(toks[0], "mov") && n == 3)
	{
		/* Cas 1: mov [mem], reg */
		if (toks[1][0] == '[' && toks[2][0] != '[')
		{
			mt = pmem(toks[1], &base, &idx, lbl, &d8);
			if (mt == 1 && preg(toks[2], &r2, &s2))
			{
				if (s2 == 8) { emit_mov_mem_sib_r8(&a->out->e, base, idx, r2); return 0; }
				if (s2 == 32) { emit_mov_mem_sib_r32(&a->out->e, base, idx, r2); return 0; }
				if (s2 == 64) { emit_mov_mem_sib_r64(&a->out->e, base, idx, r2); return 0; }
			}
			return 1;
		}
		if (toks[1][0] != '[' && toks[2][0] == '[')
		{
			if (preg(toks[1], &r1, &s1)) // Vérifie si "bl" est un registre 8-bit
			{
				mt = pmem(toks[2], &base, &idx, lbl, &d8);
				if (mt == 0) // No SIB needed
				{
					if (s1 == 8)
					{
						emit_mov_r8_mem_reg(&a->out->e, r1, base); // mov r8, [base]
					}
					else if (s1 == 32)
					{
						emit_mov_r32_mem_reg(&a->out->e, r1, base); // mov r32, [base]
					}
					else if (s1 == 64)
					{
						emit_mov_r64_mem_reg(&a->out->e, r1, base); // mov r64, [base]
					}
					return 0;
				}
				else if (mt == 1) // SIB needed
				{
					if (s1 == 8)
					{
						emit_mov_r8_mem_sib_disp(&a->out->e, r1, base, idx, d8); // mov r8, [base+idx+d8]
					}
					else if (s1 == 32)
					{
						emit_mov_r32_mem_sib_disp(&a->out->e, r1, base, idx, d8); // mov r32, [base+idx+d8]
					}
					else if (s1 == 64)
					{
						emit_mov_r64_mem_sib_disp(&a->out->e, r1, base, idx, d8); // mov r64, [base+idx+d8]
					}
					return 0;
				}
			}
			return 1;
		}

		if (toks[1][0] != '[' && toks[2][0] != '[' && preg(toks[1], &r1, &s1))
		{
			if (s1 == 8 && preg(toks[2], &r2, &s2) && s2 == 8)
				{ emit_mov_r8_r8(&a->out->e, r1, r2); return 0; }
			if (s1 == 8) {
				val = sym(a, toks[2]);
				if (val < 0) val = strtoll(toks[2], NULL, 0);
				emit_mov_r8_imm8(&a->out->e, r1, (uint8_t)val);
				return 0;
			}
			if (s1 == 64 && preg(toks[2], &r2, &s2) && s2 == 64)
				{ emit_mov_r64_r64(&a->out->e, r1, r2); return 0; }
			if (s1 == 32 && preg(toks[2], &r2, &s2) && s2 == 32)
				{ emit_mov_r32_r32(&a->out->e, r1, r2); return 0; }
			if (s1 == 32) {
				val = sym(a, toks[2]);
				if (val < 0) val = strtoll(toks[2], NULL, 0);
				emit_mov_r32_imm32(&a->out->e, r1, (uint32_t)val); return 0;
			}
			if (s1 == 64) {
				val = sym(a, toks[2]);
				if (val < 0) val = strtoll(toks[2], NULL, 0);
				emit_mov_r64_imm64(&a->out->e, r1, (uint64_t)val); return 0;
			}
		}
	}
	if (!strcmp(toks[0], "lea") && n == 3 && preg(toks[1], &r1, &s1) && s1 == 64)
	{
		mt = pmem(toks[2], &base, &idx, lbl, &d8);
		if (mt == 2) { lea_label(a, r1, lbl); return 0; }
	}
	if (!strcmp(toks[0], "movzx") && n == 3 && preg(toks[1], &r1, &s1) && s1 == 32)
	{
		int8_t  d8 = 0;
		if (toks[2][0] != '[' && preg(toks[2], &r2, &s2) && s2 == 8)
			{ emit_movzx_r32_r8(&a->out->e, r1, r2); return 0; }
		if (toks[2][0] == '[')
		{ // gamma
			mt = pmem(toks[2], &base, &idx, lbl, &d8);
			if (mt == 1) { emit_movzx_r32_mem_sib8(&a->out->e, r1, base, idx); return 0; }
			if (mt == 3) { emit_movzx_r32_mem_reg(&a->out->e, r1, base);        return 0; }
			if (mt == 4) { emit_movzx_r32_mem_disp8(&a->out->e, r1, base, d8); return 0; }
		}
	}
	if (!strcmp(toks[0], "xchg") && n == 3 && toks[1][0] == '[')
	{
		mt = pmem(toks[1], &base, &idx, lbl, &d8);
		if (mt == 1 && preg(toks[2], &r2, &s2) && s2 == 8)
			{ emit_xchg_mem_sib_r8(&a->out->e, base, idx, r2); return 0; }
	}
	if (!strcmp(toks[0], "test") && n == 3 && preg(toks[1], &r1, &s1) && preg(toks[2], &r2, &s2))
	{
		if (s1 == 8)
		{
			emit_test_r8_r8(&a->out->e, s1, s2);
			return 0;
		}
		if (s1 == 32)
		{
			emit_test_r32_r32(&a->out->e, s1, s2);
			return 0;
		}
		if (s1 == 64)
		{
			emit_test_r64_r64(&a->out->e, s1, s2);
			return 0;
		}
		return 1;
	}
	if (!strcmp(toks[0], "cmp") && n == 3 && preg(toks[1], &r1, &s1))
	{
		/* cmp r64, r64 : 48 39 /r */
		if (s1 == 64 && preg(toks[2], &r2, &s2) && s2 == 64)
		{
			emit_cmp_r64_r64(&a->out->e, r1, r2);
			return 0;
		}
		/* cmp r32, r32 : 39 /r */
		if (s1 == 32 && preg(toks[2], &r2, &s2) && s2 == 32)
		{
			uint8_t bytes[2] = {0x39, (3 << 6) | (r2 << 3) | r1};
			emit_raw(&a->out->e, bytes, 2);
			return 0;
		}
		/* cmp r32, imm (avec support des immédiats signés) */
		if (s1 == 32)
		{
			val = sym(a, toks[2]);
			if (val < 0) val = strtoll(toks[2], NULL, 0);  // Convertir la chaîne en entier signé

			printf("Comparing r32 with immediate value: %ld\n", val);
			// Vérifier si l'immédiat tient sur 8 bits signés (-128 à 127)
			if (val >= -128 && val <= 127)
				emit_cmp_r32_imm8(&a->out->e, r1, (int8_t)val);
			else
				emit_cmp_r32_imm32(&a->out->e, r1, (int32_t)val);
			return 0;
		}
		/* cmp r64, imm (nouveau cas) */
		if (s1 == 64)
		{
			val = sym(a, toks[2]);
			if (val < 0) val = strtoll(toks[2], NULL, 0);  // Convertir la chaîne en entier signé

			// Vérifier si l'immédiat tient sur 32 bits signés (-2^31 à 2^31-1)
			if (val >= -2147483648LL && val <= 2147483647LL)
				emit_cmp_r64_imm32(&a->out->e, r1, (int32_t)val);
			else
				emit_cmp_r64_imm64(&a->out->e, r1, val);  // Cas rare (immédiat 64 bits)
			return 0;
		}
	}
	if (!strcmp(toks[0], "jmp") && n == 2)
	{
		/* cas special : placeholder OEP, patch par elf_patch */
		if (!strcmp(toks[1], "@oep"))
		{
			emit_jmp_rel32(&a->out->e, &a->out->patch_jmp_oep);
			return (0);
		}
		/* label deja defini (saut arriere) */
		val = sym(a, toks[1]);
		if (val >= 0)
		{
			int64_t disp = val - (int64_t)(a->out->e.len + 2);
			if (disp >= -128 && disp <= 127)
			{
				uint8_t bytes[2] = {0xEB, (uint8_t)(int8_t)disp};
				return emit_raw(&a->out->e, bytes, 2);
			}
			else
			{
				int32_t d32 = (int32_t)(val - (int64_t)(a->out->e.len + 5));
				uint8_t bytes[5] = {0xE9, 0, 0, 0, 0};
				memcpy(bytes + 1, &d32, 4);
				return emit_raw(&a->out->e, bytes, 5);
			}
		}
		/* label pas encore defini (saut avant) : fixup rel32 */
		{
			size_t poff = a->out->e.len + 1;
			size_t pend = a->out->e.len + 5;
			size_t dummy;
			emit_jmp_rel32(&a->out->e, &dummy);
			addfixup(a, toks[1], poff, pend, 0);
		}
		return (0);
	}
	/* directives de donnees */
	if (!strcmp(toks[0], ".evasion_msg"))
		{ emit_raw(&a->out->e, (const uint8_t *)EVASION_MSG, EVASION_MSG_LEN); return 0; }
	if (!strcmp(toks[0], ".msg"))
		{ emit_raw(&a->out->e, (const uint8_t *)WOODY_MSG, WOODY_MSG_LEN); return 0; }
	if (!strcmp(toks[0], ".key"))
		{ emit_raw(&a->out->e, a->crypto->key, a->crypto->key_len); return 0; }

	if (!strcmp(toks[0], "_zero") && n == 2)
	{
		if (!preg(toks[1], &r1, &s1)) return -1;

		printf("register: %d, size: %d, lsb_value: %d\n", r1, s1, lsb_value);

		if (s1 == 8) {
			if (lsb_value) emit_and_r8_imm8(&a->out->e, r1, 0);   /* 0x24/0x80 ✓ */
			else           emit_xor_r32_r32(&a->out->e, r1, r1);   /* 0x31 ✓ LDE reconnaît */
		}
		else if (s1 == 32) {
			if (lsb_value)
				emit_and_r32_imm8(&a->out->e, r1, 0);
			else
				emit_xor_r32_r32(&a->out->e, r1, r1);  // XOR r32, r32
		}
		else if (s1 == 64) {
			if (lsb_value)
				emit_and_r64_imm8(&a->out->e, r1, 0);  // AND r64, 0
			else
				emit_xor_r64_r64(&a->out->e, r1, r1);  // XOR r64, r64
		}
		a->key_index++;
		return 0;
	}
	if (!strcmp(toks[0], "_set") && n == 3)
	{
		if (!preg(toks[1], &r1, &s1)) return -1;

		if (toks[2][0] == '[')                       /* source mémoire */
		{
			mt = pmem(toks[2], &base, &idx, lbl, &d8);
			if (lsb_value) {
				if (mt == 3) emit_mov_r32_mem_reg(&a->out->e, r1, base);
				if (mt == 4) emit_mov_r32_mem_disp8(&a->out->e, r1, base, d8);
				if (mt == 1) emit_mov_r32_mem_sib(&a->out->e, r1, base, idx);
			} else {
				if (mt == 3) emit_movzx_r32_mem_reg(&a->out->e, r1, base);
				if (mt == 4) emit_movzx_r32_mem_disp8(&a->out->e, r1, base, d8);
				if (mt == 1) emit_movzx_r32_mem_sib8(&a->out->e, r1, base, idx);
			}
			a->key_index++;
			return 0;
		}
		else if (preg(toks[2], &r2, &s2))            /* source registre */
		{
			/* r64 → r64 */
			if (s1 == 64 && s2 == 64)
			{
				if (lsb_value)
					emit_mov_r64_r64(&a->out->e, r1, r2);       /* 48 89 /r */
				else
					emit_lea_r64_reg0(&a->out->e, r1, r2);       /* 48 8D mod=01 disp8=0 */
				a->key_index++;
				return 0;
			}

			/* r8 imm */
			if (s1 == 8)
			{
				if (lsb_value)
					emit_mov_r8_imm8(&a->out->e, r1, (uint8_t)val);   /* B0+r ib */
				else
					emit_mov_r32_imm32(&a->out->e, r1, (uint32_t)val); /* B8+r id, zero-extend */
				a->key_index++;
				return 0;
			}
		}
		else                                          /* source immédiate */
		{
			val = sym(a, toks[2]);
			if (val < 0) val = strtoll(toks[2], NULL, 0);
			if (lsb_value) emit_mov_r32_imm32(&a->out->e, r1, (uint32_t)val);
			else           emit_lea_abs(&a->out->e, r1, (int32_t)val);
		}
		a->key_index++;
		return 0;
	}
	if (!strcmp(toks[0], "_inc") && n == 2)
	{
		if (!preg(toks[1], &r1, &s1))
			return (-1);
		if (lsb_value)           // variante 0 : INC
		{
			if (s1 == 8)       emit_inc_r8(&a->out->e, r1);
			else if (s1 == 32) emit_inc_r32(&a->out->e, r1);
			else               emit_inc_r64(&a->out->e, r1);
		}
		else {  /* lsb=0 */
			if (s1 == 8)
				emit_add_r8_imm8(&a->out->e, r1, 1);   /* 80 /0 01 ← LDE reconnaît */
			else if (s1 == 32 || s1 == 64)
				emit_add_r32_imm32_long(&a->out->e, r1, 1);
		}
		a->key_index++;
		return (0);
	}
	if (!strcmp(toks[0], "_dec") && n == 2)
	{
		if (!preg(toks[1], &r1, &s1))
			return (-1);
		if (lsb_value)           // variante 0 : DEC
		{
			if (s1 == 8)       emit_dec_r8(&a->out->e, r1);
			else if (s1 == 32) emit_dec_r32(&a->out->e, r1);
			else               emit_dec_r64(&a->out->e, r1);
		}
		else                               // variante 1 : SUB reg, 1
			emit_sub_r32_imm8(&a->out->e, r1, 1);
		a->key_index++;
		return (0);
	}
	fprintf(stderr, "asm: inconnu: '%s' (%d tokens)\n", toks[0], n);
	for (int i = 0; i < n; i++)
		fprintf(stderr, "  tok[%d] = '%s'\n", i, toks[i]);
	return -1;
}

/* ── entree publique ────────────────────────────────────────────── */
int asm_build(const char *src, t_crypto_ctx *crypto, t_asm_result *out)
{
    t_asm   a;
    char    toks[8][64];
    char    line[256];
    int     n, llen, tok0len;

    memset(&a, 0, sizeof(a));
    a.out    = out;
    a.crypto = crypto;

    const char *p = src;
    while (*p) {
        const char *start = p;
        while (*p && *p != '\n') p++;
        llen = (int)(p - start);
        if (*p == '\n') p++;
        if (llen <= 0 || llen > 255) continue;
        strncpy(line, start, (size_t)llen);
        line[llen] = '\0';
        memset(toks, 0, sizeof(toks));
        n = tokenize(line, toks, 8);
        if (n == 0) continue;
        tok0len = (int)strlen(toks[0]);
        if (tok0len > 1 && toks[0][tok0len - 1] == ':') {
            toks[0][tok0len - 1] = '\0';
            deflabel(&a, toks[0]);
            if (ainstr(&a, toks + 1, n - 1) < 0) return -1;
            continue;
        }
        if (ainstr(&a, toks, n) < 0) return -1;
    }
    /* resolution des fixups */
    for (int i = 0; i < a.nfixups; i++) {
        int64_t target = sym(&a, a.fixups[i].name);
        if (target < 0) { fprintf(stderr, "asm: non resolu '%s'\n", a.fixups[i].name); return -1; }
        if (a.fixups[i].is_rel8) {
            int8_t d = (int8_t)(target - (int64_t)a.fixups[i].end);
            a.out->e.buf[a.fixups[i].off] = (uint8_t)d;
        } else {
            int32_t d = (int32_t)(target - (int64_t)a.fixups[i].end);
            patch_disp32_buf(a.out->e.buf, a.fixups[i].off, d);
        }
    }
    return 0;
}