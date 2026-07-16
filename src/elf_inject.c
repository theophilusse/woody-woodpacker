#include "woody.h"

int	elf_find_injection_point(t_elf_ctx *ctx)
{
	/* trouver le PT_LOAD exécutable contenant e_entry */
	Elf64_Half ph;

	ph = 0;
	while (ph < ctx->ehdr->e_phnum)
	{
		Elf64_Phdr *p;

		p = &ctx->phdrs[ph];
		if (p->p_type == PT_LOAD &&
			p->p_flags & PF_X &&
			ctx->ehdr->e_entry >= p->p_vaddr && ctx->ehdr->e_entry < p->p_vaddr + p->p_memsz)
		{
			ctx->target_phdr_idx = ph;
			return (0);
		}
		ph++;
	}
	return (1);
}

size_t padding_available(t_elf_ctx *ctx, Elf64_Phdr *p)
{
    size_t  end_of_segment;
    size_t  next_segment_offset;
    Elf64_Half i;

    end_of_segment = p->p_offset + p->p_filesz;
    next_segment_offset = ctx->size;   /* par defaut : fin du fichier */

    for (i = 0; i < ctx->ehdr->e_phnum; i++)
    {
        Elf64_Phdr *other = &ctx->phdrs[i];

        if (other == p || other->p_type != PT_LOAD)
            continue;
        if (other->p_offset > p->p_offset && (size_t)other->p_offset < next_segment_offset)
            next_segment_offset = other->p_offset;
    }

    if (next_segment_offset <= end_of_segment)
        return (0);
    return (next_segment_offset - end_of_segment);
}

static int elf_patch_new_segment(t_elf_ctx *ctx, t_stub *stub, t_opts *opts)
{
    Elf64_Phdr  *new_phdrs;
    Elf64_Phdr  *new_seg;
    Elf64_Phdr  saved_phdrs[64];   /* copie de securite AVANT tout realloc/ecriture */
    size_t      new_phdr_count;
    size_t      new_phdr_table_offset;
    size_t      new_seg_vaddr;
    size_t      new_seg_offset;
    uint8_t     *tmp;
    size_t      old_file_size;
    size_t      old_phnum;
    size_t      align;
    int32_t     disp;

    old_file_size = ctx->size;
    old_phnum = ctx->ehdr->e_phnum;
    if (old_phnum >= 64)
    {
        fprintf(stderr, "elf_patch_new_segment: trop de program headers existants\n");
        return (-1);
    }

    /* ── Sauvegarde l'ancienne table PHDR AVANT tout realloc/ecriture,
    ** pour ne jamais dependre d'un pointeur qui pourrait devenir invalide
    ** ou d'une zone qui pourrait etre ecrasee plus tard ── */
    memcpy(saved_phdrs, ctx->phdrs, old_phnum * sizeof(Elf64_Phdr));

    new_phdr_count = old_phnum + 1;

    /* Nouvelle adresse virtuelle : apres le dernier segment existant, alignee page */
    new_seg_vaddr = 0;
    for (size_t i = 0; i < old_phnum; i++)
    {
        size_t end = saved_phdrs[i].p_vaddr + saved_phdrs[i].p_memsz;
        if (end > new_seg_vaddr)
            new_seg_vaddr = end;
    }
    align = 0x1000;
    new_seg_vaddr = (new_seg_vaddr + align - 1) & ~(align - 1);

    /* Position dans le fichier : a la fin, avec alignement fichier/memoire coherent */
    new_seg_offset = old_file_size;
    {
        size_t rem_vaddr = new_seg_vaddr % align;
        size_t rem_offset = new_seg_offset % align;
        if (rem_offset != rem_vaddr)
            new_seg_offset += (rem_vaddr + align - rem_offset) % align;
    }

    new_phdr_table_offset = new_seg_offset + stub->len;
    size_t total_new_size = new_phdr_table_offset + new_phdr_count * sizeof(Elf64_Phdr);

    /* ── Realloc : si ca echoue, ctx->raw original reste intact ── */
    tmp = realloc(ctx->raw, total_new_size);
    if (!tmp)
        return (-1);
    ctx->raw = tmp;
    ctx->ehdr = (Elf64_Ehdr *)ctx->raw;

    /* Zero le padding entre l'ancienne fin de fichier et new_seg_offset */
    memset(ctx->raw + old_file_size, 0, new_seg_offset - old_file_size);

    /* ── Patch patch_jmp_oep AVANT d'ecrire le stub, sur stub->bytes en memoire ── */
    stub->load_vaddr = new_seg_vaddr;
    stub->original_oep = ctx->ehdr->e_entry;   /* capture avant modification */

    if (stub->patch_jmp_oep != (size_t)-1)
    {
        disp = (int32_t)(stub->original_oep - (stub->load_vaddr + stub->patch_jmp_oep + 4));
        if (opts->verbose)
            fprintf(stderr, "elf_patch_new_segment: original_oep=0x%lx load_vaddr=0x%lx "
                    "patch_jmp_oep=%zu disp=%d\n",
                    stub->original_oep, stub->load_vaddr, stub->patch_jmp_oep, disp);
        patch_disp32_buf(stub->bytes, stub->patch_jmp_oep, disp);
    }
    else if (opts->verbose)
        fprintf(stderr, "elf_patch_new_segment: pas de jmp @oep dans ce stub, patch ignore\n");

    /* Ecrit le stub (deja patche) a sa position finale */
    memcpy(ctx->raw + new_seg_offset, stub->bytes, stub->len);

    /* Construit la nouvelle table PHDR : ancienne (sauvegardee) + nouvelle entree */
    new_phdrs = (Elf64_Phdr *)(ctx->raw + new_phdr_table_offset);
    memcpy(new_phdrs, saved_phdrs, old_phnum * sizeof(Elf64_Phdr));

	/* met a jour l'entree PT_PHDR existante pour pointer
    ** vers la nouvelle position de la table, dans le nouveau segment */
    for (size_t i = 0; i < old_phnum; i++)
    {
        if (new_phdrs[i].p_type == PT_PHDR)
        {
            new_phdrs[i].p_offset = new_phdr_table_offset;
            new_phdrs[i].p_vaddr  = new_seg_vaddr + stub->len;
            new_phdrs[i].p_paddr  = new_phdrs[i].p_vaddr;
            new_phdrs[i].p_filesz = new_phdr_count * sizeof(Elf64_Phdr);
            new_phdrs[i].p_memsz  = new_phdrs[i].p_filesz;
            break;
        }
    }

    new_seg = &new_phdrs[old_phnum];
    memset(new_seg, 0, sizeof(*new_seg));
    new_seg->p_type   = PT_LOAD;
    new_seg->p_flags  = PF_R | PF_X;
    new_seg->p_offset = new_seg_offset;
    new_seg->p_vaddr  = new_seg_vaddr;
    new_seg->p_paddr  = new_seg_vaddr;
    new_seg->p_filesz = stub->len + new_phdr_count * sizeof(Elf64_Phdr);
    new_seg->p_memsz  = new_seg->p_filesz;
    new_seg->p_align  = align;

    ctx->ehdr->e_phoff = new_phdr_table_offset;
    ctx->ehdr->e_phnum = (Elf64_Half)new_phdr_count;
    ctx->ehdr->e_entry = new_seg_vaddr;

    ctx->phdrs = new_phdrs;
    ctx->size = total_new_size;

    if (opts->verbose)
        fprintf(stderr, "elf_patch_new_segment: nouveau segment a vaddr=0x%zx offset=0x%zx "
                "taille=%zu, e_phoff deplace a 0x%zx (%zu entrees)\n",
                new_seg_vaddr, new_seg_offset, stub->len, new_phdr_table_offset, new_phdr_count);

    return (0);
}

int elf_patch(t_elf_ctx *ctx, t_stub *stub, t_crypto_ctx *crypto, t_opts *opts)
{
    Elf64_Phdr  *p;
    size_t      stub_offset;
    uint8_t     *tmp;
    uint64_t    new_align;

    (void)crypto;
    p = &ctx->phdrs[ctx->target_phdr_idx];

    new_align = 0x4000;
    if (p->p_align < new_align)
    {
        if ((p->p_vaddr % new_align) == (p->p_offset % new_align))
            p->p_align = new_align;
    }

    if (stub->len > padding_available(ctx, p))
    {
        if (opts->verbose)
            fprintf(stderr, "elf_patch: padding insuffisant (%zu dispo, %zu requis), "
                    "fallback vers nouveau segment PT_LOAD\n",
                    padding_available(ctx, p), stub->len);
        return (elf_patch_new_segment(ctx, stub, opts));
    }

    /* ── chemin existant, injection dans le padding, inchange ── */
    stub_offset = p->p_offset + p->p_filesz;
    tmp = realloc(ctx->raw, ctx->size + stub->len);
    if (!tmp)
        return (-1);
    ctx->raw = tmp;
    ctx->ehdr = (Elf64_Ehdr *)ctx->raw;
    ctx->phdrs = (Elf64_Phdr *)(ctx->raw + ctx->ehdr->e_phoff);
    p = &ctx->phdrs[ctx->target_phdr_idx];

    memmove(ctx->raw + stub_offset, stub->bytes, stub->len);

    stub->load_vaddr = p->p_vaddr + p->p_filesz;
    stub->original_oep = ctx->ehdr->e_entry;

    if (stub->patch_jmp_oep != (size_t)-1)
    {
        int32_t disp = (int32_t)(stub->original_oep - (stub->load_vaddr + stub->patch_jmp_oep + 4));
        if (opts->verbose)
            fprintf(stderr, "original_oep=0x%lx load_vaddr=0x%lx patch_jmp_oep=%zu disp=%d\n",
                    stub->original_oep, stub->load_vaddr, stub->patch_jmp_oep, disp);
        patch_disp32_buf(stub->bytes, stub->patch_jmp_oep, disp);
        memcpy(ctx->raw + stub_offset, stub->bytes, stub->len);
    }
    else if (opts->verbose)
        fprintf(stderr, "elf_patch: pas de jmp @oep dans ce stub, patch ignore\n");

    p->p_filesz += stub->len;
    p->p_memsz  += stub->len;
    ctx->ehdr->e_entry = stub->load_vaddr;
    ctx->size += stub->len;

    return (0);
}

int	elf_write(t_elf_ctx *ctx, const char *out_path)
{
	(void)ctx;
	(void)out_path;
	/* TODO: écrire ctx->raw (mis à jour) dans out_path, chmod 0755 */
		/* TODO: lire le fichier entier en mémoire (malloc + read),
	 * remplir ctx->raw / ctx->size, puis faire pointer
	 * ctx->ehdr et ctx->phdrs sur les bons offsets dans ctx->raw */
	FILE *f;

	if (!out_path)
		return (1);
	f = fopen(out_path, "wb");
	if (f == NULL)
	{
		printf("Error writing %s\n", out_path);
		return (1);
	}
	if (fwrite(ctx->raw, 1, ctx->size, f) != ctx->size)
	{
		printf("Error writing %s\n", out_path);
		fclose(f);
		return (1);
	}
	fclose(f);
	if (chmod(out_path, 0755) != 0)
	{
		fprintf(stderr, "Error setting permissions on %s\n", out_path);
		return (1);
	}
	return (0);
}
