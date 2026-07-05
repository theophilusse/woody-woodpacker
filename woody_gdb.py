import gdb

def read_meta(path="./woody_meta.txt"):
    meta = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            meta[k] = v
    return meta

def find_signature(start, end, sig):
    inferior = gdb.selected_inferior()
    mem = inferior.read_memory(start, end - start).tobytes()
    idx = mem.find(bytes(sig))
    if idx == -1:
        return None
    return start + idx


class AutoBreak(gdb.Command):
    """autobreak <label> <hexbyte...> : cherche une signature d'octets fixe
    (instruction litterale, non-polymorphe) autour de $pc et pose un breakpoint dessus.
    Usage: autobreak ksa_start 48 81 ec 00 01 00 00"""

    def __init__(self):
        super(AutoBreak, self).__init__("autobreak", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        args = arg.split()
        if len(args) < 2:
            print("usage: autobreak <label> <hexbyte> [hexbyte...]")
            return
        label = args[0]
        try:
            sig = [int(x, 16) for x in args[1:]]
        except ValueError:
            print("autobreak: octets invalides, attendu en hexadecimal (ex: 48 81 ec)")
            return
        pc = int(gdb.parse_and_eval("$pc"))
        start = pc & ~0xFFF
        end = start + 0x10000
        addr = find_signature(start, end, sig)
        if addr is None:
            print(f"autobreak: signature '{label}' introuvable dans [0x{start:x},0x{end:x})")
            return
        gdb.execute(f"break *0x{addr:x}")
        print(f"autobreak: '{label}' -> 0x{addr:x}")


class WoodySetup(gdb.Command):
    """woodysetup [nbytes] : pose un breakpoint sur load_vaddr (lu depuis
    ./woody_meta.txt), lance le programme, neutralise l'anti-debug (ptrace),
    puis pose un watchpoint sur $ecx filtre a la zone scannee par le LDE.

    Avec un argument numerique, pose plutot un watchpoint sur $rsi (pas $ecx),
    loguant $rsi et $rip a chaque changement, limite aux <nbytes> premiers
    octets de la zone scannee — utile pour localiser precisement un blocage
    tres tot dans le scan.
    Usage: woodysetup          -> watch $ecx (mode normal)
           woodysetup 60       -> watch $rsi, limite aux 60 premiers octets
    """

    def __init__(self):
        super(WoodySetup, self).__init__("woodysetup", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        try:
            meta = read_meta()
        except FileNotFoundError:
            print("woodysetup: ./woody_meta.txt introuvable — lance d'abord une generation")
            return

        patch_jmp_oep = int(meta["patch_jmp_oep"])
        load_vaddr = int(meta["load_vaddr"])
        scan_end = load_vaddr + patch_jmp_oep + 5

        print(f"woodysetup: load_vaddr=0x{load_vaddr:x} scan_end=0x{scan_end:x} "
              f"(taille zone scannee = {scan_end - load_vaddr} octets)")

        gdb.execute("delete breakpoints")
        gdb.execute(f"break *0x{load_vaddr:x}")
        gdb.execute("run")

        gdb.execute(f"set $scan_start = 0x{load_vaddr:x}")
        gdb.execute(f"set $scan_end = 0x{scan_end:x}")

        # ── Neutralisation de l'anti-debug (cmp eax,-1 apres le syscall ptrace) ──
        sig_cmp_eax_neg1 = [0x83, 0xf8, 0xff]
        addr = find_signature(load_vaddr, scan_end, sig_cmp_eax_neg1)
        if addr is None:
            print("woodysetup: signature anti-debug (cmp eax,-1) introuvable, "
                  "anti-debug NON neutralise — le programme risque de se terminer immediatement")
        else:
            gdb.execute(f"break *0x{addr:x}")
            gdb.execute("continue")
            gdb.execute("set $eax = 0")
            gdb.execute(f"clear *0x{addr:x}")
            print(f"woodysetup: anti-debug neutralise a 0x{addr:x} (eax force a 0)")

        gdb.execute("delete breakpoints")

        args = arg.split()
        if args:
            # ── Mode fin : watch $rsi + $rip, limite aux N premiers octets ──
            try:
                nbytes = int(args[0])
            except ValueError:
                print("woodysetup: argument invalide, attendu un nombre d'octets")
                return
            gdb.execute(f"set $scan_limit = $scan_start + {nbytes}")
            gdb.execute("watch $rsi")
            gdb.execute(f"""commands
silent
if $rsi >= $scan_start && $rsi < $scan_limit
  printf "rsi=%ld rip=0x%lx\\n", $rsi - $scan_start, $rip
end
continue
end""")
            print(f"woodysetup: watchpoint fin pose sur $rsi, limite aux {nbytes} "
                  f"premiers octets de la zone scannee. Lance 'set logging file ...', "
                  f"'set logging on', puis 'continue'.")
        else:
            # ── Mode normal : watch $ecx sur toute la zone scannee ──
            gdb.execute("watch $ecx")
            gdb.execute("""commands
silent
if $rsi >= $scan_start && $rsi < $scan_end
  printf "%d %ld\\n", $ecx, $rsi - $scan_start
end
continue
end""")
            print("woodysetup: watchpoint pose sur $ecx. Lance 'set logging file ...', "
                  "'set logging on', puis 'continue'.")


class WoodyCompare(gdb.Command):
    """woodycompare <sim_trace> <gdb_trace> : compare deux fichiers de trace,
    en tolerant un ecart de 0 ou 1 sur la position (convention REX pre/post-strip),
    et ne signale que les VRAIES divergences (ecart >= 2 ou valeur differente)."""

    def __init__(self):
        super(WoodyCompare, self).__init__("woodycompare", gdb.COMMAND_USER)

    def _dedupe(self, pairs):
        deduped = []
        i = 0
        while i < len(pairs):
            val, pos = pairs[i]
            j = i
            while j + 1 < len(pairs) and pairs[j + 1][1] == pos:
                j += 1
            deduped.append((pairs[j][0], pos))
            i = j + 1
        return deduped

    def invoke(self, arg, from_tty):
        args = arg.split()
        if len(args) != 2:
            print("usage: woodycompare <sim_trace_file> <gdb_trace_file>")
            return
        sim_path, gdb_path = args

        try:
            sim_pairs = []
            with open(sim_path) as f:
                for l in f:
                    p = l.split()
                    if len(p) == 2:
                        sim_pairs.append((int(p[0]) + 1, int(p[1])))

            gdb_pairs = []
            with open(gdb_path) as f:
                for l in f:
                    p = l.split()
                    if len(p) == 2 and p[0].lstrip('-').isdigit() and p[1].isdigit():
                        gdb_pairs.append((int(p[0]), int(p[1])))
        except FileNotFoundError as e:
            print(f"woodycompare: fichier introuvable ({e})")
            return

        gdb_deduped = self._dedupe(gdb_pairs)
        print(f"sim: {len(sim_pairs)} entrees   reel (dedup): {len(gdb_deduped)} entrees")

        n = min(len(sim_pairs), len(gdb_deduped))
        first_diff = None
        for k in range(n):
            sv, sp = sim_pairs[k]
            rv, rp = gdb_deduped[k]
            if sv != rv or rp - sp not in (0, 1):   # tolere l'ecart REX de 0 ou 1
                first_diff = k
                break

        if first_diff is None:
            if len(sim_pairs) == len(gdb_deduped):
                print(f"alignement coherent sur les {n} lignes (ecart REX 0/1 tolere) — aucune vraie divergence")
            else:
                print(f"coherent sur les {n} premieres lignes, longueur differente "
                      f"(sim={len(sim_pairs)}, reel={len(gdb_deduped)})")
            return

        print(f"VRAIE DIVERGENCE a l'index {first_diff} (ecart > 1 ou valeur differente)")
        lo = max(0, first_diff - 5)
        hi = min(n, first_diff + 15)
        print(f"{'idx':>4} {'sim':>14} {'reel':>14} {'ecart':>6}")
        for k in range(lo, hi):
            sv, sp = sim_pairs[k]
            rv, rp = gdb_deduped[k]
            mark = " <<<" if k == first_diff else ""
            print(f"{k:>4} {str(sim_pairs[k]):>14} {str(gdb_deduped[k]):>14} {rp-sp:>6}{mark}")


AutoBreak()
WoodySetup()
WoodyCompare()