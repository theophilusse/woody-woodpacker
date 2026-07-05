import gdb

def read_meta():
    meta = {}
    with open("./woody_meta.txt") as f:
        for line in f:
            k, v = line.strip().split("=", 1)
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
    """autobreak <label> <hexbyte...> : cherche une signature d'octets fixe et pose un breakpoint dessus.
    Usage: autobreak ksa_start 48 81 ec 00 01 00 00"""
    def __init__(self):
        super(AutoBreak, self).__init__("autobreak", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        args = arg.split()
        if len(args) < 2:
            print("usage: autobreak <label> <hexbyte> [hexbyte...]")
            return
        label = args[0]
        sig = [int(x, 16) for x in args[1:]]
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
    """woodysetup : pose un breakpoint sur load_vaddr, lance le programme,
    neutralise le check anti-debug (ptrace), puis pose le watchpoint sur $ecx
    filtre a la zone scannee par le LDE."""

    def __init__(self):
        super(WoodySetup, self).__init__("woodysetup", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        try:
            meta = read_meta()
        except FileNotFoundError:
            print("woodysetup: /tmp/woody_meta.txt introuvable — lance d'abord une generation")
            return

        patch_jmp_oep = int(meta["patch_jmp_oep"])
        load_vaddr = int(meta["load_vaddr"])
        scan_end = load_vaddr + patch_jmp_oep + 5

        print(f"woodysetup: load_vaddr=0x{load_vaddr:x} scan_end=0x{scan_end:x} "
              f"(taille zone scannee = {scan_end - load_vaddr} octets)")

        gdb.execute("delete breakpoints")
        gdb.execute(f"break *0x{load_vaddr:x}")
        gdb.execute("run")

        print("woodysetup: dump des 60 premiers octets du buffer LDE :")
        output = gdb.execute(f"x/60xb 0x{load_vaddr:x}", to_string=True)
        print(output)

        gdb.execute(f"set $scan_start = 0x{load_vaddr:x}")
        gdb.execute(f"set $scan_end = 0x{scan_end:x}")

        # ── Neutralisation de l'anti-debug ──
        # Cherche l'instruction "syscall" du ptrace (juste avant le cmp eax,-1)
        # dans la zone scannee, en partant de load_vaddr.
        sig_ptrace_syscall = [0x0f, 0x05]  # opcode syscall, generique
        # on cherche plutot la sequence "cmp eax,-1" = 83 F8 FF (forme courte imm8)
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
        gdb.execute("watch $ecx")
        gdb.execute("""commands
silent
if $rsi >= $scan_start && $rsi < $scan_end
  printf "%d %ld\\n", $ecx, $rsi - $scan_start
end
continue
end""")
        print("woodysetup: watchpoint pose. Lance 'set logging file ...', "
              "'set logging on', puis 'continue'.")

AutoBreak()
WoodySetup()
