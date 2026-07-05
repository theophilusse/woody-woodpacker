import gdb

def read_meta():
    meta = {}
    with open("/tmp/woody_meta.txt") as f:
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
    """woodysetup : configure scan_start/scan_end et pose le watchpoint sur $ecx,
    en filtrant uniquement les positions a l'interieur de la zone scannee par le LDE."""
    def __init__(self):
        super(WoodySetup, self).__init__("woodysetup", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        meta = read_meta()
        patch_jmp_oep = int(meta["patch_jmp_oep"])
        gdb.execute("starti")
        load_vaddr = int(gdb.parse_and_eval("$pc"))
        scan_end = load_vaddr + patch_jmp_oep + 5
        print(f"load_vaddr=0x{load_vaddr:x} scan_end=0x{scan_end:x}")
        gdb.execute(f"set $scan_start = 0x{load_vaddr:x}")
        gdb.execute(f"set $scan_end = 0x{scan_end:x}")
        gdb.execute("delete")
        gdb.execute("watch $ecx")
        gdb.execute("""commands
silent
if $rsi >= $scan_start && $rsi < $scan_end
  printf "%d %ld\\n", $ecx, $rsi - $scan_start
end
continue
end""")

AutoBreak()
WoodySetup()
