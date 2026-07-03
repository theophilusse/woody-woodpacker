set disassembly-flavor intel
define si
	stepi
	i r
	x/8bx $rip
	x/15i $rip
end
define antidebug
	set $rax = 0x0
	continue
end
break *0x401161
break *0x40133e
command 2
echo AntiDebug\n
end
break *0x40139b
command 3
echo LDE begin\n
end
break *0x4013ab
command 4
i r
echo LDE Loop\n
end
