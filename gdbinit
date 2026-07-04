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
