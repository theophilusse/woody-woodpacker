set disassembly-flavor intel
define si
	stepi
	i r
	x/8bx $rip
	x/15i $rip
end
define antidebug
	stepi
	stepi
	stepi
	stepi
	stepi
	stepi
	stepi
	stepi
	set $rax = 0x0
	stepi
	stepi
	stepi
	echo Ready to continue\n
end
break *0x401161
