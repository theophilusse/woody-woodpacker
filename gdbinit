define si
	stepi
	x/18i $rip
end
break *0x401161
commands 1
	echo Entering STUB\n
end
break *0x401178
commands 2
	echo Key buffer zeroed\n
end
break *0x401180
commands 3
	echo Running LDE
end
