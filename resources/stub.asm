
stub:	file format elf64-x86-64

Disassembly of section .text:

0000000000000000 <push>:
       0: 55                           	push	rbp
       1: 48 89 e5                     	mov	rbp, rsp
       4: 89 7d fc                     	mov	dword ptr [rbp - 0x4], edi
       7: 8b 45 fc                     	mov	eax, dword ptr [rbp - 0x4]
       a: 5d                           	pop	rbp
       b: c3                           	ret
       c: 0f 1f 40 00                  	nop	dword ptr [rax]

0000000000000010 <main>:
      10: 55                           	push	rbp
      11: 48 89 e5                     	mov	rbp, rsp
      14: 48 83 ec 10                  	sub	rsp, 0x10
      18: c7 45 fc 00 00 00 00         	mov	dword ptr [rbp - 0x4], 0x0
      1f: 48 c7 45 f0 00 00 00 00      	mov	qword ptr [rbp - 0x10], 0x0
      27: b8 e8 03 00 00               	mov	eax, 0x3e8
      2c: 48 39 45 f0                  	cmp	qword ptr [rbp - 0x10], rax
      30: 0f 83 e0 02 00 00            	jae	0x316 <main+0x306>
      36: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      3a: 0f b6 00                     	movzx	eax, byte ptr [rax]
      3d: 83 f8 24                     	cmp	eax, 0x24
      40: 75 25                        	jne	0x67 <main+0x57>
      42: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      46: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
      4a: 83 f8 00                     	cmp	eax, 0x0
      4d: 75 0a                        	jne	0x59 <main+0x49>
      4f: bf 01 00 00 00               	mov	edi, 0x1
      54: e8 00 00 00 00               	call	0x59 <main+0x49>
      59: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      5d: 48 83 c0 02                  	add	rax, 0x2
      61: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
      65: eb c0                        	jmp	0x27 <main+0x17>
      67: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      6b: 0f b6 00                     	movzx	eax, byte ptr [rax]
      6e: 3d 80 00 00 00               	cmp	eax, 0x80
      73: 75 25                        	jne	0x9a <main+0x8a>
      75: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      79: 0f b6 40 02                  	movzx	eax, byte ptr [rax + 0x2]
      7d: 83 f8 00                     	cmp	eax, 0x0
      80: 75 0a                        	jne	0x8c <main+0x7c>
      82: bf 01 00 00 00               	mov	edi, 0x1
      87: e8 00 00 00 00               	call	0x8c <main+0x7c>
      8c: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      90: 48 83 c0 03                  	add	rax, 0x3
      94: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
      98: eb 8d                        	jmp	0x27 <main+0x17>
      9a: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      9e: 0f b6 00                     	movzx	eax, byte ptr [rax]
      a1: 83 f8 31                     	cmp	eax, 0x31
      a4: 75 29                        	jne	0xcf <main+0xbf>
      a6: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      aa: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
      ae: 83 e0 18                     	and	eax, 0x18
      b1: c1 f8 03                     	sar	eax, 0x3
      b4: 48 8b 4d f0                  	mov	rcx, qword ptr [rbp - 0x10]
      b8: 0f b6 49 01                  	movzx	ecx, byte ptr [rcx + 0x1]
      bc: 83 e1 03                     	and	ecx, 0x3
      bf: 39 c8                        	cmp	eax, ecx
      c1: 75 07                        	jne	0xca <main+0xba>
      c3: 31 ff                        	xor	edi, edi
      c5: e8 00 00 00 00               	call	0xca <main+0xba>
      ca: e9 3e 02 00 00               	jmp	0x30d <main+0x2fd>
      cf: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      d3: 0f b6 00                     	movzx	eax, byte ptr [rax]
      d6: 3d b8 00 00 00               	cmp	eax, 0xb8
      db: 7c 29                        	jl	0x106 <main+0xf6>
      dd: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      e1: 0f b6 00                     	movzx	eax, byte ptr [rax]
      e4: 3d bf 00 00 00               	cmp	eax, 0xbf
      e9: 7f 1b                        	jg	0x106 <main+0xf6>
      eb: bf 01 00 00 00               	mov	edi, 0x1
      f0: e8 00 00 00 00               	call	0xf5 <main+0xe5>
      f5: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
      f9: 48 83 c0 05                  	add	rax, 0x5
      fd: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
     101: e9 21 ff ff ff               	jmp	0x27 <main+0x17>
     106: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     10a: 0f b6 00                     	movzx	eax, byte ptr [rax]
     10d: 83 f8 48                     	cmp	eax, 0x48
     110: 75 44                        	jne	0x156 <main+0x146>
     112: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     116: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
     11a: 3d 8d 00 00 00               	cmp	eax, 0x8d
     11f: 75 35                        	jne	0x156 <main+0x146>
     121: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     125: 0f b6 40 02                  	movzx	eax, byte ptr [rax + 0x2]
     129: 83 e0 07                     	and	eax, 0x7
     12c: 83 f8 04                     	cmp	eax, 0x4
     12f: 75 25                        	jne	0x156 <main+0x146>
     131: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     135: 0f b6 40 03                  	movzx	eax, byte ptr [rax + 0x3]
     139: 83 f8 25                     	cmp	eax, 0x25
     13c: 75 18                        	jne	0x156 <main+0x146>
     13e: 31 ff                        	xor	edi, edi
     140: e8 00 00 00 00               	call	0x145 <main+0x135>
     145: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     149: 48 83 c0 08                  	add	rax, 0x8
     14d: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
     151: e9 d1 fe ff ff               	jmp	0x27 <main+0x17>
     156: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     15a: 0f b6 00                     	movzx	eax, byte ptr [rax]
     15d: 3d fe 00 00 00               	cmp	eax, 0xfe
     162: 74 29                        	je	0x18d <main+0x17d>
     164: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     168: 0f b6 00                     	movzx	eax, byte ptr [rax]
     16b: 3d ff 00 00 00               	cmp	eax, 0xff
     170: 74 1b                        	je	0x18d <main+0x17d>
     172: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     176: 0f b6 00                     	movzx	eax, byte ptr [rax]
     179: 83 f8 48                     	cmp	eax, 0x48
     17c: 75 67                        	jne	0x1e5 <main+0x1d5>
     17e: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     182: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
     186: 3d ff 00 00 00               	cmp	eax, 0xff
     18b: 75 58                        	jne	0x1e5 <main+0x1d5>
     18d: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     191: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
     195: 25 f8 00 00 00               	and	eax, 0xf8
     19a: 3d c0 00 00 00               	cmp	eax, 0xc0
     19f: 75 44                        	jne	0x1e5 <main+0x1d5>
     1a1: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     1a5: 0f b6 00                     	movzx	eax, byte ptr [rax]
     1a8: 83 f8 48                     	cmp	eax, 0x48
     1ab: 75 1d                        	jne	0x1ca <main+0x1ba>
     1ad: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     1b1: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
     1b5: 3d ff 00 00 00               	cmp	eax, 0xff
     1ba: 75 0e                        	jne	0x1ca <main+0x1ba>
     1bc: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     1c0: 48 83 c0 03                  	add	rax, 0x3
     1c4: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
     1c8: eb 0c                        	jmp	0x1d6 <main+0x1c6>
     1ca: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     1ce: 48 83 c0 02                  	add	rax, 0x2
     1d2: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
     1d6: bf 01 00 00 00               	mov	edi, 0x1
     1db: e8 00 00 00 00               	call	0x1e0 <main+0x1d0>
     1e0: e9 42 fe ff ff               	jmp	0x27 <main+0x17>
     1e5: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     1e9: 0f b6 00                     	movzx	eax, byte ptr [rax]
     1ec: 3d 83 00 00 00               	cmp	eax, 0x83
     1f1: 75 2c                        	jne	0x21f <main+0x20f>
     1f3: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     1f7: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
     1fb: 25 f8 00 00 00               	and	eax, 0xf8
     200: 3d f8 00 00 00               	cmp	eax, 0xf8
     205: 75 18                        	jne	0x21f <main+0x20f>
     207: 31 ff                        	xor	edi, edi
     209: e8 00 00 00 00               	call	0x20e <main+0x1fe>
     20e: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     212: 48 83 c0 03                  	add	rax, 0x3
     216: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
     21a: e9 08 fe ff ff               	jmp	0x27 <main+0x17>
     21f: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     223: 0f b6 00                     	movzx	eax, byte ptr [rax]
     226: 3d fe 00 00 00               	cmp	eax, 0xfe
     22b: 74 29                        	je	0x256 <main+0x246>
     22d: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     231: 0f b6 00                     	movzx	eax, byte ptr [rax]
     234: 3d ff 00 00 00               	cmp	eax, 0xff
     239: 74 1b                        	je	0x256 <main+0x246>
     23b: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     23f: 0f b6 00                     	movzx	eax, byte ptr [rax]
     242: 83 f8 48                     	cmp	eax, 0x48
     245: 75 67                        	jne	0x2ae <main+0x29e>
     247: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     24b: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
     24f: 3d ff 00 00 00               	cmp	eax, 0xff
     254: 75 58                        	jne	0x2ae <main+0x29e>
     256: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     25a: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
     25e: 25 f8 00 00 00               	and	eax, 0xf8
     263: 3d c8 00 00 00               	cmp	eax, 0xc8
     268: 75 44                        	jne	0x2ae <main+0x29e>
     26a: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     26e: 0f b6 00                     	movzx	eax, byte ptr [rax]
     271: 83 f8 48                     	cmp	eax, 0x48
     274: 75 1d                        	jne	0x293 <main+0x283>
     276: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     27a: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
     27e: 3d ff 00 00 00               	cmp	eax, 0xff
     283: 75 0e                        	jne	0x293 <main+0x283>
     285: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     289: 48 83 c0 03                  	add	rax, 0x3
     28d: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
     291: eb 0c                        	jmp	0x29f <main+0x28f>
     293: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     297: 48 83 c0 02                  	add	rax, 0x2
     29b: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
     29f: bf 01 00 00 00               	mov	edi, 0x1
     2a4: e8 00 00 00 00               	call	0x2a9 <main+0x299>
     2a9: e9 79 fd ff ff               	jmp	0x27 <main+0x17>
     2ae: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     2b2: 0f b6 00                     	movzx	eax, byte ptr [rax]
     2b5: 3d 83 00 00 00               	cmp	eax, 0x83
     2ba: 75 39                        	jne	0x2f5 <main+0x2e5>
     2bc: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     2c0: 0f b6 40 01                  	movzx	eax, byte ptr [rax + 0x1]
     2c4: 25 f8 00 00 00               	and	eax, 0xf8
     2c9: 3d e8 00 00 00               	cmp	eax, 0xe8
     2ce: 75 25                        	jne	0x2f5 <main+0x2e5>
     2d0: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     2d4: 0f b6 40 02                  	movzx	eax, byte ptr [rax + 0x2]
     2d8: 83 f8 01                     	cmp	eax, 0x1
     2db: 75 18                        	jne	0x2f5 <main+0x2e5>
     2dd: 31 ff                        	xor	edi, edi
     2df: e8 00 00 00 00               	call	0x2e4 <main+0x2d4>
     2e4: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     2e8: 48 83 c0 03                  	add	rax, 0x3
     2ec: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
     2f0: e9 32 fd ff ff               	jmp	0x27 <main+0x17>
     2f5: 48 8b 45 f0                  	mov	rax, qword ptr [rbp - 0x10]
     2f9: 48 83 c0 01                  	add	rax, 0x1
     2fd: 48 89 45 f0                  	mov	qword ptr [rbp - 0x10], rax
     301: eb 00                        	jmp	0x303 <main+0x2f3>
     303: eb 00                        	jmp	0x305 <main+0x2f5>
     305: eb 00                        	jmp	0x307 <main+0x2f7>
     307: eb 00                        	jmp	0x309 <main+0x2f9>
     309: eb 00                        	jmp	0x30b <main+0x2fb>
     30b: eb 00                        	jmp	0x30d <main+0x2fd>
     30d: eb 00                        	jmp	0x30f <main+0x2ff>
     30f: eb 00                        	jmp	0x311 <main+0x301>
     311: e9 11 fd ff ff               	jmp	0x27 <main+0x17>
     316: 31 c0                        	xor	eax, eax
     318: 48 83 c4 10                  	add	rsp, 0x10
     31c: 5d                           	pop	rbp
     31d: c3                           	ret
