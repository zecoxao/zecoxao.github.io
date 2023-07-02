import {IN_BROWSER, IN_SHELL} from './env.js';

let offsets_obj = {
    // Offset from a JSGlobalObject to its poiner to the GlobalObject
    JS_GLOBAL_OBJ_TO_GLOBAL_OBJ: undefined,

    // Offset from a GlobalObject to its pointer to the VM instance
    GLOBAL_OBJ_TO_VM: undefined,

    // Offset from a VM instance to its topCallFrame member
    VM_TO_TOP_CALL_FRAME: undefined,

    // Offset from a JSFunction to its Executable pointer
    JS_FUNCTION_TO_EXECUTABLE: undefined,

    // Offset from an Executable to its JITCode pointer
    EXECUTABLE_TO_JITCODE: undefined,

    // Offset from an Executable to its pointer to the native function
    EXECUTABLE_TO_NATIVE_FUNC: undefined,

    // Offset from a JITCode instance to the entrypoint pointer
    JIT_CODE_TO_ENTRYPOINT: undefined,

    // Offset from the base of the JavaScriptCore module to the head of the EXC_BAD_ACCESS handler
    JSC_BASE_TO_SEGV_HANDLER: undefined,

    // Offset from the base of the JavaScriptCore module to the return address in __Xmach_exception_raise_state from _catch_mach_exception_raise_state
    JSC_BASE_TO_CATCH_EXCEPTION_RET_ADDR: undefined,

    // Offsets from the base of the JavaScriptCore module to the implementation of Math.exp.
    JSC_BASE_TO_MATH_EXP: undefined,

    resolve() {
        if (IN_BROWSER) {
            // Safari 13.1, macOS 10.15.4
            // "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15"
            if (navigator.userAgent.match(/Intel Mac OS X 10_15_4/)) {
                this.JS_GLOBAL_OBJ_TO_GLOBAL_OBJ = 24;
                this.GLOBAL_OBJ_TO_VM = 56;
                this.VM_TO_TOP_CALL_FRAME = 0x9ac0;
                this.JS_FUNCTION_TO_EXECUTABLE = 24;
                this.EXECUTABLE_TO_JITCODE = 8;
                this.JIT_CODE_TO_ENTRYPOINT = 0x148;
            }
            // iOS 13.4, iPhone XS
            // Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1
            else if (navigator.userAgent.match(/Version\/13.1 Mobile\/15E148/)) {
                this.JS_GLOBAL_OBJ_TO_GLOBAL_OBJ = 24;
                this.GLOBAL_OBJ_TO_VM = 56;
                // Find this offset e.g. by looking at JSC::VM::throwException in the JSC binary
                this.VM_TO_TOP_CALL_FRAME = 0x99c0;
                this.JS_FUNCTION_TO_EXECUTABLE = 24;
                this.EXECUTABLE_TO_JITCODE = 8;
                this.EXECUTABLE_TO_NATIVE_FUNC = 40;
                this.JIT_CODE_TO_ENTRYPOINT = 0x148;
                this.JSC_BASE_TO_SEGV_HANDLER = 0x3e8b00b0;
                this.JSC_BASE_TO_CATCH_EXCEPTION_RET_ADDR = 0x279f8;
                this.JSC_BASE_TO_MATH_EXP = 0xbb877c;
            } else {
                throw "Unknown platform: " + navigator.userAgent;
            }
        } else {
            // TODO automatically detect Debug or Release build somehow.

            // DEBUG
            //this.JS_GLOBAL_OBJ_TO_GLOBAL_OBJ = 16;
            //this.GLOBAL_OBJ_TO_VM = 64;
            //this.VM_TO_TOP_CALL_FRAME = 0x9c60;

            // RELEASE
            this.JS_GLOBAL_OBJ_TO_GLOBAL_OBJ = 16;
            this.GLOBAL_OBJ_TO_VM = 56;
            this.VM_TO_TOP_CALL_FRAME = 0x9c00;
            this.JS_FUNCTION_TO_EXECUTABLE = 24;
            this.EXECUTABLE_TO_JITCODE = 8;
            this.JIT_CODE_TO_ENTRYPOINT = 0x148;
        }
    }
};

// Wrap it in a proxy to detect access to missing offsets.
export let offsets = new Proxy(offsets_obj, {
    get(target, property, receiver) {
        if (target[property] === undefined) {
            throw `Using undefined offset ${property}`;
        }
        return target[property];
    }
});
