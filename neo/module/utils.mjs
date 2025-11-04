import { Int } from './int64.mjs';

export function die(msg) {
    alert(msg);
    undefinedFunction();
}

export function debug_log(msg) {
    let textNode = document.createTextNode(msg);
    let node = document.createElement("p").appendChild(textNode);

    document.body.appendChild(node);
    document.body.appendChild(document.createElement("br"));
}

export function clear_log() {
    document.body.innerHTML = null;
}

export function str2array(str, length, offset) {
    if (offset === undefined) {
        offset = 0;
    }
    let a = new Array(length);
    for (let i = 0; i < length; i++) {
        a[i] = str.charCodeAt(i + offset);
    }
    return a;
}

// alignment must be 32 bits and is a power of 2
export function align(a, alignment) {
    if (!(a instanceof Int)) {
        a = new Int(a);
    }
    const mask = -alignment & 0xffffffff;
    let type = a.constructor;
    let low = a.low() & mask;
    return new type(low, a.high());
}

export async function send(url, buffer, file_name, onload=() => {}) {
    const file = new File(
        [buffer],
        file_name,
        {type:'application/octet-stream'}
    );
    const form = new FormData();
    form.append('upload', file);

    debug_log('send');
    const response = await fetch(url, {method: 'POST', body: form});

    if (!response.ok) {
        throw Error(`Network response was not OK, status: ${response.status}`);
    }
    onload();
}