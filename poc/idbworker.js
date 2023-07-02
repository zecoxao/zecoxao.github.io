function freememory() {
    for (var i = 0; i < 1000; i++) {
        a = new Uint8Array(1024*1024);
    }
}

let ev = new Event('mine');
let req = indexedDB.open('db');
req.dispatchEvent(ev);
req = 0;
ev = 0;
freememory();
