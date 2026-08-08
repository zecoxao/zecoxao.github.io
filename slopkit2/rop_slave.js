// Sacrificial ROP thread.
//
// Its only job is to exist and to return from onmessage on demand. The chain
// runs on THIS thread's stack, never the renderer's - which is the whole point:
// lapse-runtime pivots RSP on the main thread and then "returns" by guessing
// RBP, which kills the renderer on every syscall (getpid included).
//
// Deliberately minimal. Anything else here would add frames we would have to
// reason about when locating the saved return address.
self.onmessage = function (event) {
    self.postMessage(1);
};
