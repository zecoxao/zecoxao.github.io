let socket = new WebSocket(`ws://${location.host}/logging`);

function log(msg) {
    try {
        socket.send('[WORKER X] ' + msg);
    } catch (e) {}
}

socket.onopen = function() {
    onmessage = function(m) {
        let r = eval(m.data);
        try {
            postMessage(r);
        } catch (e) {
            // Can't clone this.
            postMessage(undefined);
        }
    };

    postMessage('Ready');
};
