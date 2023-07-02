import {IN_BROWSER} from './env.js';
import {waitFor} from './ready.js';

// Logging function.
export let log;

if (IN_BROWSER) {
    let socket = new WebSocket(`ws://${location.host}/logging`);

    waitFor(new Promise(function(resolve, reject) {
        socket.onopen = function() {
            resolve();
        }
        socket.onerror = function(err) {
            reject(err);
        };
    }));

    log = function(msg) {
        try {
            socket.send(msg);
        } catch (e) {}
        document.body.innerText += msg + '\n';
    }
} else {
    log = print;
}
