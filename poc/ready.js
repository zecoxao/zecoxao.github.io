import {IN_BROWSER} from './env.js';

let pending_promises = [];

// Wait for page to be loaded.
if (IN_BROWSER) {
    waitFor(new Promise(function(resolve) {
        window.onload = function() {
            resolve();
        }
    }));
}

export function waitFor(p) {
    pending_promises.push(p);
}

export async function ready() {
    await Promise.all(pending_promises);
}

