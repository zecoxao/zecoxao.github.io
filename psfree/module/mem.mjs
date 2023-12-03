/* Copyright (C) 2023 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

import { Int } from './int64.mjs';
import {
    read16,
    read32,
    read64,
    write16,
    write32,
    write64,
} from './rw.mjs';
import * as o from './offset.mjs';

export let Addr = null;
export let mem = null;

function init_module(memory, addr_class) {
    mem = memory;
    Addr = addr_class;
}

export class Memory {
    constructor(main, main_addr, worker, worker_addr, worker_index)  {
        this.main = main;
        this.main_addr = main_addr;
        this.worker = worker;
        this.worker_addr = worker_addr;

        worker.a = main; // ensure a butterfly
        let butterfly = read64(main, worker_index + o.js_butterfly);
        this.butterfly = butterfly;

        write32(main, worker_index + o.view_m_length, 0xffffffff);
        // setup main's m_vector to worker
        write64(main, worker_index + o.view_m_vector, main_addr);
        write64(worker, o.view_m_vector, worker_addr);

        this._current_addr = main_addr;

        const mem = this;
        class Addr extends Int {
            read8(offset) {
                let addr = this.add(offset);
                return mem.read8(addr);
            }

            read16(offset) {
                let addr = this.add(offset);
                return mem.read16(addr);
            }

            read32(offset) {
                let addr = this.add(offset);
                return mem.read32(addr);
            }

            read64(offset) {
                let addr = this.add(offset);
                return mem.read64(addr);
            }

            // returns a pointer instead of an Int
            readp(offset) {
                let addr = this.add(offset);
                return mem.readp(addr);
            }

            write8(offset, value) {
                let addr = this.add(offset);

                mem.write8(addr, value);
            }

            write16(offset, value) {
                let addr = this.add(offset);

                mem.write16(addr, value);
            }

            write32(offset, value) {
                let addr = this.add(offset);

                mem.write32(addr, value);
            }

            write64(offset, value) {
                let addr = this.add(offset);

                mem.write64(addr, value);
            }
        }
        init_module(this, Addr);
    }

    _addrof(obj) {
        if (typeof obj !== 'object'
            && typeof obj !== 'function'
        ) {
            throw TypeError('addrof argument not a JS object');
        }
        this.worker.a = obj;
        write64(this.main, o.view_m_vector, this.butterfly.sub(0x10));
        let res = read64(this.worker, 0);
        write64(this.main, o.view_m_vector, this._current_addr);

        return res;
    }

    addrof(obj) {
        return new Addr(this._addrof(obj));
    }

    set_addr(addr) {
        if (!(addr instanceof Int)) {
            throw TypeError('addr must be an Int');
        }
        this._current_addr = addr;
        write64(this.main, o.view_m_vector, this._current_addr);
    }

    get_addr() {
        return this._current_addr;
    }

    read8(addr) {
        this.set_addr(addr);
        return this.worker[0];
    }

    read16(addr) {
        this.set_addr(addr);
        return read16(this.worker, 0);
    }

    read32(addr) {
        this.set_addr(addr);
        return read32(this.worker, 0);
    }

    read64(addr) {
        this.set_addr(addr);
        return read64(this.worker, 0);
    }

    // returns a pointer instead of an Int
    readp(addr) {
        return new Addr(this.read64(addr));
    }

    write8(addr, value) {
        this.set_addr(addr);
        this.worker[0] = value;
    }

    write16(addr, value) {
        this.set_addr(addr);
        write16(this.worker, 0, value);
    }

    write32(addr, value) {
        this.set_addr(addr);
        write32(this.worker, 0, value);
    }

    write64(addr, value) {
        this.set_addr(addr);
        write64(this.worker, 0, value);
    }
}
