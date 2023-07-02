export const IN_BROWSER = typeof(console) !== 'undefined';
export const IN_SHELL = !IN_BROWSER;
export const IS_IOS = IN_BROWSER ? navigator.userAgent.match(/iPhone/) : false;
export const NUM_REGS = IS_IOS ? 32 : 16;
