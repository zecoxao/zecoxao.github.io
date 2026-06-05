// @ts-check

const CUSTOM_ACTION_APPCACHE_REMOVE = "appcache-remove";

/**
 * @typedef {Object} PayloadInfo
 * @property {string} displayTitle
 * @property {string} description
 * @property {string} fileName - path relative to the payloads folder
 * @property {string} author
 * @property {string} projectSource
 * @property {string} binarySource - should be direct download link to the included version, so that you can verify the hashes
 * @property {string} version
 * @property {string[]?} [supportedFirmwares] - optional, these are interpreted as prefixes, so "" would match all, and "4." would match 4.xx, if not set, the payload is assumed to be compatible with all firmwares
 * @property {number?} [toPort] - optional, if the payload should be sent to "127.0.0.1:<port>" instead of loading directly, if specified it'll show up in webkit-only mode too
 * @property {string?} [customAction]
 */

/**
 * @type {PayloadInfo[]}
*/
const payload_map = [
    // { // auto-loaded
    //     displayTitle: "PS5 Payload ELF Loader",
    //     description: "Uses port 9021. Persistent network elf loader",
    //     fileName: "elfldr.elf",
    //     author: "john-tornblom",
    //     projectSource: "https://github.com/ps5-payload-dev/elfldr",
    //     binarySource: "https://github.com/ps5-payload-dev/elfldr/releases/download/v0.19/Payload.zip",
    //     version: "0.19",
    //     supportedFirmwares: ["1.", "2.", "3.", "4.", "5."]
    // },
    {
        displayTitle: "etaHEN",
        description: "AIO HEN",
        fileName: "etaHEN.elf",
        author: "LightningMods, Buzzer, sleirsgoevy, ChendoChap, astrelsky, illusion, CTN, SiSTR0, Nomadic",
        projectSource: "https://github.com/etaHEN/etaHEN",
        binarySource: "https://github.com/etaHEN/etaHEN/releases/download/2.6B/etaHEN-2.6B.bin",
        version: "2.6b",
        toPort: 9021
    },
    {
        displayTitle: "ps5-kstuff-lite",
        description: "FPKG enabler",
        fileName: "kstuff.elf",
        author: "sleirsgoevy, john-tornblom, EchoStretch, buzzer-re, BestPig, LightningMods, zecoxao, idlesauce",
        projectSource: "https://github.com/EchoStretch/kstuff-lite",
        binarySource: "https://github.com/EchoStretch/kstuff-lite/releases/tag/v1.07",
        version: "1.07",
        supportedFirmwares: ["3.", "4.", "5.", "6.", "7.", "8.", "9.", "10."],
        toPort: 9021
    },
    {
        displayTitle: "elf-arsenal",
        description: "all in one tool for payloads",
        fileName: "elf-arsenal.elf",
        author: "Sonic-Iso", 
        projectSource: "https://git.etawen.dev/soniciso/elf-arsenal",
        binarySource: "https://git.etawen.dev/soniciso/elf-arsenal/releases/tag/v1.6.6",
        version: "1.6.6",
        supportedFirmwares: ["1.","2.","3.","4.","5."],
        toPort: 9021
    },
    {
        displayTitle: "libhijacker game-patch",
        description: "Patches supported games to run at higher framerates, and adds debug menus to certain titles.",
        fileName: "libhijacker-game-patch.v1.160.elf",
        author: "illusion0001, astrelsky",
        projectSource: "https://github.com/illusion0001/libhijacker",
        binarySource: "https://github.com/illusion0001/libhijacker-game-patch/releases/tag/1.160-75ab26a3",
        version: "1.160",
        supportedFirmwares: ["3.", "4."]
    },
    {
        displayTitle: "websrv",
        description: "Custom homebrew loader. Runs on port 8080.",
        fileName: "websrv.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/websrv",
        binarySource: "https://github.com/ps5-payload-dev/websrv/actions/runs/14318408868",
        version: "0.22",
        toPort: 9021
    },
    {
        displayTitle: "ftpsrv",
        description: "FTP server. Runs on port 2121.",
        fileName: "ftpsrv.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/ftpsrv",
        binarySource: "https://github.com/ps5-payload-dev/pacbrew-repo/actions/runs/14012252230",
        version: "0.12.8",
        toPort: 9021
    },
    {
        displayTitle: "klogsrv",
        description: "Klog server. Runs on port 3232.",
        fileName: "klogsrv.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/klogsrv",
        binarySource: "https://github.com/ps5-payload-dev/pacbrew-repo/actions/runs/14012252230",
        version: "0.5.3",
        toPort: 9021
    },
    {
        displayTitle: "shadowmountplus",
        description: "Mount games has never been easier with shadowmountplus",
        fileName: "shadowmountplus.elf",
        author: "drakmor",
        projectSource: "https://github.com/drakmor/ShadowMountPlus/",
        binarySource: "https://github.com/drakmor/ShadowMountPlus/releases/tag/1.6test15-fix2",
        version: "1.6test15-fix2",
        toPort: 9021
    },
    {
        displayTitle: "voidshell",
        description: "AIO tool by VoidWhisper",
        fileName: "voidshell.elf",
        author: "VoidWhisper",
        projectSource: "https://ko-fi.com/s/d90b784d5d",
        binarySource: "https://ko-fi.com/s/d90b784d5d",
        version: "3.0B",
        toPort: 9021
    },
    {
        displayTitle: "ps5debug-NG",
        description: "OpenSource Debugger",
        fileName: "ps5debug-NG_v1.2.5.elf",
        author: "SiSTR0, ctn123, jogolden, OpenSourcereR-dev",
        projectSource: "https://github.com/OpenSourcereR-dev/ps5debug-NG",
        binarySource: "https://github.com/OpenSourcereR-dev/ps5debug-NG/releases/tag/1.2.5",
        version: "1.2.5",
        supportedFirmwares: ["3.", "4.","5."],
        toPort: 9021
    },
    {
        displayTitle: "ps5-backpork",
        description: "Backpork by BestPig, for the best BackPorts",
        fileName: "ps5-backpork.elf",
        author: "MeilleurCochon",
        projectSource: "https://github.com/BestPig/BackPork",
        binarySource: "https://github.com/BestPig/BackPork/releases/download/0.1/ps5-backpork.elf",
        version: "0.1",
        supportedFirmwares: ["1.", "2.", "3.", "4.", "5."],
		toPort: 9021
    },
    {
        displayTitle: "ps5-linux-loader",
        description: "Linux Loader for the PS5 by TheFlow",
        fileName: "ps5-linux-loader.elf",
        author: "TheFlow",
        projectSource: "https://github.com/ps5-linux/ps5-linux-loader/",
        binarySource: "https://github.com/ps5-linux/ps5-linux-loader/releases/tag/v2.1",
        version: "2.1",
		supportedFirmwares: ["3.","4.","5.","6."],
        toPort: 9021
    },
    {
        displayTitle: "Browser appcache remover",
        description: "Deletes for only the current user in webkit-only mode",
        fileName: "",
        author: "Storm21CH, idlesauce",
        projectSource: "https://github.com/Storm21CH/PS5_Browser_appCache_remove",
        binarySource: "",
        version: "1.0",
        customAction: CUSTOM_ACTION_APPCACHE_REMOVE
    }

];
