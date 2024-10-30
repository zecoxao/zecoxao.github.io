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
    //     binarySource: "https://github.com/PS5Dev/PS5-UMTX-Jailbreak/blob/33ef329d6480bb7bed6aadc144ba222ea5d14bbf/document/en/ps5/payloads/elfldr.elf",
    //     version: "?",
    //     supportedFirmwares: ["1.", "2.", "3.", "4.", "5."]
    // },
    {
        displayTitle: "ps5-kstuff",
        description: "FPKG enabler",
        fileName: "ps5-kstuff.bin",
        author: "sleirsgoevy",
        projectSource: "https://github.com/sleirsgoevy/ps4jb-payloads/tree/bd-jb/ps5-kstuff",
        binarySource: "https://github.com/sleirsgoevy/ps4jb2/blob/3e6053c3e4c691a9ccdc409172293a81de00ad7f/ps5-kstuff.bin",
        version: "3e6053c",
        supportedFirmwares: ["3.", "4."]
    },
    {
        displayTitle: "Byepervisor HEN",
        description: "FPKG enabler",
        fileName: "byepervisor.elf",
        author: "SpecterDev, ChendoChap, flatz, fail0verflow, Znullptr, kiwidog, sleirsgoevy, EchoStretch",
        projectSource: "https://github.com/EchoStretch/Byepervisor",
        binarySource: "https://github.com/EchoStretch/Byepervisor/actions/runs/11545292602",
        version: "4655f86",
        supportedFirmwares: ["1.12", "1.14", "2.00", "2.20", "2.25", "2.26", "2.30", "2.50"],
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
        description: "Uses john-tornblom's elfldr. Custom homebrew loader. Runs on port 8080.",
        fileName: "websrv.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/websrv/releases",
        binarySource: "https://github.com/ps5-payload-dev/pacbrew-repo/actions/runs/11543810644",
        version: "0.14",
        toPort: 9021
    },
    {
        displayTitle: "ftpsrv",
        description: "Uses john-tornblom's elfldr. FTP server. Runs on port 2121.",
        fileName: "ftpsrv.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/ftpsrv",
        binarySource: "https://github.com/ps5-payload-dev/pacbrew-repo/actions/runs/11543810644",
        version: "0.11",
        toPort: 9021
    },
    {
        displayTitle: "klogsrv",
        description: "Uses john-tornblom's elfldr. Klog server. Runs on port 3232.",
        fileName: "klogsrv.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/klogsrv/releases",
        binarySource: "https://github.com/ps5-payload-dev/pacbrew-repo/actions/runs/11543810644",
        version: "0.5",
        toPort: 9021
    },
    {
        displayTitle: "shsrv",
        description: "Uses john-tornblom's elfldr. Telnet shell server. Runs on port 2323.",
        fileName: "shsrv.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/shsrv/releases",
        binarySource: "https://github.com/ps5-payload-dev/pacbrew-repo/actions/runs/11543810644",
        version: "0.12",
        toPort: 9021
    },
    {
        displayTitle: "gdbsrv",
        description: "Uses john-tornblom's elfldr. GDB server. Runs on port 2159.",
        fileName: "gdbsrv.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/gdbsrv/releases",
        binarySource: "https://github.com/ps5-payload-dev/pacbrew-repo/actions/runs/11543810644",
        version: "0.4-1",
        toPort: 9021
    },
    {
        displayTitle: "ps5debug",
        description: "Debugger (Experimental beta)",
        fileName: "ps5debug.elf",
        author: "SiSTR0, ctn123",
        projectSource: "https://github.com/GoldHEN/ps5debug",
        binarySource: "https://github.com/GoldHEN/ps5debug/releases/download/1.0b1/ps5debug_v1.0b1.7z",
        version: "1.0b1",
        supportedFirmwares: ["3.", "4."]
    },
    {
        displayTitle: "ps5-versions",
        description: "Shows kernel build, os and sdk versions",
        fileName: "ps5-versions.elf",
        author: "SiSTRo",
        projectSource: "https://github.com/SiSTR0/ps5-versions",
        binarySource: "https://github.com/SiSTR0/ps5-versions/releases/download/v1.0/ps5-versions.elf",
        version: "1.0",
        supportedFirmwares: ["1.", "2.", "3.", "4."]
    },
    {
        // https://github.com/Storm21CH/PS5_Browser_appCache_remove
        displayTitle: "Browser appcache remover",
        description: "Deletes for only the current user in webkit-only mode",
        fileName: "",
        author: "Storm21CH, idlesauce",
        projectSource: "",
        binarySource: "",
        version: "1.0",
        customAction: CUSTOM_ACTION_APPCACHE_REMOVE
    }

];
