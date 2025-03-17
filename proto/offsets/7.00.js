const OFFSET_wk_vtable_first_element     = 0x00DF7BD0; // B8 37 00 00 00 C3
const OFFSET_wk_snprintf_import          = 0x021A6438; //fixed
const OFFSET_wk___stack_chk_guard_import = 0x021A6278; //fixed

const OFFSET_lk___stack_chk_guard        = 0x000911B0;//match
const OFFSET_lk_pthread_create_name_np   = 0x00001910;//match
const OFFSET_lk_pthread_join             = 0x0002c8e0;//match
const OFFSET_lk_pthread_exit             = 0x0001e400;//match
const OFFSET_lk__thread_list             = 0x0005C198;//maybe? 
const OFFSET_lk_sleep                    = 0x00020c30;//match
const OFFSET_lk_sceKernelGetCurrentCpu   = 0x00000460;//match

const OFFSET_lc_snprintf                 = 0x00063BD0;//match
const OFFSET_lc_setjmp                   = 0x000737D0;//match
const OFFSET_lc_longjmp                  = 0x0005d2d0;//match

const OFFSET_WORKER_STACK_OFFSET         = 0x0007FB88;//always the same

let wk_gadgetmap = {
    "ret":              0x0000004c, // C3
    "pop rdi":          0x001d041d, // 5F C3
    "pop rsi":          0x00025f17, // 5E C3
    "pop rdx":          0x000421b2, // 5A C3
    "pop rcx":          0x0001fe95, // 59 C3
    "pop r8":           0x001e48de, // 47 58 C3
    "pop r9":           0x00451af1, // 47 59 C3
    "pop rax":          0x00020eb0, // 58 C3
    "pop rsp":          0x00025cd0, // 5C C3

    "mov [rdi], rsi":   0x000133e0, // 48 89 37 C3
    "mov [rdi], rax":   0x00008c2a, // 48 89 07 C3
    "mov [rdi], eax":   0x00008c2b, // 89 07 C3

    "infloop":          0x000183D9, // EB FE

    //branching specific gadgets
    "cmp [rcx], eax":   0x0063fd12, //39 01 C3
    "sete al":          0x0000ee14, //0F 94 C0 C3
    "seta al":          0x00119f54, //0F 97 C0 C3
    "setb al":          0x00031e34, //0F 92 C0 C3
    "setg al":          0x0040c547, //0F 9F C0 C3
    "setl al":          0x0042b7cc, //0F 9C C0 C3
    "shl rax, 3":       0x012347a3, //48 C1 E0 03 C3
    "add rax, rcx":     0x00064d5f, //48 01 C8 C3
    "mov rax, [rax]":   0x0001ac12, //48 8B 00 C3
    "inc dword [rax]":  0x00453DEA, //FF 00 C3
};

let syscall_map = {
    0x001: 0x2fa9a, // sys_exit
    0x002: 0x31a90, // sys_fork
    0x003: 0x322d0, // sys_read
    0x004: 0x30c90, // sys_write
    0x005: 0x300d0, // sys_open
    0x006: 0x2fed0, // sys_close
    0x007: 0x2fa50, // sys_wait4
    0x00A: 0x2fcc0, // sys_unlink
    0x00C: 0x30270, // sys_chdir
    0x00F: 0x2fd10, // sys_chmod
    0x014: 0x31c30, // sys_getpid
    0x017: 0x2fd50, // sys_setuid
    0x018: 0x31070, // sys_getuid
    0x019: 0x2fb20, // sys_geteuid
    0x01B: 0x301b0, // sys_recvmsg
    0x01C: 0x30cf0, // sys_sendmsg
    0x01D: 0x31010, // sys_recvfrom
    0x01E: 0x2fc20, // sys_accept
    0x01F: 0x2f990, // sys_getpeername
    0x020: 0x30cb0, // sys_getsockname
    0x021: 0x2fe30, // sys_access
    0x022: 0x30410, // sys_chflags
    0x023: 0x31fe0, // sys_fchflags
    0x024: 0x2ff10, // sys_sync
    0x025: 0x31e20, // sys_kill
    0x027: 0x30bb0, // sys_getppid
    0x029: 0x32160, // sys_dup
    0x02A: 0x317a0, // sys_compat10.pipe
    0x02B: 0x30c50, // sys_getegid
    0x02C: 0x31f60, // sys_profil
    0x02F: 0x31990, // sys_getgid
    0x031: 0x315e0, // sys_getlogin
    0x032: 0x2fce0, // sys_setlogin
    0x035: 0x31ad0, // sys_sigaltstack
    0x036: 0x30110, // sys_ioctl
    0x037: 0x2fba0, // sys_reboot
    0x038: 0x31cf0, // sys_revoke
    0x03B: 0x3143d, // sys_execve
    0x041: 0x31d90, // sys_msync
    0x049: 0x31bf0, // sys_munmap
    0x04A: 0x30660, // sys_mprotect
    0x04B: 0x2f950, // sys_madvise
    0x04E: 0x30f10, // sys_mincore
    0x04F: 0x321c0, // sys_getgroups
    0x050: 0x30b50, // sys_setgroups
    0x053: 0x30330, // sys_setitimer
    0x056: 0x30880, // sys_getitimer
    0x059: 0x31870, // sys_getdtablesize
    0x05A: 0x305e0, // sys_dup2
    0x05C: 0x31680, // sys_fcntl
    0x05D: 0x32290, // sys_select
    0x05F: 0x30980, // sys_fsync
    0x060: 0x30800, // sys_setpriority
    0x061: 0x32100, // sys_socket
    0x062: 0x303b0, // sys_connect
    0x063: 0x31f40, // sys_netcontrol
    0x064: 0x315a0, // sys_getpriority
    0x065: 0x30d60, // sys_netabort
    0x066: 0x30dd0, // sys_netgetsockinfo
    0x068: 0x30960, // sys_bind
    0x069: 0x2fff0, // sys_setsockopt
    0x06A: 0x30820, // sys_listen
    0x071: 0x30fb0, // sys_socketex
    0x072: 0x31de0, // sys_socketclose
    0x074: 0x31c70, // sys_gettimeofday
    0x075: 0x31850, // sys_getrusage
    0x076: 0x30250, // sys_getsockopt
    0x078: 0x308c0, // sys_readv
    0x079: 0x30760, // sys_writev
    0x07A: 0x30f30, // sys_settimeofday
    0x07C: 0x31cb0, // sys_fchmod
    0x07D: 0x31af0, // sys_netgetiflist
    0x07E: 0x30f50, // sys_setreuid
    0x07F: 0x31030, // sys_setregid
    0x080: 0x30af0, // sys_rename
    0x083: 0x30ad0, // sys_flock
    0x085: 0x31b10, // sys_sendto
    0x086: 0x306e0, // sys_shutdown
    0x087: 0x324b0, // sys_socketpair
    0x088: 0x312f0, // sys_mkdir
    0x089: 0x31ec0, // sys_rmdir
    0x08A: 0x31290, // sys_utimes
    0x08C: 0x30fd0, // sys_adjtime
    0x08D: 0x304d0, // sys_kqueueex
    0x093: 0x2fca0, // sys_setsid
    0x0A5: 0x31bb0, // sys_sysarch
    0x0B6: 0x30e30, // sys_setegid
    0x0B7: 0x30f70, // sys_seteuid
    0x0BC: 0x31930, // sys_stat
    0x0BD: 0x317d0, // sys_fstat
    0x0BE: 0x31f00, // sys_lstat
    0x0BF: 0x31e80, // sys_pathconf
    0x0C0: 0x32200, // sys_fpathconf
    0x0C2: 0x310f0, // sys_getrlimit
    0x0C3: 0x314e0, // sys_setrlimit
    0x0C4: 0x300b0, // sys_getdirentries
    0x0CA: 0x31560, // sys___sysctl
    0x0CB: 0x32220, // sys_mlock
    0x0CC: 0x323b0, // sys_munlock
    0x0CE: 0x2f9d0, // sys_futimes
    0x0D1: 0x311d0, // sys_poll
    0x0E8: 0x323f0, // sys_clock_gettime
    0x0E9: 0x32490, // sys_clock_settime
    0x0EA: 0x31350, // sys_clock_getres
    0x0EB: 0x32020, // sys_ktimer_create
    0x0EC: 0x31d10, // sys_ktimer_delete
    0x0ED: 0x2fd90, // sys_ktimer_settime
    0x0EE: 0x2f9b0, // sys_ktimer_gettime
    0x0EF: 0x2ffb0, // sys_ktimer_getoverrun
    0x0F0: 0x30e90, // sys_nanosleep
    0x0F1: 0x2fb00, // sys_ffclock_getcounter
    0x0F2: 0x301f0, // sys_ffclock_setestimate
    0x0F3: 0x2fc00, // sys_ffclock_getestimate
    0x0F7: 0x31c90, // sys_clock_getcpuclockid2
    0x0FB: 0x2fa79, // sys_rfork
    0x0FD: 0x30c30, // sys_issetugid
    0x110: 0x31270, // sys_getdents
    0x121: 0x30740, // sys_preadv
    0x122: 0x307e0, // sys_pwritev
    0x136: 0x2ff90, // sys_getsid
    0x13B: 0x30d10, // sys_aio_suspend
    0x144: 0x32350, // sys_mlockall
    0x145: 0x30150, // sys_munlockall
    0x147: 0x30ff0, // sys_sched_setparam
    0x148: 0x315c0, // sys_sched_getparam
    0x149: 0x30290, // sys_sched_setscheduler
    0x14A: 0x31520, // sys_sched_getscheduler
    0x14B: 0x31150, // sys_sched_yield
    0x14C: 0x31580, // sys_sched_get_priority_max
    0x14D: 0x32330, // sys_sched_get_priority_min
    0x14E: 0x30e10, // sys_sched_rr_get_interval
    0x154: 0x30a03, // sys_sigprocmask
    0x155: 0x319f0, // sys_sigsuspend
    0x157: 0x319b0, // sys_sigpending
    0x159: 0x30620, // sys_sigtimedwait
    0x15A: 0x31760, // sys_sigwaitinfo
    0x16A: 0x302f0, // sys_kqueue
    0x16B: 0x30310, // sys_kevent
    0x17B: 0x302d0, // sys_mtypeprotect
    0x188: 0x2fae0, // sys_uuidgen
    0x189: 0x31f20, // sys_sendfile
    0x18D: 0x30230, // sys_fstatfs
    0x190: 0x324f0, // sys_ksem_close
    0x191: 0x310d0, // sys_ksem_post
    0x192: 0x313f0, // sys_ksem_wait
    0x193: 0x31130, // sys_ksem_trywait
    0x194: 0x304b0, // sys_ksem_init
    0x195: 0x2feb0, // sys_ksem_open
    0x196: 0x31810, // sys_ksem_unlink
    0x197: 0x30640, // sys_ksem_getvalue
    0x198: 0x316a0, // sys_ksem_destroy
    0x1A0: 0x30c70, // sys_sigaction
    0x1A1: 0x31090, // sys_sigreturn
    0x1A5: 0x32264, // sys_getcontext
    0x1A6: 0x2fd70, // sys_setcontext
    0x1A7: 0x31640, // sys_swapcontext
    0x1AD: 0x310b0, // sys_sigwait
    0x1AE: 0x318d0, // sys_thr_create
    0x1AF: 0x31d50, // sys_thr_exit
    0x1B0: 0x2fdb0, // sys_thr_self
    0x1B1: 0x301d0, // sys_thr_kill
    0x1B9: 0x300f0, // sys_ksem_timedwait
    0x1BA: 0x2fd30, // sys_thr_suspend
    0x1BB: 0x30eb0, // sys_thr_wake
    0x1BC: 0x316e0, // sys_kldunloadf
    0x1C6: 0x305c0, // sys__umtx_op
    0x1C7: 0x30a90, // sys_thr_new
    0x1C8: 0x30da0, // sys_sigqueue
    0x1D0: 0x30e50, // sys_thr_set_name
    0x1D2: 0x2f910, // sys_rtprio_thread
    0x1DB: 0x30470, // sys_pread
    0x1DC: 0x31480, // sys_pwrite
    0x1DD: 0x2ffd0, // sys_mmap
    0x1DE: 0x320a0, // sys_lseek
    0x1DF: 0x307a0, // sys_truncate
    0x1E0: 0x30780, // sys_ftruncate
    0x1E1: 0x30b30, // sys_thr_kill2
    0x1E2: 0x30210, // sys_shm_open
    0x1E3: 0x2fc60, // sys_shm_unlink
    0x1E6: 0x31830, // sys_cpuset_getid
    0x1E7: 0x30450, // sys_ps4_cpuset_getaffinity
    0x1E8: 0x31a10, // sys_ps4_cpuset_setaffinity
    0x1F3: 0x31c10, // sys_openat
    0x203: 0x324d0, // sys___cap_rights_get
    0x20A: 0x31890, // sys_pselect
    0x214: 0x31600, // sys_regmgr_call
    0x215: 0x32310, // sys_jitshm_create
    0x216: 0x322f0, // sys_jitshm_alias
    0x217: 0x311b0, // sys_dl_get_list
    0x218: 0x31660, // sys_dl_get_info
    0x21A: 0x30bf0, // sys_evf_create
    0x21B: 0x308e0, // sys_evf_delete
    0x21C: 0x30cd0, // sys_evf_open
    0x21D: 0x2fdd0, // sys_evf_close
    0x21E: 0x32000, // sys_evf_wait
    0x21F: 0x2fc40, // sys_evf_trywait
    0x220: 0x308a0, // sys_evf_set
    0x221: 0x32240, // sys_evf_clear
    0x222: 0x30b10, // sys_evf_cancel
    0x223: 0x318f0, // sys_query_memory_protection
    0x224: 0x2ff30, // sys_batch_map
    0x225: 0x321e0, // sys_osem_create
    0x226: 0x31620, // sys_osem_delete
    0x227: 0x31540, // sys_osem_open
    0x228: 0x302b0, // sys_osem_close
    0x229: 0x31b90, // sys_osem_wait
    0x22A: 0x30900, // sys_osem_trywait
    0x22B: 0x31b50, // sys_osem_post
    0x22C: 0x30130, // sys_osem_cancel
    0x22D: 0x30860, // sys_namedobj_create
    0x22E: 0x31310, // sys_namedobj_delete
    0x22F: 0x32080, // sys_set_vm_container
    0x230: 0x31500, // sys_debug_init
    0x233: 0x2fbe0, // sys_opmc_enable
    0x234: 0x31bd0, // sys_opmc_disable
    0x235: 0x319d0, // sys_opmc_set_ctl
    0x236: 0x31780, // sys_opmc_set_ctr
    0x237: 0x2fac0, // sys_opmc_get_ctr
    0x23C: 0x30b90, // sys_virtual_query
    0x249: 0x2fb60, // sys_is_in_sandbox
    0x24A: 0x31ab0, // sys_dmem_container
    0x24B: 0x31cd0, // sys_get_authinfo
    0x24C: 0x2fa30, // sys_mname
    0x24F: 0x30070, // sys_dynlib_dlsym
    0x250: 0x30ed0, // sys_dynlib_get_list
    0x251: 0x314c0, // sys_dynlib_get_info
    0x252: 0x31d30, // sys_dynlib_load_prx
    0x253: 0x30170, // sys_dynlib_unload_prx
    0x254: 0x2fe90, // sys_dynlib_do_copy_relocations
    0x256: 0x2fe70, // sys_dynlib_get_proc_param
    0x257: 0x31a70, // sys_dynlib_process_needed_and_relocate
    0x258: 0x31970, // sys_sandbox_path
    0x259: 0x2f8f0, // sys_mdbg_service
    0x25A: 0x32470, // sys_randomized_path
    0x25B: 0x31390, // sys_rdup
    0x25C: 0x320c0, // sys_dl_get_metadata
    0x25D: 0x30bd0, // sys_workaround8849
    0x25E: 0x30370, // sys_is_development_mode
    0x25F: 0x303d0, // sys_get_self_auth_info
    0x260: 0x31db0, // sys_dynlib_get_info_ex
    0x262: 0x32450, // sys_budget_get_ptype
    0x263: 0x31330, // sys_get_paging_stats_of_all_threads
    0x264: 0x312b0, // sys_get_proc_type_info
    0x265: 0x31230, // sys_get_resident_count
    0x267: 0x30190, // sys_get_resident_fmem_count
    0x268: 0x318b0, // sys_thr_get_name
    0x269: 0x2f930, // sys_set_gpo
    0x26A: 0x31050, // sys_get_paging_stats_of_all_objects
    0x26B: 0x31910, // sys_test_debug_rwmem
    0x26C: 0x30030, // sys_free_stack
    0x26E: 0x30050, // sys_ipmimgr_call
    0x26F: 0x30010, // sys_get_gpo
    0x270: 0x32040, // sys_get_vm_map_timestamp
    0x271: 0x307c0, // sys_opmc_set_hw
    0x272: 0x30e70, // sys_opmc_get_hw
    0x273: 0x31950, // sys_get_cpu_usage_all
    0x274: 0x30d30, // sys_mmap_dmem
    0x275: 0x31700, // sys_physhm_open
    0x276: 0x30d80, // sys_physhm_unlink
    0x278: 0x313d0, // sys_thr_suspend_ucontext
    0x279: 0x309a0, // sys_thr_resume_ucontext
    0x27A: 0x31e60, // sys_thr_get_ucontext
    0x27B: 0x30600, // sys_thr_set_ucontext
    0x27C: 0x2f9f0, // sys_set_timezone_info
    0x27D: 0x309c0, // sys_set_phys_fmem_limit
    0x27E: 0x32180, // sys_utc_to_localtime
    0x27F: 0x32410, // sys_localtime_to_utc
    0x280: 0x30700, // sys_set_uevt
    0x281: 0x320e0, // sys_get_cpu_usage_proc
    0x282: 0x31ee0, // sys_get_map_statistics
    0x283: 0x32370, // sys_set_chicken_switches
    0x286: 0x2fa10, // sys_get_kernel_mem_statistics
    0x287: 0x30430, // sys_get_sdk_compiled_version
    0x288: 0x30c10, // sys_app_state_change
    0x289: 0x30f90, // sys_dynlib_get_obj_member
    0x28C: 0x30b70, // sys_process_terminate
    0x28D: 0x30490, // sys_blockpool_open
    0x28E: 0x321a0, // sys_blockpool_map
    0x28F: 0x31190, // sys_blockpool_unmap
    0x290: 0x316c0, // sys_dynlib_get_info_for_libdbg
    0x291: 0x32060, // sys_blockpool_batch
    0x292: 0x31f80, // sys_fdatasync
    0x293: 0x31b30, // sys_dynlib_get_list2
    0x294: 0x2ff70, // sys_dynlib_get_info2
    0x295: 0x31250, // sys_aio_submit
    0x296: 0x306a0, // sys_aio_multi_delete
    0x297: 0x31170, // sys_aio_multi_wait
    0x298: 0x317f0, // sys_aio_multi_poll
    0x299: 0x30ef0, // sys_aio_get_data
    0x29A: 0x30720, // sys_aio_multi_cancel
    0x29B: 0x31a30, // sys_get_bio_usage_all
    0x29C: 0x304f0, // sys_aio_create
    0x29D: 0x32120, // sys_aio_submit_cmd
    0x29E: 0x309e0, // sys_aio_init
    0x29F: 0x323d0, // sys_get_page_table_stats
    0x2A0: 0x31d70, // sys_dynlib_get_list_for_libdbg
    0x2A1: 0x31ea0, // sys_blockpool_move
    0x2A2: 0x32390, // sys_virtual_query_all
    0x2A3: 0x303f0, // sys_reserve_2mb_page
    0x2A4: 0x311f0, // sys_cpumode_yield
    0x2A5: 0x31460, // sys_wait6
    0x2A6: 0x30df0, // sys_cap_rights_limit
    0x2A7: 0x2fef0, // sys_cap_ioctls_limit
    0x2A8: 0x313b0, // sys_cap_ioctls_get
    0x2A9: 0x30920, // sys_cap_fcntls_limit
    0x2AA: 0x2fe50, // sys_cap_fcntls_get
    0x2AB: 0x312d0, // sys_bindat
    0x2AC: 0x30090, // sys_connectat
    0x2AD: 0x2fb80, // sys_chflagsat
    0x2AE: 0x2f970, // sys_accept4
    0x2AF: 0x31fc0, // sys_pipe2
    0x2B0: 0x30350, // sys_aio_mlock
    0x2B1: 0x31110, // sys_procctl
    0x2B2: 0x314a0, // sys_ppoll
    0x2B3: 0x31210, // sys_futimens
    0x2B4: 0x2fc80, // sys_utimensat
    0x2B5: 0x31e00, // sys_numa_getaffinity
    0x2B6: 0x30680, // sys_numa_setaffinity
    0x2C1: 0x30840, // sys_get_phys_page_size
};

// Kernel stack offsets
const OFFSET_KERNEL_STACK_COOKIE                = 0xDEADC0DE;
const OFFSET_KERNEL_STACK_SYS_SCHED_YIELD_RET   = 0xDEADC0DE;

// Kernel text-relative offsets
const OFFSET_KERNEL_DATA                        = 0x1526600; // ffffffff81726600
const OFFSET_KERNEL_SYS_SCHED_YIELD_RET         = 0x044E605; // ffffffff8064e605
const OFFSET_KERNEL_ALLPROC                     = 0x232B548; //done
const OFFSET_KERNEL_SECURITY_FLAGS              = 0x6BF19F4; //done
//const OFFSET_KERNEL_TARGETID                    = 0x6BF19FA; //done, should be 6th byte not 4th
const OFFSET_KERNEL_QA_FLAGS                    = 0x6BF1A18; //done
const OFFSET_KERNEL_UTOKEN_FLAGS                = 0x6BF1A80; //done
const OFFSET_KERNEL_PRISON0                     = 0x1654FB0; //done
const OFFSET_KERNEL_ROOTVNODE                   = 0x6EC8180; //done

// Kernel data-relative offsets
const OFFSET_KERNEL_DATA_BASE_ALLPROC           = 0x3851B48; // ffffffff83a51b48
const OFFSET_KERNEL_DATA_BASE_SECURITYFLAGS     = 0x8117FF4; // ffffffff88317ff4
const OFFSET_KERNEL_DATA_BASE_TARGETID          = 0x8117FFA; // ffffffff88317ffa, done should be 6th byte not 4th
const OFFSET_KERNEL_DATA_BASE_QA_FLAGS          = 0x8118018; // ffffffff88318018
const OFFSET_KERNEL_DATA_BASE_UTOKEN_FLAGS      = 0x8118080; // ffffffff88318080
const OFFSET_KERNEL_DATA_BASE_PRISON0           = 0x2B7B5B0; // ffffffff82d7b5b0
const OFFSET_KERNEL_DATA_BASE_ROOTVNODE         = 0x83EE780; // ffffffff885ee780