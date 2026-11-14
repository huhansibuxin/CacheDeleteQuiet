// CacheDeleteQuiet v1.1.1 - PLAN D: in-process C-level rebind of the recursive
//                            container scan, arm64e / rootless+roothide
// =============================================================================
// v1.1.0 device result (23:46:25, PID 32590): injection OK, but
//   CBASE mh=0x10044c000 slide=0x10044C000   <-- slide == mh, image 0 was NOT
//   REBIND [0..2] MISS raw=0x0 (not code)        the helper main executable
//   REBIND READY bound=0/3 (short-circuit=YES)  <-- misleading, nothing bound
//   23:46:32 htop 99% for ~30 s, fs_usage again all tmp/trash getattrlistbulk.
// => Fix: locate the main image by name + dladdr cross-check, derive slot
//    addresses from its real LC_SEGMENT_64 layout, and dump the whole dyld
//    image table / segment table / slot neighbourhood into the log.
// WHY v1.1.0 (v1.0.0 -> v1.0.1 both FAILED to lower CPU, proven on device)
//   v1.0.1 full log, 22:55:01 and 23:18:13 (PID 31798 / 32491):
//     START / DIAG / all 5 "HOOK ... OK" / READY / ONE 0ms factory call.
//   htop spike 23:18:53 (99.1%, ~30 s) produced ZERO further log lines.
//   => all five ObjC selectors are NOT on the 99% path. The CPU is burned in
//      pure C code that class_replaceMethod cannot reach.
//   fs_usage spike capture (device_state/cachedelete/spike_20261114_230049_01.txt)
//   shows the actual work: per-file
//     open + fstat64 + getattrlistbulk + close
//   on /private/var/mobile/Containers/Data/Application/<UUID>/tmp/trash/<hash>
//   i.e. a recursive tmp/trash walk, NOT purgeable estimation.
//
// WHY a GOT rebind (and NOT another ObjC hook, NOT a daemon disable)
//   Disabling the Mach service makes other apps fail to launch (observed), so
//   the process MUST stay alive and keep answering XPC.
//   Offline chained-fixups dump (analyze_fixups.py -> reports/helper_fixups.txt):
//     _fast_size_directory  __auth_got slot vm 0x100014148  auth_bind ord 41
//     _statfs               __auth_got slot vm 0x1000143D8  auth_bind ord 123
//     _traverse_directory   __auth_got slot vm 0x100014418  auth_bind ord 131
//     _CacheDeleteCopyItemizedPurgeableSpaceWithInfo  vm 0x100014018  ord 3
//   All are ARM64E auth binds (raw 0xC0090000000000NN: auth=1, bind=1,
//   key=IA, addrDiv=1, diversity=0). The corresponding __auth_stubs are:
//     adrp x17, #0x100014000 ; add x17,x17,#imm ; ldr x16,[x17] ; braa x16,x17
//   so the slot holds a PAC-signed (IA key + address diversity) function ptr.
//
// SAFETY: we NEVER guess a PAC signature.
//   For each slot we read dyld's already-signed pointer and self-verify the
//   discriminator with a PURE NUMERIC comparison (no deref, no branch):
//     stripped = ptrauth_strip(p, IA)
//     authed   = ptrauth_auth_data(p, IA, disc)
//     disc is accepted only when authed == stripped.
//   Two discriminator candidates are tried: the raw slot address (what the
//   stub passes in x17) and ptrauth_blend_discriminator(slot, 0).
//   If neither verifies, the slot is LEFT ALONE (fail-open). No crash path.
//   Only after verification do we vm_protect(VM_PROT_COPY) the single
//   __DATA_CONST page, write a freshly signed wrapper pointer, and restore.
//
// WHAT IS SHORT-CIRCUITED (QUIET, default)
//   _fast_size_directory  -> return 0   (recursive size/stat of every cache)
//   _traverse_directory   -> return 0   (recursive tmp/trash walk)
//   _statfs               -> ALWAYS passthrough (only count calls)
//   _CacheManagementEnumerateAssets / _CacheManagementRemove are NOT TOUCHED:
//   those are the real PURGE path and must keep working.
//   Returning 0 is an Apple-tolerated result: the disassembly has an explicit
//   `cbz x0, skip` right after the _fast_size_directory call site.
//
// Modes (empty flag files, checked ONCE in ctor, then kickstart -k)
//   (none)            QUIET  - rebind + short-circuit the two C scans [default]
//   PROBE_ONLY        probe  - rebind but ALWAYS call the original (A/B baseline)
//   PASSTHROUGH_ALL   pass   - no C rebind at all, stock behaviour
//   DISABLED          off    - no hooks installed at all
//   STRICT            strict - same as QUIET (kept for flag compatibility)
//   Log (PowerlogProbe v0.9.0 fallback - first writable one wins):
//     $TMPDIR/CacheDeleteQuiet.log (normally null on this helper)
//     /var/mobile/Documents/CacheDeleteQuiet/quiet.log
//     /var/mobile/Library/Logs/CacheDeleteQuiet.log
//     /var/tmp/CacheDeleteQuiet.log            <-- real one on device
//     /private/var/tmp/CacheDeleteQuiet.log
//   From SSH prepend /rootfs/private. Flags may be dropped in ANY of those dirs.
//
// HARD CONSTRAINTS (unchanged from v1.0.1)
//   - ZERO Logos %hook / ZERO substrate / ZERO ellekit LINK dependency.
//     No inline-patch API is used; we rebind our own image's GOT slots.
//   - NO Foundation / UIKit link; objc/runtime + libSystem + ptrauth builtins.
//   - NO polling / timer / dispatch_after. Event-driven only.
//   - Fail-open on any missing class / method / unmatched PAC discriminator.
// =============================================================================

#import <objc/runtime.h>
#import <objc/message.h>
#import <stdint.h>
#import <stdlib.h>
#import <stdarg.h>
#import <string.h>
#import <stdio.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <time.h>
#import <sys/stat.h>
#import <sys/time.h>
#import <mach/mach.h>
#import <mach/machine.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>

#if __has_include(<ptrauth.h>)
#import <ptrauth.h>
#define CDQ_PTRAUTH 1
#else
#define CDQ_PTRAUTH 0
#endif

// Kept alive so CI can assert the exact build that was packaged.
static const char kBuildTag[] __attribute__((used)) =
    "CacheDeleteQuiet 1.1.1 QUIET plan-D auth-got-rebind no-substrate";

#define kFlagDir        "/var/mobile/Documents/CacheDeleteQuiet"
#define kFlagOff        kFlagDir "/DISABLED"
#define kFlagPass       kFlagDir "/PASSTHROUGH_ALL"
#define kFlagProbe      kFlagDir "/PROBE_ONLY"
#define kFlagStrict     kFlagDir "/STRICT"

static const char *kLogCandidates[] = {
    "/var/mobile/Documents/CacheDeleteQuiet/quiet.log",
    "/var/mobile/Library/Logs/CacheDeleteQuiet.log",
    "/var/tmp/CacheDeleteQuiet.log",
    "/private/var/tmp/CacheDeleteQuiet.log",
};
static const char *kLogDirs[] = {
    "/var/mobile/Documents/CacheDeleteQuiet",
    "/var/mobile/Library/Logs",
    "/var/tmp",
    "/private/var/tmp",
};
#define kCandCount (sizeof(kLogCandidates) / sizeof(kLogCandidates[0]))

enum { MODE_OFF = 0, MODE_QUIET = 1, MODE_PROBE = 2, MODE_STRICT = 3, MODE_PASS = 4 };

static int g_mode = MODE_QUIET;
static int g_logfd = -1;
static const char *g_logpath = "(none)";
static int g_openErrno[4] = {0, 0, 0, 0};
static unsigned long long g_seq = 0;

// ---- tiny libSystem-only logger -------------------------------------------
static unsigned long long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, 0);
    return (unsigned long long)tv.tv_sec * 1000ULL + (unsigned long long)(tv.tv_usec / 1000);
}

static void plog(const char *fmt, ...) {
    if (g_logfd < 0) return;
    char body[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(body) - 1) n = (int)sizeof(body) - 1;

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%F %T", &tm);

    char line[1152];
    int m = snprintf(line, sizeof(line), "[%s] %.*s\n", ts, n, body);
    if (m <= 0) return;
    if (m > (int)sizeof(line) - 1) m = (int)sizeof(line) - 1;
    (void)write(g_logfd, line, (size_t)m);
}

static char g_dynLog[512];

static void open_log(void) {
    const char *tmp = getenv("TMPDIR");
    if (tmp && *tmp) {
        int n = snprintf(g_dynLog, sizeof(g_dynLog), "%s/CacheDeleteQuiet.log", tmp);
        if (n > 0 && n < (int)sizeof(g_dynLog)) {
            int fd = open(g_dynLog, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd >= 0) { g_logfd = fd; g_logpath = g_dynLog; return; }
        }
    }
    for (size_t i = 0; i < kCandCount; i++) {
        (void)mkdir(kLogDirs[i], 0755);
        int fd = open(kLogCandidates[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) { g_logfd = fd; g_logpath = kLogCandidates[i]; return; }
        g_openErrno[i] = errno;
    }
}

static void log_call(const char *name, unsigned long long t0, int pass, const char *cls) {
    unsigned long long dt = now_ms() - t0;
    unsigned long long seq = __sync_fetch_and_add(&g_seq, 1ULL);
    plog("%llu seq=%llu mode=%d pid=%d %-46s %-4s %llums cls=%s\n",
         now_ms(), seq, g_mode, (int)getpid(), name,
         pass ? "PASS" : "SKIP", dt, cls ? cls : "-");
}

static int flag_exists(const char *name) {
    static const char *dirs[] = {
        "/var/mobile/Documents/CacheDeleteQuiet",
        "/var/mobile/Library/Logs",
        "/var/tmp",
        "/private/var/tmp",
    };
    const char *tmp = getenv("TMPDIR");
    if (tmp && *tmp) {
        char p[512];
        int n = snprintf(p, sizeof(p), "%s/%s", tmp, name);
        if (n > 0 && n < (int)sizeof(p)) {
            struct stat st;
            if (stat(p, &st) == 0) return 1;
        }
    }
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        char p[256];
        int n = snprintf(p, sizeof(p), "%s/%s", dirs[i], name);
        if (n > 0 && n < (int)sizeof(p)) {
            struct stat st;
            if (stat(p, &st) == 0) return 1;
        }
    }
    return 0;
}

// =============================================================================
// PLAN D: arm64e __auth_got rebind
// =============================================================================

// Offsets are from the main image base (__DATA_CONST starts at +0x14000).
// Verified against reports/helper_fixups.txt (offline chained-fixups dump).
typedef struct {
    const char *name;
    uint64_t    slotOff;
    int         skip;      // 1 = QUIET short-circuits this call
} CSlot;

static const CSlot kCSlots[] = {
    { "_fast_size_directory", 0x14148, 1 },
    { "_traverse_directory",  0x14418, 1 },
    { "_statfs",              0x143D8, 0 },
};
#define CSLOT_COUNT ((int)(sizeof(kCSlots) / sizeof(kCSlots[0])))

typedef uint64_t (*fn_gen)(uint64_t, uint64_t, uint64_t, uint64_t,
                           uint64_t, uint64_t, uint64_t, uint64_t);

static void *g_origC[CSLOT_COUNT];
static unsigned long long g_hits[CSLOT_COUNT];
static unsigned long long g_skips[CSLOT_COUNT];
static int g_bound[CSLOT_COUNT];

static int cdq_should_skip(int idx) {
    return (g_mode == MODE_QUIET || g_mode == MODE_STRICT) && kCSlots[idx].skip;
}

static void cdq_cstat(int idx, unsigned long long n) {
    if (n == 0) {
        plog("CSTAT first-hit %-26s mode=%d bound=%d skipRule=%d t=%llu\n",
             kCSlots[idx].name, g_mode, g_bound[idx], kCSlots[idx].skip, now_ms());
    } else if ((n & 0x1FFULL) == 0) {
        plog("CSTAT %-26s hits=%llu skips=%llu mode=%d t=%llu\n",
             kCSlots[idx].name, (unsigned long long)(n + 1),
             (unsigned long long)g_skips[idx], g_mode, now_ms());
    }
}

#define CDQ_WRAPPER(NAME, IDX)                                                   \
static uint64_t NAME(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,       \
                     uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {     \
    unsigned long long n = __sync_fetch_and_add(&g_hits[IDX], 1ULL);           \
    cdq_cstat(IDX, n);                                                          \
    if (cdq_should_skip(IDX)) {                                                 \
        __sync_fetch_and_add(&g_skips[IDX], 1ULL);                              \
        return 0;                                                               \
    }                                                                           \
    fn_gen f = (fn_gen)g_origC[IDX];                                            \
    return f ? f(a0, a1, a2, a3, a4, a5, a6, a7) : 0;                           \
}

CDQ_WRAPPER(cdq_wrap_fast_size, 0)
CDQ_WRAPPER(cdq_wrap_traverse,  1)
CDQ_WRAPPER(cdq_wrap_statfs,    2)

static void *cdq_wrappers[CSLOT_COUNT] = {
    (void *)cdq_wrap_fast_size, (void *)cdq_wrap_traverse, (void *)cdq_wrap_statfs,
};

#if CDQ_PTRAUTH
// Pure numeric self-test: never dereferences or branches to the candidate.
// Returns WHICH discriminator dyld used (0 = unproven), value in *discOut.
static int cdq_verify_discriminator(void *signedPtr, void *slotAddr,
                                    void *stripped, uint64_t *discOut) {
    uint64_t d1 = (uint64_t)(uintptr_t)slotAddr;      // stub passes x17 = slot
    if (ptrauth_auth_data(signedPtr, ptrauth_key_asia, d1) == stripped) {
        *discOut = d1; return 1;
    }
    uint64_t d2 = (uint64_t)(uintptr_t)ptrauth_blend_discriminator(slotAddr, 0ULL);
    if (ptrauth_auth_data(signedPtr, ptrauth_key_asia, d2) == stripped) {
        *discOut = d2; return 2;
    }
    if (ptrauth_auth_data(signedPtr, ptrauth_key_asia, 0ULL) == stripped) {
        *discOut = 0ULL; return 3;
    }
    return 0;
}
#endif

// v1.1.0 BUG: _dyld_get_image_header(0) is NOT reliably the helper executable
// under roothide/ElleKit (an injected dylib can own index 0). On device the
// three slots all read raw=0x0 -> bound=0/3 -> zero CPU effect, while the
// log still said "short-circuit=YES". v1.1.1 locates the main image by NAME
// (and cross-checks with dladdr on a method IMP that lives in it), then uses
// its real load-command segment layout instead of a hard-coded assumption.
static const struct mach_header_64 *cdq_locate_image(IMP mainSym,
                                                      uint8_t **baseOut) {
    uint32_t n = _dyld_image_count();
    const struct mach_header_64 *byName = NULL, *byExec = NULL, *byAddr = NULL;
    plog("IMG count=%u\n", n);
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        const struct mach_header_64 *h =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t sl = (intptr_t)_dyld_get_image_vmaddr_slide(i);
        int hot = nm && strstr(nm, "CacheDeleteAppContainerCaches");
        if (i < 14 || hot)
            plog("IMG [%u] mh=%p slide=0x%lX %s\n", i, (void *)h,
                 (unsigned long)sl, nm ? nm : "?");
        if (hot) byName = h;
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE && !byExec)
            byExec = h;
    }
    if (mainSym) {
        Dl_info di;
        void *sym = (void *)mainSym;
#if CDQ_PTRAUTH
        sym = ptrauth_strip(sym, ptrauth_key_asia);
#endif
        memset(&di, 0, sizeof(di));
        if (dladdr(sym, &di) && di.dli_fbase) {
            byAddr = (const struct mach_header_64 *)di.dli_fbase;
            plog("IMG dladdr base=%p fname=%s sym=%s\n", di.dli_fbase,
                 di.dli_fname ? di.dli_fname : "?",
                 di.dli_sname ? di.dli_sname : "?");
        } else {
            plog("IMG dladdr MISS sym=%p\n", sym);
        }
    }
    const struct mach_header_64 *mh = byName ? byName : (byAddr ? byAddr : byExec);
    plog("IMG PICK byName=%p byDladdr=%p byExec=%p -> %p\n",
         (void *)byName, (void *)byAddr, (void *)byExec, (void *)mh);
    *baseOut = (uint8_t *)mh;
    return mh;
}

static int cdq_seg_layout(const struct mach_header_64 *mh,
                          uint64_t *textVm, uint64_t *dcVm, uint64_t *dcFile) {
    *textVm = 0; *dcVm = 0; *dcFile = 0;
    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < 8) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const void *)p;
            if (!strncmp(sg->segname, "__TEXT", 6)) *textVm = sg->vmaddr;
            else if (!strncmp(sg->segname, "__DATA_CONST", 12)) {
                *dcVm = sg->vmaddr; *dcFile = sg->fileoff;
            }
        }
        p += lc->cmdsize;
    }
    plog("SEG textVm=0x%llX dcVm=0x%llX dcFile=0x%llX\n",
         (unsigned long long)*textVm, (unsigned long long)*dcVm,
         (unsigned long long)*dcFile);
    return *textVm && *dcVm;
}

static int cdq_install_c_hooks(IMP mainSym) {
#if !CDQ_PTRAUTH
    plog("REBIND MISS ptrauth.h unavailable (not an arm64e build)\n");
    return 0;
#else
    uint8_t *base = NULL;
    const struct mach_header_64 *mh = cdq_locate_image(mainSym, &base);
    if (!mh || mh->magic != MH_MAGIC_64 || mh->cputype != CPU_TYPE_ARM64) {
        plog("REBIND MISS bad main image header\n");
        return 0;
    }
    uint64_t textVm = 0, dcVm = 0, dcFile = 0;
    int haveSeg = cdq_seg_layout(mh, &textVm, &dcVm, &dcFile);
    uint64_t segDelta = haveSeg ? (dcVm - textVm) : 0x14000ULL;
    uint64_t dcFileOff = haveSeg ? dcFile : 0x14000ULL;
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 0) pagesize = 16384;
    plog("CBASE mh=%p segDelta=0x%llX dcFile=0x%llX pagesize=%ld target=CacheDeleteAppContainerCaches\n",
         (void *)mh, (unsigned long long)segDelta,
         (unsigned long long)dcFileOff, pagesize);

    int ok = 0;
    for (int i = 0; i < CSLOT_COUNT; i++) {
        uint64_t slotDelta = segDelta + (kCSlots[i].slotOff - dcFileOff);
        void **slot = (void **)(base + slotDelta);
        uint64_t *q = (uint64_t *)slot;
        plog("SLOT [%d] %-24s addr=%p delta=0x%llX nb=[%016llX %016llX %016llX]\n",
             i, kCSlots[i].name, (void *)slot, (unsigned long long)slotDelta,
             (unsigned long long)q[-1], (unsigned long long)q[0],
             (unsigned long long)q[1]);
        void *signedPtr = *slot;
        void *stripped = ptrauth_strip(signedPtr, ptrauth_key_asia);
        uintptr_t addr = (uintptr_t)stripped;

        // Sanity: a real code pointer in a loaded image, not random data.
        if (addr < 0x100000000ULL || addr > 0x0000800000000000ULL) {
            plog("REBIND [%d] %-26s MISS slot=%p raw=0x%016llX stripped=0x%llX (not code)\n",
                 i, kCSlots[i].name, (void *)slot,
                 (unsigned long long)(uintptr_t)signedPtr,
                 (unsigned long long)addr);
            continue;
        }

        uint64_t disc = 0;
        int which = cdq_verify_discriminator(signedPtr, (void *)slot,
                                             stripped, &disc);
        if (!which) {
            plog("REBIND [%d] %-26s MISS slot=%p raw=0x%016llX stripped=0x%llX "
                 "pac-disc unverified (fail-open)\n",
                 i, kCSlots[i].name, (void *)slot,
                 (unsigned long long)(uintptr_t)signedPtr,
                 (unsigned long long)addr);
            continue;
        }

        g_origC[i] = stripped;   // original code, untouched (GOT rebind only)
        g_bound[i] = 1;

        vm_address_t page = (vm_address_t)((uintptr_t)slot & ~(uintptr_t)(pagesize - 1));
        kern_return_t kr = vm_protect(mach_task_self(), page,
                                      (vm_size_t)pagesize, 0,
                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) {
            plog("REBIND [%d] %-26s MISS vm_protect kr=%d (fail-open)\n",
                 i, kCSlots[i].name, (int)kr);
            g_origC[i] = NULL;
            g_bound[i] = 0;
            continue;
        }

        void *newSigned = ptrauth_sign_unauthenticated(
            cdq_wrappers[i], ptrauth_key_asia, disc);
        *slot = newSigned;
        (void)vm_protect(mach_task_self(), page, (vm_size_t)pagesize,
                         0, VM_PROT_READ);

        plog("REBIND [%d] %-26s OK slot=%p orig=0x%llX wrap=%p disc=%d(0x%llX) skip=%d\n",
             i, kCSlots[i].name, (void *)slot, (unsigned long long)addr,
             cdq_wrappers[i], which, (unsigned long long)disc,
             kCSlots[i].skip);
        ok++;
    }
    plog("REBIND READY bound=%d/%d mode=%d (short-circuit=%s) "
         "untouched=_CacheManagementEnumerateAssets,_CacheManagementRemove,_statfs\n",
         ok, CSLOT_COUNT, g_mode,
         (g_mode == MODE_QUIET || g_mode == MODE_STRICT) ? "YES" : "NO");
    return ok;
#endif
}

// =============================================================================
// ObjC hooks - kept as EVIDENCE ONLY. v1.0.1 proved the 99% path never calls
// them, so they now ALWAYS pass through and never change behaviour.
// =============================================================================
typedef id (*fn_enum)(id, SEL, unsigned long long, id);
typedef id (*fn_factory)(id, SEL, id, int);
typedef id (*fn_purge)(id, SEL, id, id);
typedef id (*fn_periodic)(id, SEL, id);
typedef id (*fn_prune)(id, SEL);

static IMP g_origEnum = NULL, g_origFactory = NULL, g_origPurge = NULL;
static IMP g_origPeriodic = NULL, g_origPrune = NULL;
static const char *g_enumEnc = "-";

static Class find_owner(SEL sel, int *is_meta) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return Nil;
    Class *list = (Class *)malloc(sizeof(Class) * (size_t)n);
    if (!list) return Nil;
    n = objc_getClassList(list, n);
    Class found = Nil;
    for (int i = 0; i < n && !found; i++) {
        Class c = list[i];
        if (!c) continue;
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(c, &mc);
        if (ms) {
            for (unsigned int j = 0; j < mc; j++) {
                if (sel_isEqual(method_getName(ms[j]), sel)) { found = c; *is_meta = 0; break; }
            }
            free(ms);
        }
        if (found) break;
        Class meta = object_getClass((id)c);
        if (!meta) continue;
        mc = 0;
        ms = class_copyMethodList(meta, &mc);
        if (ms) {
            for (unsigned int j = 0; j < mc; j++) {
                if (sel_isEqual(method_getName(ms[j]), sel)) { found = c; *is_meta = 1; break; }
            }
            free(ms);
        }
    }
    free(list);
    return found;
}

static int install_hook(SEL sel, IMP replacement, IMP *orig,
                        const char **encOut, char *clsOut, size_t clsCap) {
    int is_meta = 0;
    Class c = find_owner(sel, &is_meta);
    if (!c) return 0;
    Method m = is_meta ? class_getClassMethod(c, sel) : class_getInstanceMethod(c, sel);
    if (!m) return 0;
    Class target = is_meta ? object_getClass((id)c) : c;
    const char *enc = method_getTypeEncoding(m);
    *orig = method_getImplementation(m);
    *encOut = enc;
    if (clsOut && clsCap) {
        const char *nm = class_getName(c);
        strncpy(clsOut, nm ? nm : "-", clsCap - 1);
        clsOut[clsCap - 1] = 0;
    }
    class_replaceMethod(target, sel, replacement, enc);
    return 1;
}

static id hk_enum(id self, SEL _cmd, unsigned long long type, id block) {
    unsigned long long t0 = now_ms();
    id r = g_origEnum ? ((fn_enum)g_origEnum)(self, _cmd, type, block) : nil;
    log_call("enumerateBundlesOfType:block:", t0, 1, "LSApplicationWorkspace");
    return r;
}
static id hk_factory(id self, SEL _cmd, id info, int urgency) {
    unsigned long long t0 = now_ms();
    id r = g_origFactory ? ((fn_factory)g_origFactory)(self, _cmd, info, urgency) : nil;
    log_call("cacheDeleteManagedAssetsWithInfo:atUrgency:", t0, 1, "CacheDeleteManagedAssets");
    return r;
}
static id hk_purge(id self, SEL _cmd, id assets, id testObject) {
    unsigned long long t0 = now_ms();
    id r = g_origPurge ? ((fn_purge)g_origPurge)(self, _cmd, assets, testObject) : nil;
    log_call("purgeAssets:testObject:", t0, 1, "purge");
    return r;
}
static id hk_periodic(id self, SEL _cmd, id info) {
    unsigned long long t0 = now_ms();
    id r = g_origPeriodic ? ((fn_periodic)g_origPeriodic)(self, _cmd, info) : nil;
    log_call("periodic:", t0, 1, "periodic");
    return r;
}
static id hk_prune(id self, SEL _cmd) {
    unsigned long long t0 = now_ms();
    id r = g_origPrune ? ((fn_prune)g_origPrune)(self, _cmd) : nil;
    log_call("pruneContainerTmps", t0, 1, "prune");
    return r;
}

// ---- ctor -----------------------------------------------------------------
__attribute__((constructor)) static void cdq_init(void) {
    if (flag_exists("DISABLED")) return;

    g_mode = MODE_QUIET;
    if (flag_exists("PROBE_ONLY"))           g_mode = MODE_PROBE;
    else if (flag_exists("STRICT"))          g_mode = MODE_STRICT;
    else if (flag_exists("PASSTHROUGH_ALL")) g_mode = MODE_PASS;

    open_log();
    plog("START %llu build=1.1.1 plan=D mode=%d pid=%d uid=%d proc=CacheDeleteAppContainerCaches "
         "log=%s errno=[%d,%d,%d,%d] logfd=%d\n",
         now_ms(), g_mode, (int)getpid(), (int)getuid(), g_logpath,
         g_openErrno[0], g_openErrno[1], g_openErrno[2], g_openErrno[3], g_logfd);

    int ncls = objc_getClassList(NULL, 0);
    plog("DIAG classes=%d lsClass=%p cdcClass=%p tmpdir=%s\n",
         ncls, (void *)objc_getClass("LSApplicationWorkspace"),
         (void *)objc_getClass("CacheDeleteManagedAssets"),
         getenv("TMPDIR") ? getenv("TMPDIR") : "(null)");

    char cls[128];
    const char *enc = "-";
    int ok = 0;

    SEL selEnum = sel_registerName("enumerateBundlesOfType:block:");
    char enumCls[128] = "-";
    Class ls = objc_getClass("LSApplicationWorkspace");
    Method m = ls ? class_getInstanceMethod(ls, selEnum) : NULL;
    if (m) {
        strncpy(enumCls, "LSApplicationWorkspace", sizeof(enumCls) - 1);
    } else {
        int is_meta = 0;
        Class owner = find_owner(selEnum, &is_meta);
        if (owner) {
            Method om = is_meta ? class_getClassMethod(owner, selEnum)
                                : class_getInstanceMethod(owner, selEnum);
            if (om) {
                ls = is_meta ? object_getClass((id)owner) : owner;
                m = om;
                const char *nm = class_getName(owner);
                strncpy(enumCls, nm ? nm : "?", sizeof(enumCls) - 1);
                enumCls[sizeof(enumCls) - 1] = 0;
            }
        }
    }
    if (ls && m) {
        g_origEnum = method_getImplementation(m);
        g_enumEnc = method_getTypeEncoding(m);
        enc = g_enumEnc ? g_enumEnc : "-";
        class_replaceMethod(ls, selEnum, (IMP)hk_enum, g_enumEnc);
        ok = 1;
        plog("HOOK enum OK cls=%s enc=%s origIMP=%p\n", enumCls, enc, (void *)g_origEnum);
    }
    if (!ok) plog("HOOK enum MISS (no LSApplicationWorkspace impl found) enc=-\n");

    cls[0] = 0; enc = "-";
    ok = install_hook(sel_registerName("cacheDeleteManagedAssetsWithInfo:atUrgency:"),
                      (IMP)hk_factory, &g_origFactory, &enc, cls, sizeof(cls));
    plog("HOOK factory %s cls=%s enc=%s\n", ok ? "OK" : "MISS", cls, enc);

    cls[0] = 0; enc = "-";
    ok = install_hook(sel_registerName("purgeAssets:testObject:"),
                      (IMP)hk_purge, &g_origPurge, &enc, cls, sizeof(cls));
    plog("HOOK purge %s cls=%s enc=%s\n", ok ? "OK" : "MISS", cls, enc);

    cls[0] = 0; enc = "-";
    ok = install_hook(sel_registerName("periodic:"),
                      (IMP)hk_periodic, &g_origPeriodic, &enc, cls, sizeof(cls));
    plog("HOOK periodic %s cls=%s enc=%s\n", ok ? "OK" : "MISS", cls, enc);

    cls[0] = 0; enc = "-";
    ok = install_hook(sel_registerName("pruneContainerTmps"),
                      (IMP)hk_prune, &g_origPrune, &enc, cls, sizeof(cls));
    plog("HOOK prune %s cls=%s enc=%s\n", ok ? "OK" : "MISS", cls, enc);

    // PLAN D - the actual CPU fix. PASSTHROUGH_ALL skips it entirely.
    if (g_mode == MODE_PASS) {
        plog("REBIND SKIPPED mode=PASSTHROUGH_ALL (stock C behaviour)\n");
    } else {
        (void)cdq_install_c_hooks(g_origPrune);
    }

    plog("READY mode=%d enumEnc=%s log=%s (ObjC hooks are evidence-only, C rebind does the work)\n",
         g_mode, g_enumEnc ? g_enumEnc : "-", g_logpath);
}
