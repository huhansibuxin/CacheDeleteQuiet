// CacheDeleteQuiet v1.0.1 - QUIET (diagnostic + filter), arm64e / rootless+roothide
// v1.0.1: logger rewritten to the PowerlogProbe v0.9.0 method. v1.0.0 used a
//   single hard-coded /var/mobile/Documents/CacheDeleteQuiet/quiet.log; this
//   launchd XPC helper is sandboxed and could not create that directory, so
//   g_logfd stayed -1 and EVERY plog() was a silent no-op. The hooks were
//   installed but there was no evidence at all. Now we try several writable
//   candidates in order (incl. /var/tmp and $TMPDIR) and record the errno of
//   each failed one in the START line.
// =============================================================================
// Target process : CacheDeleteAppContainerCaches
//   /System/Library/CacheDelete/CacheDeleteAppContainerCaches (96 KB helper)
//   This is NOT the `deleted` daemon. It is the XPC service that actually
//   enumerates every installed app container and recursively stats caches.
//
// Why a tweak (and NOT a daemon disable / plist patch)
//   Disabling the Mach service makes other apps fail to launch (observed on
//   device), so the process MUST stay alive and MUST keep answering XPC.
//   CACHE_DELETE_DO_NOT_QUERY=True only gates the query built by `deleted`;
//   clients that talk to this helper directly still trigger a full rescan.
//   This tweak leaves the process, the XPC listener and all callbacks intact,
//   and only short-circuits the expensive *estimation* path in-process.
//
// Offline disassembly evidence (reports/helper_xref.txt, 2026-11-14)
//   3 independent paths inside the helper:
//     [A] purgeable ESTIMATION  <-- the 80-99% CPU
//         0x1000094F4  -[LSApplicationWorkspace enumerateBundlesOfType:block:]
//                        + _fetchAllPersonas + UIBackgroundModes + isContainerized
//         0x100003A4C  dataContainerURL x2 / groupContainerURLs /
//                        _fast_size_directory x3 (recursive stat of every cache)
//         0x10000699C  cacheDeleteManagedAssetsWithInfo:atUrgency: (factory,
//                        called exactly ONCE, from the XPC estimation callback)
//     [B] real PURGE (keep!)
//         0x1000052C4  purgeAssets:testObject: -> sizeEligibleAsset: ->
//                        sortAssets: -> dispatch_group_async
//         uses _CacheManagementEnumerateAssets, NOT enumerateBundlesOfType:
//     [C] PERIODIC / tmp pruning (keep!)
//         0x100005A10  periodic: -> _CacheManagementRemove
//         0x10000B5BC  pruneContainerTmps -> pruneDir:bundleID: ->
//                        _traverse_directory / _rmdir
//   => [A] and [B]/[C] do not share an entry point. Short-circuiting [A]
//      cannot break real cleanup.
//
// What QUIET does (default)
//   Hooks ONLY -[LSApplicationWorkspace enumerateBundlesOfType:block:] inside
//   this one process and returns immediately WITHOUT invoking the caller's
//   block. The estimation therefore sees zero app bundles -> zero container
//   stat / zero _fast_size_directory / zero sorting. Apple's own code already
//   has to tolerate "zero bundles enumerated" (fresh device, no persona,
//   no permission), so the resulting CacheDeleteManagedAssets object and the
//   XPC reply dictionary are still fully well-formed -- they just report a
//   tiny purgeable amount, exactly like the already-verified DO_NOT_QUERY
//   plist did (17.5 h soak: 26 purgeable requests, service skipped, no
//   app launch failures).
//   Everything else passes through to the original IMP untouched.
//
// Modes (empty flag files, checked ONCE in ctor, then kickstart -k)
//   (none)              QUIET      - short-circuit [A], log timings  [default]
//   PROBE_ONLY          probe      - 100% passthrough + timings (A/B/C)
//   STRICT              strict     - QUIET + also skip the estimation factory
//                                    (EXPERIMENTAL, may return nil)
//   PASSTHROUGH_ALL     pass       - all hooks inert, stock behaviour
//   DISABLED            off        - no hooks installed at all
//   Log (v1.0.1, PowerlogProbe-style fallback - first writable one wins):
//     /var/mobile/Documents/CacheDeleteQuiet/quiet.log
//     /var/mobile/Library/Logs/CacheDeleteQuiet.log
//     /var/tmp/CacheDeleteQuiet.log
//     /private/var/tmp/CacheDeleteQuiet.log
//   From SSH prepend /rootfs/private, e.g.
//     /rootfs/private/var/tmp/CacheDeleteQuiet.log
//   The START line always prints the path that actually opened, plus errno
//   for every candidate that failed. Flags may be dropped in ANY of those dirs.
//
// HARD CONSTRAINTS (same discipline as PowerlogProbe 1.3.0 RELEASE)
//   - ZERO Logos %hook / ZERO substrate / ZERO ellekit LINK dependency.
//     A launchd XPC helper can fail to dlopen a dylib that references
//     libellekit; dead-strip + pure objc/runtime is the only safe route.
//   - NO Foundation / UIKit link; everything via objc_msgSend + libSystem.
//   - NO polling / timer / dispatch_after. Event-driven only.
//   - Fail-open: if a class or method is missing, nothing is hooked.
//   - Hook replacements always declare `id` return. On arm64 the caller
//     ignores x0 for void methods; for id/int methods the original x0 value
//     is passed straight back. Extra arguments stay in x2..x7 untouched.
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

// PowerlogProbe v0.9.0 proved this ordering works on a sandboxed launchd
// daemon: try several candidates, ignore mkdir failure, take the first fd
// that opens. /var/tmp is world-writable and is the reliable fallback.
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

// Kept alive so CI can assert the exact build that was packaged.
static const char kBuildTag[] __attribute__((used)) =
    "CacheDeleteQuiet 1.0.1 QUIET diag+filter no-substrate fallback-log";

enum { MODE_OFF = 0, MODE_QUIET = 1, MODE_PROBE = 2, MODE_STRICT = 3, MODE_PASS = 4 };

static int g_mode = MODE_QUIET;
static int g_logfd = -1;
static const char *g_logpath = "(none)";
static int g_openErrno[4] = {0, 0, 0, 0};
static unsigned long long g_seq = 0;
static const char *g_enumEnc = "-";

// ---- original IMPs --------------------------------------------------------
typedef id (*fn_enum)(id, SEL, unsigned long long, id);
typedef id (*fn_factory)(id, SEL, id, int);
typedef id (*fn_purge)(id, SEL, id, id);
typedef id (*fn_periodic)(id, SEL, id);
typedef id (*fn_prune)(id, SEL);

static IMP g_origEnum = NULL;
static IMP g_origFactory = NULL;
static IMP g_origPurge = NULL;
static IMP g_origPeriodic = NULL;
static IMP g_origPrune = NULL;

// ---- tiny libSystem-only logger -------------------------------------------
static unsigned long long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, 0);
    return (unsigned long long)tv.tv_sec * 1000ULL + (unsigned long long)(tv.tv_usec / 1000);
}

// PowerlogProbe v0.9.0 method: open(2)/write(2) only, no stdio buffering,
// with a real timestamp so spikes can be matched against htop samples.
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
    // Sandboxed launchd helpers normally get a private TMPDIR that is ALWAYS
    // writable even when /var/mobile/Documents and /var/tmp are blocked.
    // Try it first, then the PowerlogProbe candidate list.
    const char *tmp = getenv("TMPDIR");
    if (tmp && *tmp) {
        int n = snprintf(g_dynLog, sizeof(g_dynLog), "%s/CacheDeleteQuiet.log", tmp);
        if (n > 0 && n < (int)sizeof(g_dynLog)) {
            int fd = open(g_dynLog, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd >= 0) {
                g_logfd = fd;
                g_logpath = g_dynLog;
                return;
            }
        }
    }
    for (size_t i = 0; i < kCandCount; i++) {
        (void)mkdir(kLogDirs[i], 0755);
        int fd = open(kLogCandidates[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            g_logfd = fd;
            g_logpath = kLogCandidates[i];
            return;
        }
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

// A flag may be dropped in any of the writable dirs; check all of them so
// mode switches keep working even when Documents is sandbox-blocked.
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

// ---- find the one class in this process that implements a selector --------
// We deliberately do not hardcode Apple's internal class names: a minor OS
// build may rename them. class_copyMethodList returns only methods the class
// itself implements (no inheritance), which keeps the search precise.
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

// Returns 1 on success; writes owner class name and type encoding.
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

// ---- hook implementations -------------------------------------------------
// [A] the expensive full-disk enumeration. QUIET / STRICT skip it entirely.
// Returning nil is safe for void (x0 ignored), BOOL/int (0) and id (nil).
static id hk_enum(id self, SEL _cmd, unsigned long long type, id block) {
    unsigned long long t0 = now_ms();
    if (g_mode == MODE_QUIET || g_mode == MODE_STRICT) {
        log_call("enumerateBundlesOfType:block:", t0, 0, "LSApplicationWorkspace");
        return nil;
    }
    id r = g_origEnum ? ((fn_enum)g_origEnum)(self, _cmd, type, block) : nil;
    log_call("enumerateBundlesOfType:block:", t0, 1, "LSApplicationWorkspace");
    return r;
}

// [A] estimation factory, called once per XPC purgeable request.
// STRICT additionally skips it; QUIET keeps it (so the reply object stays
// fully constructed by Apple's own code, just with an empty asset list).
static id hk_factory(id self, SEL _cmd, id info, int urgency) {
    unsigned long long t0 = now_ms();
    if (g_mode == MODE_STRICT) {
        log_call("cacheDeleteManagedAssetsWithInfo:atUrgency:", t0, 0, "CacheDeleteManagedAssets");
        return nil;
    }
    id r = g_origFactory ? ((fn_factory)g_origFactory)(self, _cmd, info, urgency) : nil;
    log_call("cacheDeleteManagedAssetsWithInfo:atUrgency:", t0, 1, "CacheDeleteManagedAssets");
    return r;
}

// [B] real PURGE - ALWAYS passthrough, timing only.
static id hk_purge(id self, SEL _cmd, id assets, id testObject) {
    unsigned long long t0 = now_ms();
    id r = g_origPurge ? ((fn_purge)g_origPurge)(self, _cmd, assets, testObject) : nil;
    log_call("purgeAssets:testObject:", t0, 1, "purge");
    return r;
}

// [C] periodic cleanup - ALWAYS passthrough, timing only.
static id hk_periodic(id self, SEL _cmd, id info) {
    unsigned long long t0 = now_ms();
    id r = g_origPeriodic ? ((fn_periodic)g_origPeriodic)(self, _cmd, info) : nil;
    log_call("periodic:", t0, 1, "periodic");
    return r;
}

// [C] container tmp pruning - ALWAYS passthrough, timing only.
static id hk_prune(id self, SEL _cmd) {
    unsigned long long t0 = now_ms();
    id r = g_origPrune ? ((fn_prune)g_origPrune)(self, _cmd) : nil;
    log_call("pruneContainerTmps", t0, 1, "prune");
    return r;
}

// ---- ctor -----------------------------------------------------------------
__attribute__((constructor)) static void cdq_init(void) {
    if (flag_exists("DISABLED")) return;                  // no hooks at all

    g_mode = MODE_QUIET;
    if (flag_exists("PROBE_ONLY"))       g_mode = MODE_PROBE;
    else if (flag_exists("STRICT"))      g_mode = MODE_STRICT;
    else if (flag_exists("PASSTHROUGH_ALL")) g_mode = MODE_PASS;

    open_log();
    plog("START %llu build=1.0.1 mode=%d pid=%d uid=%d proc=CacheDeleteAppContainerCaches log=%s "
         "errno=[%d,%d,%d,%d] logfd=%d\n",
         now_ms(), g_mode, (int)getpid(), (int)getuid(), g_logpath,
         g_openErrno[0], g_openErrno[1], g_openErrno[2], g_openErrno[3], g_logfd);

    // Runtime inventory: distinguishes "dylib not injected" (no START at all)
    // from "class not loaded" / "selector does not exist".
    int ncls = objc_getClassList(NULL, 0);
    plog("DIAG classes=%d lsClass=%p cdcClass=%p tmpdir=%s\n",
         ncls, (void *)objc_getClass("LSApplicationWorkspace"),
         (void *)objc_getClass("CacheDeleteManagedAssets"),
         getenv("TMPDIR") ? getenv("TMPDIR") : "(null)");

    char cls[128];
    const char *enc = "-";
    int ok = 0;

    // The single most important hook: full-disk app enumeration.
    // Only touch LSApplicationWorkspace in THIS process; the Filter plist
    // guarantees no other process ever loads this dylib.
    SEL selEnum = sel_registerName("enumerateBundlesOfType:block:");
    char enumCls[128] = "-";
    Class ls = objc_getClass("LSApplicationWorkspace");
    Method m = ls ? class_getInstanceMethod(ls, selEnum) : NULL;
    if (m) {
        strncpy(enumCls, "LSApplicationWorkspace", sizeof(enumCls) - 1);
    } else {
        // Do not assume the owner class: scan every loaded class (incl. meta)
        // for an implementation of this selector. A category / subclass would
        // otherwise leave the single most important hook silently unhooked.
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
        plog("HOOK enum OK cls=%s enc=%s origIMP=%p\n",
             enumCls, enc, (void *)g_origEnum);
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

    plog("READY mode=%d enumEnc=%s log=%s\n", g_mode, g_enumEnc ? g_enumEnc : "-", g_logpath);
}
