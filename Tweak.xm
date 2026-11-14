// CacheDeleteQuiet v1.0.0 - QUIET (diagnostic + filter), arm64e / rootless+roothide
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
//   Log: /var/mobile/Documents/CacheDeleteQuiet/quiet.log
//   From SSH this is /rootfs/private/var/mobile/Documents/CacheDeleteQuiet/quiet.log
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
#import <sys/stat.h>
#import <sys/time.h>

#define kDir            "/var/mobile/Documents/CacheDeleteQuiet"
#define kLog            kDir "/quiet.log"
#define kFlagOff        kDir "/DISABLED"
#define kFlagPass       kDir "/PASSTHROUGH_ALL"
#define kFlagProbe      kDir "/PROBE_ONLY"
#define kFlagStrict     kDir "/STRICT"

// Kept alive so CI can assert the exact build that was packaged.
static const char kBuildTag[] __attribute__((used)) =
    "CacheDeleteQuiet 1.0.0 QUIET diag+filter no-substrate";

enum { MODE_OFF = 0, MODE_QUIET = 1, MODE_PROBE = 2, MODE_STRICT = 3, MODE_PASS = 4 };

static int g_mode = MODE_QUIET;
static int g_logfd = -1;
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

static void plog(const char *fmt, ...) {
    if (g_logfd < 0) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) (void)write(g_logfd, buf, (size_t)(n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1));
}

static void log_call(const char *name, unsigned long long t0, int pass, const char *cls) {
    unsigned long long dt = now_ms() - t0;
    unsigned long long seq = __sync_fetch_and_add(&g_seq, 1ULL);
    plog("%llu seq=%llu mode=%d pid=%d %-46s %-4s %llums cls=%s\n",
         now_ms(), seq, g_mode, (int)getpid(), name,
         pass ? "PASS" : "SKIP", dt, cls ? cls : "-");
}

static int flag_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
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
    if (flag_exists(kFlagOff)) return;                     // no hooks at all

    g_mode = MODE_QUIET;
    if (flag_exists(kFlagProbe))       g_mode = MODE_PROBE;
    else if (flag_exists(kFlagStrict)) g_mode = MODE_STRICT;
    else if (flag_exists(kFlagPass))   g_mode = MODE_PASS;

    (void)mkdir(kDir, 0755);
    g_logfd = open(kLog, O_WRONLY | O_CREAT | O_APPEND, 0644);
    plog("START %llu build=1.0.0 mode=%d pid=%d proc=CacheDeleteAppContainerCaches\n",
         now_ms(), g_mode, (int)getpid());

    char cls[128];
    const char *enc = "-";
    int ok = 0;

    // The single most important hook: full-disk app enumeration.
    // Only touch LSApplicationWorkspace in THIS process; the Filter plist
    // guarantees no other process ever loads this dylib.
    Class ls = objc_getClass("LSApplicationWorkspace");
    SEL selEnum = sel_registerName("enumerateBundlesOfType:block:");
    if (ls) {
        Method m = class_getInstanceMethod(ls, selEnum);
        if (m) {
            g_origEnum = method_getImplementation(m);
            g_enumEnc = method_getTypeEncoding(m);
            enc = g_enumEnc ? g_enumEnc : "-";
            class_replaceMethod(ls, selEnum, (IMP)hk_enum, g_enumEnc);
            ok = 1;
            plog("HOOK enum OK cls=LSApplicationWorkspace enc=%s\n", enc);
        }
    }
    if (!ok) plog("HOOK enum MISS cls=LSApplicationWorkspace\n");

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

    plog("READY mode=%d enumEnc=%s log=%s\n", g_mode, g_enumEnc ? g_enumEnc : "-", kLog);
}
