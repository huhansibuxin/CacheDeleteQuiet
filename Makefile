# CacheDeleteQuiet v1.2.0 - PLAN D3 auth-GOT rebind of the whole framework-API set in
#   CacheDeleteAppContainerCaches (rootless + roothide)
# THEOS_PACKAGE_SCHEME is overridden by CI per matrix job; the ?= below is
# only the local default (never use '=' here).
export TARGET = iphone:clang:latest:16.0
export ARCHS = arm64e

THEOS_PACKAGE_SCHEME ?= rootless
export THEOS_PACKAGE_SCHEME
export _THEOS_PLATFORM_DPKG_DEB_COMPRESSION = gzip

TWEAK_NAME = CacheDeleteQuiet
CacheDeleteQuiet_FILES = Tweak.xm

# ZERO substrate/ellekit LINK dependency. This is a launchd XPC helper: a
# dylib referencing libellekit can fail to dlopen silently (proven on
# keybagd / aggregated). We use only __attribute__((constructor)),
# objc/runtime class_replaceMethod, mach vm_protect and ptrauth builtins -
# no Logos, no inline-patch API. No Foundation / UIKit / sqlite link either.
# arm64e is REQUIRED: the plan-D rebind relies on __ptrauth.h builtins.
CacheDeleteQuiet_LDFLAGS = -Wl,-dead_strip_dylibs
CacheDeleteQuiet_CFLAGS = -Os -fno-objc-arc
ERROR_ON_WARNINGS = 0

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
