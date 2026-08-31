#include <jni.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/mman.h>

/**
 * v1.0's isHooked() only checked the FIRST byte of a function against
 * x86 opcodes (0xE9 near-jmp, 0xEB short-jmp, 0xCC int3). Two problems:
 *
 *   1. Almost every real Android device is ARM/ARM64, not x86, so this
 *      check was silently a no-op on the devices that matter.
 *   2. Even on x86, checking only byte 0 misses any trampoline hook
 *      placed a few bytes into the function (very common — hooking
 *      frameworks routinely preserve a short prologue before jumping).
 *
 * This version:
 *   - Branches on target architecture so it actually inspects the
 *     instruction encodings that exist on that CPU.
 *   - Inspects the first N bytes of the function, not just byte 0.
 *   - On ARM/ARM64 looks for common inline-hook patterns: LDR-to-PC /
 *     branch-to-register sequences (used by Frida's Interceptor and
 *     similar) rather than x86 opcodes that don't exist on that ISA.
 *
 * This is still a heuristic, not a proof. A careful attacker can hook
 * further into the function body, use return-oriented techniques, or
 * hook at a different layer entirely (e.g. libc/syscall level) that this
 * simple prologue scan won't see. Treat this as one signal among many
 * (see RootDetection/FridaDetection's confidence scoring on the Kotlin
 * side), not a standalone guarantee.
 */

namespace {

constexpr size_t SCAN_WINDOW = 16;

#if defined(__i386__) || defined(__x86_64__)
bool looksHookedX86(const unsigned char* ptr) {
    for (size_t i = 0; i < SCAN_WINDOW; i++) {
        unsigned char b = ptr[i];
        // near/short jmp, int3 breakpoint, or a call opcode landing
        // right at the start of the function (unusual for normal
        // compiler-generated prologues, common for trampolines).
        if (b == 0xE9 || b == 0xEB || b == 0xCC || b == 0xE8) {
            return true;
        }
    }
    return false;
}
#endif

#if defined(__arm__)
bool looksHookedArm32(const unsigned char* ptr) {
    // ARM32 inline hooks commonly overwrite the prologue with a branch
    // (B/BL, opcode bits 101x in the top nibble of the last byte for
    // A32 encoding) or an LDR PC, [PC, #-4] absolute-jump trampoline.
    // This is intentionally permissive (higher false-positive tolerance)
    // since it's combined with other signals upstream, not used alone.
    const uint32_t* instr = reinterpret_cast<const uint32_t*>(ptr);
    for (size_t i = 0; i < SCAN_WINDOW / 4; i++) {
        uint32_t word = instr[i];
        uint8_t topByte = (word >> 24) & 0xFF;
        // B/BL condition+opcode top byte patterns (0xEA/0xEB unconditional
        // branch/branch-link) appearing as the very first instruction of
        // a function is atypical for normal compiler output.
        if (topByte == 0xEA || topByte == 0xEB) {
            return true;
        }
    }
    return false;
}
#endif

#if defined(__aarch64__)
bool looksHookedArm64(const unsigned char* ptr) {
    const uint32_t* instr = reinterpret_cast<const uint32_t*>(ptr);
    for (size_t i = 0; i < SCAN_WINDOW / 4; i++) {
        uint32_t word = instr[i];
        // A64 unconditional branch (B) encoding: bits [31:26] == 000101
        uint32_t top6 = (word >> 26) & 0x3F;
        if (top6 == 0b000101) {
            return true;
        }
        // LDR (literal) loading into a register immediately followed by
        // a BR is a common trampoline shape; a lone LDR-literal at the
        // very start of a hot function is itself an anomaly worth
        // flagging as a weak signal.
        uint32_t top8 = (word >> 24) & 0xFF;
        if (top8 == 0x58) { // LDR (literal), 64-bit variant
            return true;
        }
    }
    return false;
}
#endif

bool isHooked(void* func_ptr) {
    if (func_ptr == nullptr) return false;
    const unsigned char* ptr = reinterpret_cast<const unsigned char*>(func_ptr);

#if defined(__i386__) || defined(__x86_64__)
    return looksHookedX86(ptr);
#elif defined(__arm__)
    return looksHookedArm32(ptr);
#elif defined(__aarch64__)
    return looksHookedArm64(ptr);
#else
    return false; // unknown architecture: don't guess
#endif
}

} // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_com_appshield_sdk_checks_NativeChecks_checkRootNative(JNIEnv *env, jobject thiz) {
    // Self-integrity: is this very function's own prologue hooked?
    if (isHooked(reinterpret_cast<void*>(
            &Java_com_appshield_sdk_checks_NativeChecks_checkRootNative))) {
        return JNI_TRUE;
    }

    // Native-side root signal: presence of su in common PATH-adjacent
    // locations, checked here too (independent of the Kotlin-side
    // check, so hooking one layer doesn't silence the other).
    const char* suPaths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su"
    };
    for (const char* path : suPaths) {
        if (access(path, F_OK) == 0) {
            return JNI_TRUE;
        }
    }

    return JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_appshield_sdk_checks_NativeChecks_checkFridaNative(JNIEnv *env, jobject thiz) {
    if (isHooked(reinterpret_cast<void*>(
            &Java_com_appshield_sdk_checks_NativeChecks_checkFridaNative))) {
        return JNI_TRUE;
    }

    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "frida") || strstr(line, "gum-js-loop") ||
                strstr(line, "gmain") || strstr(line, "linjector")) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
        fclose(fp);
    }
    return JNI_FALSE;
}
