/*
 * SIGSEGV signal handler for ghost-object detection bypass.
 *
 * Background:
 *   The packer creates "ghost" objects via Unsafe.allocateInstance or JNI AllocObject
 *   (all fields are NULL), then calls a method that LSPosed has hooked. LSPosed's
 *   native bridge dereferences a NULL field pointer, causing SIGSEGV at a low address
 *   (typically 0x88c = NULL + ApplicationInfo field offset).
 *
 * Strategy:
 *   Install a process-wide SIGSEGV handler. When the fault address falls within the
 *   first page (< 0x1000), it's a null-pointer dereference — we decode the faulting
 *   ARM64 instruction, zero the destination register, and advance PC past it. This
 *   turns a fatal crash into a silent "load null" that the Java/bridge code can handle.
 *
 *   For all other SIGSEGV (non-null-page), we chain to the previous handler so that
 *   real crashes are still reported normally.
 */

#include <jni.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <android/log.h>

#if defined(__aarch64__)
#include <ucontext.h>
#endif

#define TAG "TankeHook-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

/* Previous handler, so we can chain for non-ghost crashes */
static struct sigaction old_sa;
static volatile int handler_installed = 0;

/*
 * Per-thread consecutive-catch counter.
 * If we catch too many SIGSEGV on the same thread in rapid succession,
 * we stop catching to avoid infinite skip loops.
 */
static __thread int catch_count = 0;
#define MAX_CATCHES_PER_THREAD 64

static void chain_old_handler(int sig, siginfo_t *info, void *ucontext) {
    if (old_sa.sa_flags & SA_SIGINFO) {
        if (old_sa.sa_sigaction) {
            old_sa.sa_sigaction(sig, info, ucontext);
            return;
        }
    }
    if (old_sa.sa_handler != SIG_DFL && old_sa.sa_handler != SIG_IGN) {
        old_sa.sa_handler(sig);
        return;
    }
    /* No previous handler — restore default and re-raise */
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}

static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    uintptr_t fault_addr = (uintptr_t)info->si_addr;

    /*
     * Only intercept null-page accesses (address < 4 KB).
     * These are null-pointer dereferences with a struct field offset,
     * which is exactly what the ghost object detection triggers.
     */
    if (fault_addr >= 0x1000 || catch_count >= MAX_CATCHES_PER_THREAD) {
        catch_count = 0;
        chain_old_handler(sig, info, ucontext);
        return;
    }

#if defined(__aarch64__)
    ucontext_t *ctx = (ucontext_t *)ucontext;

    /*
     * Decode the faulting ARM64 instruction to find the destination register.
     * For LDR Xt, [Xn, #imm] and similar load variants, Rt is in bits [4:0].
     * For STR, bits [4:0] is the source register — zeroing it is harmless.
     */
    uint64_t pc = ctx->uc_mcontext.pc;
    uint32_t insn = *(uint32_t *)pc;
    int rt = insn & 0x1F;

    /* Zero the destination register (X0-X30); skip if SP (31) */
    if (rt < 31) {
        ctx->uc_mcontext.regs[rt] = 0;
    }

    /* Advance past the faulting instruction (ARM64 = fixed 4 bytes) */
    ctx->uc_mcontext.pc = pc + 4;
    catch_count++;

    LOGI("Recovered SIGSEGV at 0x%lx (insn=%08x, zeroed X%d, catch #%d)",
         (unsigned long)fault_addr, insn, rt, catch_count);
#else
    /* Non-ARM64: can't safely recover, chain to old handler */
    chain_old_handler(sig, info, ucontext);
#endif
}

JNIEXPORT void JNICALL
Java_com_lptiyu_tanke_hook_NativeHelper_nativeInstallHandler(JNIEnv *env, jclass clazz) {
    if (handler_installed) return;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags     = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, &old_sa) == 0) {
        handler_installed = 1;
        LOGI("SIGSEGV handler installed successfully");
    } else {
        LOGW("Failed to install SIGSEGV handler");
    }
}
