/*
 * SIGSEGV signal handler for anti-hook detection bypass.
 *
 * Background:
 *   The packer (BangBang/梆梆) detects Xposed by checking stack traces from native
 *   code. When Xposed is detected, the packer deliberately crashes with a null-pointer
 *   dereference (fault addr 0x88c = NULL + struct field offset).
 *
 * Strategy:
 *   Install a process-wide SIGSEGV handler. When the fault address falls within the
 *   null page (< 0x1000), simulate a function return by setting PC to the link register
 *   (LR / X30) and X0 to 0. This makes the crashing function return immediately with
 *   null, allowing the caller to handle the "error" gracefully instead of killing the
 *   process.
 *
 *   For all other SIGSEGV (non-null-page), chain to the previous handler.
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
     * These are null-pointer dereferences with a struct field offset —
     * exactly the crash pattern from packer's deliberate kill mechanism.
     */
    if (fault_addr >= 0x1000) {
        chain_old_handler(sig, info, ucontext);
        return;
    }

#if defined(__aarch64__)
    ucontext_t *ctx = (ucontext_t *)ucontext;
    uint64_t lr = ctx->uc_mcontext.regs[30]; /* X30 = Link Register */
    uint64_t old_pc = ctx->uc_mcontext.pc;

    if (lr == 0 || lr < 0x1000) {
        /* LR is invalid (null or in null page) — can't safely return. */
        LOGW("Cannot recover: LR=0x%lx, chaining to old handler", (unsigned long)lr);
        chain_old_handler(sig, info, ucontext);
        return;
    }

    /* Simulate function return: set PC to LR, return 0 in X0 */
    ctx->uc_mcontext.pc = lr;
    ctx->uc_mcontext.regs[0] = 0;  /* Return null / 0 */

    LOGI("Recovered SIGSEGV at 0x%lx (PC was 0x%lx, returning to LR=0x%lx)",
         (unsigned long)fault_addr, (unsigned long)old_pc, (unsigned long)lr);
#else
    /* Non-ARM64: can't safely recover */
    chain_old_handler(sig, info, ucontext);
#endif
}

JNIEXPORT void JNICALL
Java_com_lptiyu_tanke_hook_NativeHelper_nativeInstallHandler(JNIEnv *env, jclass clazz) {
    if (handler_installed) return;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, &old_sa) == 0) {
        handler_installed = 1;
        LOGI("SIGSEGV handler installed successfully");
    } else {
        LOGW("Failed to install SIGSEGV handler");
    }
}
