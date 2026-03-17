package com.lptiyu.tanke.hook

import android.content.pm.ApplicationInfo
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import java.lang.reflect.Field

/**
 * Zygote 阶段安装的栈帧伪装 Hook 模块。
 *
 * 包含 7 个 Hook：
 *  0. Unsafe.allocateInstance — 标记幽灵 LoadedApk
 *  1. LoadedApk.createOrUpdateClassLoaderLocked — 拦截幽灵对象
 *  2. StackTraceElement.getClassName / getMethodName / toString — 清洗类名
 *  3. Throwable.getStackTrace — 整体栈帧清洗
 *  4. Thread.getStackTrace — 整体栈帧清洗
 *  5. Thread.getAllStackTraces — 整体栈帧清洗
 *  6. VMStack.getThreadStackTrace — JNI 绕过兜底
 *
 * 由 [MainHook.initZygote] 调用，仅在 [HookPrefs.fakeStack] 为 true 时执行。
 */
object StackTraceHooks {

    private const val GHOST_MARKER = "\$\$ghost_detect\$\$"

    /** 防止 afterHookedMethod 内部递归触发相同 hook */
    private val isProcessing: ThreadLocal<Boolean> = ThreadLocal.withInitial { false }

    private val declClassField: Field? by lazy {
        try {
            StackTraceElement::class.java.getDeclaredField("declaringClass")
                .apply { isAccessible = true }
        } catch (_: Throwable) { null }
    }

    private val methodNameField: Field? by lazy {
        try {
            StackTraceElement::class.java.getDeclaredField("methodName")
                .apply { isAccessible = true }
        } catch (_: Throwable) { null }
    }

    // ─── Public entry point ─────────────────────────────────────────────

    fun installZygote() {
        installUnsafeHook()
        installGhostInterceptor()
        installStackTraceElementHooks()
        installThrowableGetStackTraceHook()
        installThreadGetStackTraceHook()
        installThreadGetAllStackTracesHook()
        installVMStackHook()
    }

    // ─── Detection / sanitize helpers ──────────────────────────────────

    private fun isSuspiciousClassName(className: String): Boolean {
        val lower = className.lowercase()
        if (lower.contains("xposed")) return true
        if (lower.contains("lsposed")) return true
        if (lower.contains("lspd")) return true
        if (lower.contains("sandhook")) return true
        if (lower.contains("epic")) return true
        if (lower.contains("pine")) return true
        if (className.endsWith(".HookBridge") || className == "HookBridge") return true
        if (className.startsWith("LSPHooker")) return true
        return false
    }

    private fun isSuspiciousFrame(element: StackTraceElement): Boolean {
        val className = element.className
        val methodName = element.methodName
        if (isSuspiciousClassName(className)) return true
        if (className.length <= 2 && methodName == "callback") return true
        if (methodName == "invokeOriginalMethod") return true
        if (methodName == "handleHookedMethod") return true
        return false
    }

    private fun sanitizeElements(elements: Array<StackTraceElement>) {
        val field = declClassField ?: return
        for (element in elements) {
            try {
                val cls = field.get(element) as? String ?: continue
                if (isSuspiciousClassName(cls)) {
                    field.set(element, "android.os.Handler")
                    methodNameField?.set(element, "dispatchMessage")
                }
            } catch (_: Throwable) {}
        }
    }

    private fun cleanAndSanitize(elements: Array<StackTraceElement>): Array<StackTraceElement>? {
        if (elements.isEmpty()) return null
        var needsScrubbing = false
        for (element in elements) {
            if (isSuspiciousFrame(element)) { needsScrubbing = true; break }
        }
        if (!needsScrubbing) return null

        val clean = mutableListOf<StackTraceElement>()
        var skipNextMethodInvoke = false
        for (element in elements) {
            if (isSuspiciousFrame(element)) { skipNextMethodInvoke = true; continue }
            if (skipNextMethodInvoke &&
                element.className == "java.lang.reflect.Method" &&
                element.methodName == "invoke") {
                skipNextMethodInvoke = false; continue
            }
            skipNextMethodInvoke = false
            clean.add(element)
        }
        val result = clean.toTypedArray()
        sanitizeElements(result)
        return result
    }

    // ─── Hook 0: Unsafe.allocateInstance ────────────────────────────────

    private fun installUnsafeHook() {
        try {
            val unsafeClass = Class.forName("sun.misc.Unsafe")
            val allocMethod = unsafeClass.getDeclaredMethod("allocateInstance", Class::class.java)
            XposedBridge.hookMethod(allocMethod, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val result = param.result ?: return
                    if (result.javaClass.name != "android.app.LoadedApk") return
                    try {
                        XposedHelpers.setObjectField(result, "mPackageName", GHOST_MARKER)
                        val appInfo = ApplicationInfo().also {
                            it.packageName = GHOST_MARKER
                            it.processName = GHOST_MARKER
                            it.sourceDir = "/dev/null"
                            it.dataDir = "/dev/null"
                            it.nativeLibraryDir = "/dev/null"
                            it.targetSdkVersion = 34
                        }
                        XposedHelpers.setObjectField(result, "mApplicationInfo", appInfo)
                    } catch (_: Throwable) {}
                }
            })
            XposedBridge.log("TankeHook: Hooked Unsafe.allocateInstance")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Unsafe hook failed: ${e.message}")
        }
    }

    // ─── Hook 1: LoadedApk.createOrUpdateClassLoaderLocked ──────────────

    private fun installGhostInterceptor() {
        try {
            val loadedApkClass = XposedHelpers.findClass("android.app.LoadedApk", null)
            val method = XposedHelpers.findMethodExact(
                loadedApkClass, "createOrUpdateClassLoaderLocked", List::class.java
            )
            XposedBridge.hookMethod(method, object : XC_MethodHook(10000) {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        val pkg = XposedHelpers.getObjectField(param.thisObject, "mPackageName")
                        if (pkg == null || pkg == GHOST_MARKER) {
                            param.throwable = NullPointerException(
                                "Attempt to invoke virtual method on a null object reference"
                            )
                        }
                    } catch (_: Throwable) {
                        param.throwable = NullPointerException(
                            "Attempt to invoke virtual method on a null object reference"
                        )
                    }
                }
            })
            XposedBridge.log("TankeHook: Hooked createOrUpdateClassLoaderLocked")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: GhostInterceptor hook failed: ${e.message}")
        }
    }

    // ─── Hook 2: StackTraceElement getClassName / getMethodName / toString

    private fun installStackTraceElementHooks() {
        try {
            val m = StackTraceElement::class.java.getDeclaredMethod("getClassName")
            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val name = param.result as? String ?: return
                    if (isSuspiciousClassName(name)) param.result = "android.os.Handler"
                }
            })
            XposedBridge.log("TankeHook: Hooked StackTraceElement.getClassName()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: StackTraceElement.getClassName hook failed: ${e.message}")
        }

        try {
            val m = StackTraceElement::class.java.getDeclaredMethod("toString")
            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val str = param.result as? String ?: return
                    val lc = str.lowercase()
                    if (lc.contains("xposed") || lc.contains("lsposed") ||
                        lc.contains("hookbridge") || lc.contains("lsphooker")) {
                        param.result = "android.os.Handler.dispatchMessage(Handler.java:106)"
                    }
                }
            })
            XposedBridge.log("TankeHook: Hooked StackTraceElement.toString()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: StackTraceElement.toString hook failed: ${e.message}")
        }

        try {
            val m = StackTraceElement::class.java.getDeclaredMethod("getMethodName")
            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val name = param.result as? String ?: return
                    if (name == "handleHookedMethod" || name == "invokeOriginalMethod" || name == "callback") {
                        param.result = "dispatchMessage"
                    }
                }
            })
            XposedBridge.log("TankeHook: Hooked StackTraceElement.getMethodName()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: StackTraceElement.getMethodName hook failed: ${e.message}")
        }
    }

    // ─── Hook 3: Throwable.getStackTrace() ──────────────────────────────

    private fun installThrowableGetStackTraceHook() {
        try {
            val m = Throwable::class.java.getDeclaredMethod("getStackTrace")
            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (isProcessing.get()) return
                    isProcessing.set(true)
                    try {
                        @Suppress("UNCHECKED_CAST")
                        val elements = param.result as? Array<StackTraceElement> ?: return
                        val cleaned = cleanAndSanitize(elements) ?: return
                        param.result = cleaned
                        try { (param.thisObject as? Throwable)?.stackTrace = cleaned } catch (_: Throwable) {}
                    } finally { isProcessing.set(false) }
                }
            })
            XposedBridge.log("TankeHook: Hooked Throwable.getStackTrace()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Throwable.getStackTrace hook failed: ${e.message}")
        }
    }

    // ─── Hook 4: Thread.getStackTrace() ─────────────────────────────────

    private fun installThreadGetStackTraceHook() {
        try {
            val m = Thread::class.java.getDeclaredMethod("getStackTrace")
            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (isProcessing.get()) return
                    isProcessing.set(true)
                    try {
                        @Suppress("UNCHECKED_CAST")
                        val elements = param.result as? Array<StackTraceElement> ?: return
                        val cleaned = cleanAndSanitize(elements) ?: return
                        param.result = cleaned
                    } finally { isProcessing.set(false) }
                }
            })
            XposedBridge.log("TankeHook: Hooked Thread.getStackTrace()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Thread.getStackTrace hook failed: ${e.message}")
        }
    }

    // ─── Hook 5: Thread.getAllStackTraces() ──────────────────────────────

    private fun installThreadGetAllStackTracesHook() {
        try {
            val m = Thread::class.java.getDeclaredMethod("getAllStackTraces")
            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                @Suppress("UNCHECKED_CAST")
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (isProcessing.get()) return
                    isProcessing.set(true)
                    try {
                        val map = param.result as? Map<Thread, Array<StackTraceElement>> ?: return
                        var changed = false
                        val cleaned = LinkedHashMap<Thread, Array<StackTraceElement>>(map.size)
                        for ((thread, elements) in map) {
                            val c = cleanAndSanitize(elements)
                            if (c != null) { cleaned[thread] = c; changed = true } else cleaned[thread] = elements
                        }
                        if (changed) param.result = cleaned
                    } finally { isProcessing.set(false) }
                }
            })
            XposedBridge.log("TankeHook: Hooked Thread.getAllStackTraces()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Thread.getAllStackTraces hook failed: ${e.message}")
        }
    }

    // ─── Hook 6: VMStack.getThreadStackTrace() ───────────────────────────

    private fun installVMStackHook() {
        try {
            val vmStackClass = XposedHelpers.findClass("dalvik.system.VMStack", null)
            val m = vmStackClass.getDeclaredMethod("getThreadStackTrace", Thread::class.java)
            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (isProcessing.get()) return
                    isProcessing.set(true)
                    try {
                        @Suppress("UNCHECKED_CAST")
                        val elements = param.result as? Array<StackTraceElement> ?: return
                        val cleaned = cleanAndSanitize(elements)
                        if (cleaned != null) param.result = cleaned
                        else sanitizeElements(elements)
                    } finally { isProcessing.set(false) }
                }
            })
            XposedBridge.log("TankeHook: Hooked VMStack.getThreadStackTrace()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: VMStack hook failed: ${e.message}")
        }
    }
}
