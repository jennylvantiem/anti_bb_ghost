package com.lptiyu.tanke.hook

import android.content.pm.ApplicationInfo
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

class MainHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    companion object {
        private var isBypassed = false

        /**
         * 幽灵对象标记。通过 Unsafe.allocateInstance 创建的 LoadedApk
         * 会被打上此标记，后续 hook 据此识别并拦截。
         */
        private const val GHOST_MARKER = "\$\$ghost_detect\$\$"

        /**
         * 重入锁：防止 getStackTrace() hook 内部触发递归调用
         */
        private val isProcessing = ThreadLocal.withInitial { false }

        /**
         * 判断单个栈帧是否属于 hook 框架的痕迹。
         * 涵盖 LSPosed、Xposed、EdXposed、SandHook、Pine 等主流框架。
         */
        private fun isSuspiciousFrame(element: StackTraceElement): Boolean {
            val className = element.className
            val methodName = element.methodName

            // 主流 hook 框架的明文类名特征
            if (className.contains("org.lsposed") ||
                className.contains("de.robv.android.xposed") ||
                className.contains("LSPHooker") ||
                className.contains("com.elder.xposed") ||
                className.contains("SandHook") ||
                className.contains("EdXposed") ||
                className.contains("me.weishu.epic") ||
                className.contains("top.canyie.pine") ||
                className.contains("com.swift.sandhook") ||
                className.contains("lspd")
            ) {
                return true
            }

            // 混淆后的 HookBridge（如 KmkyjghNEh.FrHZn.faUePQsyDyyx.HookBridge）
            if (className.endsWith(".HookBridge") || className == "HookBridge") {
                return true
            }

            // 混淆后的回调类：短类名 + callback 方法（如 class=J, method=callback）
            if (className.length <= 2 && methodName == "callback") {
                return true
            }

            // invokeOriginalMethod 是 LSPosed bridge 的核心调用
            if (methodName == "invokeOriginalMethod") {
                return true
            }

            return false
        }

        /**
         * 清洗栈帧数组：移除所有 hook 框架痕迹，
         * 同时移除紧随其后的反射 Method.invoke 帧（用于调用原方法的桥接层）。
         * @return 清洗后的数组，如果无需清洗则返回 null
         */
        private fun cleanStackTrace(elements: Array<StackTraceElement>): Array<StackTraceElement>? {
            if (elements.isEmpty()) return null

            // 快速扫描：如果没有可疑帧则直接跳过，避免不必要的内存分配
            var needsScrubbing = false
            for (element in elements) {
                if (isSuspiciousFrame(element)) {
                    needsScrubbing = true
                    break
                }
            }
            if (!needsScrubbing) return null

            val cleanTrace = mutableListOf<StackTraceElement>()
            var skipNextMethodInvoke = false

            for (element in elements) {
                if (isSuspiciousFrame(element)) {
                    skipNextMethodInvoke = true
                    continue
                }

                // hook 框架通过反射 Method.invoke 调用原方法，一并剔除
                if (skipNextMethodInvoke &&
                    element.className == "java.lang.reflect.Method" &&
                    element.methodName == "invoke"
                ) {
                    skipNextMethodInvoke = false
                    continue
                }

                skipNextMethodInvoke = false
                cleanTrace.add(element)
            }

            return if (cleanTrace.size != elements.size) cleanTrace.toTypedArray() else null
        }

        /**
         * 安装所有绕过 hook。
         *
         * 核心策略：
         * 1. 在 ghost 对象创建时填充关键字段 → 防止 LSPosed native bridge 的 SIGSEGV
         * 2. 在 hooked 方法调用前识别 ghost 对象 → 抛出干净的 Java 异常
         * 3. 在壳读取堆栈时清洗 hook 痕迹 → 欺骗检测逻辑
         */
        private fun bypassGhostInstanceDetection() {
            if (isBypassed) return
            isBypassed = true
            XposedBridge.log("TankeHook: Initializing anti-ghost detection...")

            // ═══════════════════════════════════════════════════════════
            // Hook 0: Unsafe.allocateInstance — 幽灵对象源头拦截
            //
            // 壳使用 Unsafe.allocateInstance(LoadedApk.class) 创建全空对象。
            // LSPosed 的 native bridge 在处理 hooked 方法调用时，会在
            // Java callback 之前访问对象字段（如 mApplicationInfo），
            // 全空字段导致 null->field 的链式解引用 → SIGSEGV (fault 0x88c)。
            //
            // 解决：在 allocateInstance 返回后立即填充关键字段，
            // 使 native bridge 不会遇到 null 引用链。
            // ═══════════════════════════════════════════════════════════
            try {
                val unsafeClass = Class.forName("sun.misc.Unsafe")
                val allocMethod = unsafeClass.getDeclaredMethod("allocateInstance", Class::class.java)
                XposedBridge.hookMethod(allocMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val result = param.result ?: return
                        if (result.javaClass.name != "android.app.LoadedApk") return

                        try {
                            // 标记 + 填充关键字段，使 native bridge 不会 SIGSEGV
                            XposedHelpers.setObjectField(result, "mPackageName", GHOST_MARKER)

                            // mApplicationInfo 是 SIGSEGV 的直接元凶：
                            // native bridge 读取 mApplicationInfo(null) 后访问其内部字段(+0x88c) → crash
                            val appInfo = ApplicationInfo()
                            appInfo.packageName = GHOST_MARKER
                            appInfo.processName = GHOST_MARKER
                            appInfo.sourceDir = "/dev/null"
                            appInfo.dataDir = "/dev/null"
                            appInfo.nativeLibraryDir = "/dev/null"
                            appInfo.targetSdkVersion = 34
                            XposedHelpers.setObjectField(result, "mApplicationInfo", appInfo)
                        } catch (t: Throwable) {
                            XposedBridge.log("TankeHook: Failed to fill ghost fields: ${t.message}")
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Unsafe.allocateInstance (ghost field filler)")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook Unsafe.allocateInstance: ${e.message}")
            }

            // ═══════════════════════════════════════════════════════════
            // Hook 1: LoadedApk.createOrUpdateClassLoaderLocked — 幽灵对象拦截器
            //
            // 即使 Unsafe hook 填充了字段使 native bridge 不崩溃，
            // 我们仍需在方法执行前拦截 ghost 对象，抛出干净的 NPE。
            // 这样壳捕获的异常堆栈经 getStackTrace() hook 清洗后完全干净。
            //
            // 也作为备用方案：如果壳不通过 Unsafe 创建 ghost（如直接 native 内存分配），
            // mPackageName 仍为 null，同样被拦截。
            // ═══════════════════════════════════════════════════════════
            try {
                val loadedApkClass = XposedHelpers.findClass("android.app.LoadedApk", null)
                val createCLMethod = XposedHelpers.findMethodExact(
                    loadedApkClass,
                    "createOrUpdateClassLoaderLocked",
                    List::class.java
                )
                XposedBridge.hookMethod(createCLMethod, object : XC_MethodHook(10000) {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        try {
                            val mPackageName = XposedHelpers.getObjectField(param.thisObject, "mPackageName")
                            if (mPackageName == null || mPackageName == GHOST_MARKER) {
                                param.throwable = NullPointerException(
                                    "Attempt to invoke virtual method on a null object reference"
                                )
                                return
                            }
                        } catch (_: Throwable) {
                            param.throwable = NullPointerException(
                                "Attempt to invoke virtual method on a null object reference"
                            )
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked createOrUpdateClassLoaderLocked (ghost interceptor)")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook createOrUpdateClassLoaderLocked: ${e.message}")
            }

            // ═══════════════════════════════════════════════════════════
            // Hook 2: Throwable.getStackTrace() — 核心防线
            // 壳通过 exception.getStackTrace() 读取堆栈并扫描 hook 痕迹，
            // 在返回结果前清洗即可欺骗检测。
            // 同时更新 Throwable 内部的 stackTrace 字段，
            // 确保后续 printStackTrace() 也返回干净结果。
            // ═══════════════════════════════════════════════════════════
            try {
                val getStackTraceMethod = Throwable::class.java.getDeclaredMethod("getStackTrace")
                XposedBridge.hookMethod(getStackTraceMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        // 重入保护
                        if (isProcessing.get()) return
                        isProcessing.set(true)
                        try {
                            val elements = param.result as? Array<*> ?: return
                            @Suppress("UNCHECKED_CAST")
                            val stackElements = elements as? Array<StackTraceElement> ?: return
                            val cleaned = cleanStackTrace(stackElements) ?: return
                            param.result = cleaned
                            // 持久化到 Throwable 内部，使 printStackTrace() 同样干净
                            try {
                                (param.thisObject as? Throwable)?.stackTrace = cleaned
                            } catch (_: Throwable) {
                            }
                        } finally {
                            isProcessing.set(false)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Throwable.getStackTrace()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook Throwable.getStackTrace: ${e.message}")
            }

            // ═══════════════════════════════════════════════════════════
            // Hook 3: Thread.getStackTrace() — 辅助防线
            // 壳可能通过 Thread.currentThread().getStackTrace() 检查当前调用栈
            // ═══════════════════════════════════════════════════════════
            try {
                val threadGetStackTrace = Thread::class.java.getDeclaredMethod("getStackTrace")
                XposedBridge.hookMethod(threadGetStackTrace, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (isProcessing.get()) return
                        isProcessing.set(true)
                        try {
                            val elements = param.result as? Array<*> ?: return
                            @Suppress("UNCHECKED_CAST")
                            val stackElements = elements as? Array<StackTraceElement> ?: return
                            val cleaned = cleanStackTrace(stackElements) ?: return
                            param.result = cleaned
                        } finally {
                            isProcessing.set(false)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Thread.getStackTrace()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook Thread.getStackTrace: ${e.message}")
            }

            // ═══════════════════════════════════════════════════════════
            // Hook 4: Thread.getAllStackTraces() — 补充防线
            // 壳可能枚举所有线程的堆栈来检测 hook
            // ═══════════════════════════════════════════════════════════
            try {
                val getAllStackTraces = Thread::class.java.getDeclaredMethod("getAllStackTraces")
                XposedBridge.hookMethod(getAllStackTraces, object : XC_MethodHook() {
                    @Suppress("UNCHECKED_CAST")
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (isProcessing.get()) return
                        isProcessing.set(true)
                        try {
                            val map = param.result as? Map<Thread, Array<StackTraceElement>> ?: return
                            var anyChanged = false
                            val cleanedMap = LinkedHashMap<Thread, Array<StackTraceElement>>(map.size)
                            for ((thread, elements) in map) {
                                val cleaned = cleanStackTrace(elements)
                                if (cleaned != null) {
                                    cleanedMap[thread] = cleaned
                                    anyChanged = true
                                } else {
                                    cleanedMap[thread] = elements
                                }
                            }
                            if (anyChanged) {
                                param.result = cleanedMap
                            }
                        } finally {
                            isProcessing.set(false)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Thread.getAllStackTraces()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook Thread.getAllStackTraces: ${e.message}")
            }
        }
    }

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        // 最优先：安装 native SIGSEGV 处理器
        // 必须在任何 Java hook 之前，因为 LSPosed 的 bootstrap hook
        // 可能在 ghost 对象上触发 native crash
        NativeHelper.install(startupParam.modulePath)

        bypassGhostInstanceDetection()
    }

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName != "com.lptiyu.tanke") {
            return
        }
        XposedBridge.log("TankeHook: loading for ${lpparam.packageName}")
    }
}
