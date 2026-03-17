package com.lptiyu.tanke.hook

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers

/**
 * finishRun 风险检测绕过模块。
 *
 * 屏蔽三类错误码（均在 p1141g.p1147a0.p1158c.utils.p2 中实现）：
 * （JADX 显示为 C16270p2，实际二进制类名为 p2；方法 m72734R 等实际名为 R/J/x/Q/y）
 *
 *  error_code 3009 — [HookPrefs.bypassProxy] : isWifiProxy
 *    m72734R() 读取 System.getProperty("http.proxyHost/proxyPort")
 *
 *  error_code 4004 — [HookPrefs.bypassRoot] : isRoot
 *    m72726J() 调用 RootBeer 检测库
 *  error_code 4004 — [HookPrefs.bypassDebugger] : isDebugger
 *    m72766x() 调用 Debug.isDebuggerConnected() + waitingForDebugger()
 *
 *  error_code 4005 — [HookPrefs.bypassVapp] : isVirtualApp
 *    m72733Q() 检查 context.getFilesDir() 路径是否在标准目录
 *  error_code 4005 — [HookPrefs.bypassVapp] : isDualAppEx
 *    m72767y() 通过 /proc/self/fd 符号链接检测双开/虚拟容器
 *
 * 同时提供 android.os.Debug 底层兜底 hook（无论 C16270p2 是否加载成功）。
 */
object DetectionBypassHooks {

    private var debugInstalled = false
    private var c16270Installed = false

    // ── Entry points ─────────────────────────────────────────────────────

    fun install(classLoader: ClassLoader) {
        installDebugHooks()
        installC16270Hooks(classLoader)
    }

    fun onClassLoaded(name: String, loader: ClassLoader) {
        if (!c16270Installed && name == "p1141g.p1147a0.p1158c.utils.p2") {
            installC16270Hooks(loader)
        }
    }

    // ── android.os.Debug 兜底（始终可用，在 hook 内部按pref动态判断）────────

    private fun installDebugHooks() {
        if (debugInstalled) return
        debugInstalled = true
        try {
            XposedHelpers.findAndHookMethod(
                android.os.Debug::class.java, "isDebuggerConnected",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (HookPrefs.bypassDebugger) param.result = false
                    }
                }
            )
            XposedHelpers.findAndHookMethod(
                android.os.Debug::class.java, "waitingForDebugger",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (HookPrefs.bypassDebugger) param.result = false
                    }
                }
            )
            XposedBridge.log("TankeHook: Hooked Debug.isDebuggerConnected/waitingForDebugger")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Debug hooks failed: ${e.message}")
        }
    }

    // ── C16270p2 精准检测方法（失败时由 ClassLoader 监听器重试）──────────────

    private fun installC16270Hooks(classLoader: ClassLoader) {
        if (c16270Installed) return
        try {
            val detClass = XposedHelpers.findClass(
                "p1141g.p1147a0.p1158c.utils.p2", classLoader
            )

            // 每个检测方法对应：混淆方法名 → (是否启用的 pref 读取函数, 日志标签)
            val targets = mapOf(
                "R" to Pair({ HookPrefs.bypassProxy },    "isWifiProxy(3009)"),
                "J" to Pair({ HookPrefs.bypassRoot },     "isRoot(4004)"),
                "x" to Pair({ HookPrefs.bypassDebugger }, "isDebugger(4004)"),
                "Q" to Pair({ HookPrefs.bypassVapp },     "isVirtualApp(4005)"),
                "y" to Pair({ HookPrefs.bypassVapp },     "isDualAppEx(4005)"),
            )

            var count = 0
            for (method in detClass.declaredMethods) {
                val (checkFn, label) = targets[method.name] ?: continue
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (checkFn()) {
                            HookPrefs.vlog("TankeHook: $label → false")
                            param.result = false
                        }
                    }
                })
                count++
            }
            c16270Installed = true
            XposedBridge.log("TankeHook: Hooked $count/5 risk detection methods in C16270p2")
        } catch (e: Throwable) {
            // 类尚未加载，不设置 c16270Installed，ClassLoader 监听器将在类加载时重试
            XposedBridge.log("TankeHook: C16270p2 hooks deferred: ${e.message}")
        }
    }
}
