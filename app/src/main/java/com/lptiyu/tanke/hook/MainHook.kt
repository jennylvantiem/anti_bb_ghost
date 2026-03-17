package com.lptiyu.tanke.hook

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

/**
 * LSPosed 模块主入口 — 精简调度器。
 *
 * 各功能实现已拆分到独立模块：
 *  - [HookPrefs]            : 偏好设置 key 常量 + 运行时值 + 日志工具
 *  - [StackTraceHooks]      : Zygote 级栈帧伪装（7 个 hook）
 *  - [NetworkHooks]         : SSL/TrustManager/OkHttp/OSS HttpDNS 绕过
 *  - [AdHooks]              : 广告 SDK 初始化拦截 + 开屏广告跳过
 *  - [DetectionBypassHooks] : 代理/Root/调试器/虚拟环境检测绕过
 */
class MainHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    /** ClassLoader.loadClass 重入保护，防止 hook 回调中再次触发 hook 安装 */
    private val isInstallingHooks: ThreadLocal<Boolean> = ThreadLocal.withInitial { false }
    private var classLoaderMonitorInstalled = false

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        NativeHelper.install(startupParam.modulePath)
        HookPrefs.load()
        if (HookPrefs.fakeStack) {
            StackTraceHooks.installZygote()
        }
    }

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName != "com.lptiyu.tanke") return
        XposedBridge.log("TankeHook: loading for ${lpparam.packageName}")
        HookPrefs.load()
        val cl = lpparam.classLoader
        NetworkHooks.install(cl)
        AdHooks.install(cl)
        DetectionBypassHooks.install(cl)
        installClassLoaderMonitor()
    }

    /**
     * 监听 ClassLoader.loadClass，在目标类延迟加载时通知各模块安装 hook。
     * ThreadLocal 重入保护防止 hook 回调中调用 findClass 触发无限递归。
     */
    private fun installClassLoaderMonitor() {
        if (classLoaderMonitorInstalled) return
        classLoaderMonitorInstalled = true
        try {
            XposedHelpers.findAndHookMethod(
                ClassLoader::class.java, "loadClass", String::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (isInstallingHooks.get()) return
                        val name   = param.args[0] as? String      ?: return
                        val loader = param.thisObject as? ClassLoader ?: return
                        val clazz  = param.result  as? Class<*>    ?: return
                        isInstallingHooks.set(true)
                        try {
                            NetworkHooks.onClassLoaded(name, loader, clazz)
                            AdHooks.onClassLoaded(name, loader, clazz)
                            DetectionBypassHooks.onClassLoaded(name, loader)
                        } finally {
                            isInstallingHooks.set(false)
                        }
                    }
                }
            )
            XposedBridge.log("TankeHook: ClassLoader monitor installed")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: ClassLoader monitor failed: ${e.message}")
        }
    }
}
