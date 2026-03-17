package com.lptiyu.tanke.hook

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers

/**
 * 广告 SDK 初始化拦截 + 开屏广告跳过模块。
 *
 * 功能（按 [HookPrefs] 开关控制）：
 *  - [HookPrefs.disableAds] = true  → 拦截 YFAds / 北智融合 / 快手 KsAd / 字节 TTAdSdk 初始化
 *  - [HookPrefs.skipSplashAd] = true → YFAdSplashAds.showAds() 立即触发 onAdClosed()
 *  - [HookPrefs.skipSplashAd] = true → SplashActivity.fetchAd() 阻止广告网络请求
 *
 * [install] 由 [MainHook.handleLoadPackage] 首次调用（可能失败，类尚未加载）。
 * [onClassLoaded] 由 ClassLoader 监听器在相关类加载时重试。
 */
object AdHooks {

    private var yfInitHooked = false
    private var yfInitSucHooked = false
    private var beiziInitHooked = false
    private var beiziAsyncInitHooked = false
    private var ksInitHooked = false
    private var ksStartHooked = false
    private var ttHooked = false

    private var splashShowAdsHooked = false
    private var splashFetchAdHooked = false

    // ── Entry points ─────────────────────────────────────────────────────

    fun install(classLoader: ClassLoader) {
        if (HookPrefs.disableAds || HookPrefs.skipSplashAd) installAdSdkHooks(classLoader)
        if (HookPrefs.skipSplashAd) installSplashAdHooks(classLoader)
    }

    fun onClassLoaded(name: String, loader: ClassLoader, clazz: Class<*>) {
        if (HookPrefs.disableAds &&
            (name.startsWith("com.yfanads") || name.startsWith("com.beizi") ||
             name.startsWith("com.kwad") || name.startsWith("com.bytedance.sdk.openadsdk"))) {
            installAdSdkHooks(loader)
            hookDynamicYfEntry(name, clazz)
        }
        if (HookPrefs.skipSplashAd &&
            (name.startsWith("com.yfanads.android") || name.contains("Splash"))) {
            hookDynamicSplashShowAds(name, clazz)
        }
        if (HookPrefs.skipSplashAd &&
            (name.startsWith("com.lptiyu.tanke") && name.contains("Splash"))) {
            hookDynamicFetchAd(name, clazz)
        }
        if (HookPrefs.skipSplashAd &&
            (name == "com.lptiyu.tanke.activities.splash.SplashActivity" ||
             name == "com.yfanads.android.core.splash.YFAdSplashAds")) {
            installSplashAdHooks(loader)
        }
    }

    // ── Ad SDK init hooks ────────────────────────────────────────────────

    private fun installAdSdkHooks(classLoader: ClassLoader) {
        XposedBridge.log("TankeHook: Installing ad SDK hooks (disableAds=${HookPrefs.disableAds})...")

        if (!HookPrefs.disableAds) return

        // — YFAds ─────────────────────────────────────────────────────
        try {
            val yfMgrClass = XposedHelpers.findClass("com.yfanads.android.YFAdsManager", classLoader)
            var count = 0
            for (method in yfMgrClass.declaredMethods) {
                if (method.name == "init") {
                    XposedBridge.hookMethod(method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            HookPrefs.vlog("YFAdsManager.init() blocked")
                            param.result = null
                        }
                    })
                    count++
                }
            }
            if (count > 0) {
                yfInitHooked = true
                XposedBridge.log("TankeHook: Hooked YFAdsManager.init() ($count overloads)")
            }
            else XposedBridge.log("TankeHook: YFAdsManager.init not found")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: YFAdsManager hook failed: ${e.message}")
        }

        try {
            XposedHelpers.findAndHookMethod(
                "com.yfanads.android.YFAdsManager", classLoader, "isInitSuc",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) { param.result = false }
                }
            )
            yfInitSucHooked = true
        } catch (_: Throwable) {}

        // — 北智融合 BeiZis ───────────────────────────────────────────
        try {
            XposedHelpers.findAndHookMethod(
                "com.beizi.fusion.BeiZis", classLoader,
                "init", android.content.Context::class.java, String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        HookPrefs.vlog("BeiZis.init() blocked"); param.result = null
                    }
                }
            )
            beiziInitHooked = true
            XposedBridge.log("TankeHook: Hooked BeiZis.init()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: BeiZis.init hook failed: ${e.message}")
        }
        try {
            XposedHelpers.findAndHookMethod(
                "com.beizi.fusion.BeiZis", classLoader,
                "asyncInit", android.content.Context::class.java, String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        HookPrefs.vlog("BeiZis.asyncInit() blocked"); param.result = null
                    }
                }
            )
            beiziAsyncInitHooked = true
        } catch (_: Throwable) {}

        // — 快手 KsAdSDK ─────────────────────────────────────────────
        try {
            val ksConfigClass = XposedHelpers.findClass("com.kwad.sdk.api.SdkConfig", classLoader)
            XposedHelpers.findAndHookMethod(
                "com.kwad.sdk.api.KsAdSDK", classLoader,
                "init", android.content.Context::class.java, ksConfigClass,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        HookPrefs.vlog("KsAdSDK.init() blocked"); param.result = false
                    }
                }
            )
            ksInitHooked = true
            XposedBridge.log("TankeHook: Hooked KsAdSDK.init()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: KsAdSDK.init hook failed: ${e.message}")
        }
        try {
            XposedHelpers.findAndHookMethod(
                "com.kwad.sdk.api.KsAdSDK", classLoader, "start",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        HookPrefs.vlog("KsAdSDK.start() blocked"); param.result = null
                    }
                }
            )
            ksStartHooked = true
        } catch (_: Throwable) {}

        // — 字节跳动 Pangle TTAdSdk ───────────────────────────────────
        try {
            val clazz = XposedHelpers.findClass("com.bytedance.sdk.openadsdk.TTAdSdk", classLoader)
            var count = 0
            for (method in clazz.declaredMethods) {
                if (method.name == "init" || method.name == "start") {
                    XposedBridge.hookMethod(method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            HookPrefs.vlog("TTAdSdk.${method.name}() blocked"); param.result = null
                        }
                    })
                    count++
                }
            }
            if (count > 0) {
                ttHooked = true
                XposedBridge.log("TankeHook: Hooked TTAdSdk init/start")
            }
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: TTAdSdk hook skipped: ${e.message}")
        }
    }

    // ── Splash ad skip ───────────────────────────────────────────────────

    private fun installSplashAdHooks(classLoader: ClassLoader) {
        XposedBridge.log("TankeHook: Installing splash ad hooks...")

        // Hook showAds() — 立即触发 onAdClosed() 跳过广告，保持 SplashActivity 跳转流程
        try {
            XposedHelpers.findAndHookMethod(
                "com.yfanads.android.core.splash.YFAdSplashAds", classLoader,
                "showAds", android.app.Activity::class.java, android.view.ViewGroup::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        HookPrefs.vlog("YFAdSplashAds.showAds() → onAdClosed()")
                        param.result = null
                        try {
                            val listener = XposedHelpers.getObjectField(param.thisObject, "listener")
                            if (listener != null) XposedHelpers.callMethod(listener, "onAdClosed")
                        } catch (e: Throwable) {
                            XposedBridge.log("TankeHook: onAdClosed trigger failed: ${e.message}")
                        }
                    }
                }
            )
            splashShowAdsHooked = true
            XposedBridge.log("TankeHook: Hooked YFAdSplashAds.showAds()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: YFAdSplashAds.showAds hook failed: ${e.message}")
        }

        // Hook fetchAd() — 阻止广告网络请求（次要防线）
        try {
            val splashClass = XposedHelpers.findClass(
                "com.lptiyu.tanke.activities.splash.SplashActivity", classLoader
            )
            val fetchAdMethod = splashClass.getDeclaredMethod("fetchAd", String::class.java)
            XposedBridge.hookMethod(fetchAdMethod, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    HookPrefs.vlog("SplashActivity.fetchAd() skipped"); param.result = null
                }
            })
            splashFetchAdHooked = true
            XposedBridge.log("TankeHook: Hooked SplashActivity.fetchAd()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: fetchAd hook failed: ${e.message}")
        }
    }

    private fun hookDynamicYfEntry(name: String, clazz: Class<*>) {
        if (!name.startsWith("com.yfanads.android") || yfInitHooked) return
        try {
            var count = 0
            for (method in clazz.declaredMethods) {
                if (method.name != "init") continue
                val params = method.parameterTypes
                val hasContext = params.any { android.content.Context::class.java.isAssignableFrom(it) }
                if (!hasContext) continue
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        HookPrefs.vlog("${name}.init() blocked (dynamic)")
                        param.result = null
                    }
                })
                count++
            }
            if (count > 0) {
                yfInitHooked = true
                XposedBridge.log("TankeHook: Dynamic hooked ${name}.init() ($count)")
            }
        } catch (_: Throwable) {}
    }

    private fun hookDynamicSplashShowAds(name: String, clazz: Class<*>) {
        if (splashShowAdsHooked) return
        try {
            for (method in clazz.declaredMethods) {
                if (method.name != "showAds") continue
                val p = method.parameterTypes
                if (p.size != 2) continue
                if (!android.app.Activity::class.java.isAssignableFrom(p[0])) continue
                if (!android.view.ViewGroup::class.java.isAssignableFrom(p[1])) continue
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        HookPrefs.vlog("${name}.showAds() → onAdClosed() (dynamic)")
                        param.result = null
                        try {
                            val listener = XposedHelpers.getObjectField(param.thisObject, "listener")
                            if (listener != null) XposedHelpers.callMethod(listener, "onAdClosed")
                        } catch (_: Throwable) {}
                    }
                })
                splashShowAdsHooked = true
                XposedBridge.log("TankeHook: Dynamic hooked ${name}.showAds()")
                return
            }
        } catch (_: Throwable) {}
    }

    private fun hookDynamicFetchAd(name: String, clazz: Class<*>) {
        if (splashFetchAdHooked) return
        try {
            for (method in clazz.declaredMethods) {
                if (method.name != "fetchAd") continue
                val p = method.parameterTypes
                if (p.size == 1 && p[0] == String::class.java) {
                    XposedBridge.hookMethod(method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            HookPrefs.vlog("${name}.fetchAd(String) skipped (dynamic)")
                            param.result = null
                        }
                    })
                    splashFetchAdHooked = true
                    XposedBridge.log("TankeHook: Dynamic hooked ${name}.fetchAd(String)")
                    return
                }
            }
        } catch (_: Throwable) {}
    }
}
