package com.lptiyu.tanke.hook

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers

/**
 * SSL/TLS 绕过 + HttpDNS 禁用 Hook 模块。
 *
 * 功能（按 [HookPrefs] 开关控制）：
 *  - [HookPrefs.bypassSsl] = true  → TrustManagerImpl.verifyChain() 放行任意证书链
 *  - [HookPrefs.bypassSsl] = true  → HttpsURLConnection 默认 HostnameVerifier 宽松化
 *  - [HookPrefs.bypassSsl] = true  → OkHttp CertificatePinner.check() 放行
 *  - [HookPrefs.bypassSsl] = true  → OkHostnameVerifier.verify() → true
 *  - [HookPrefs.bypassSsl] = true  → 动态 HostnameVerifier 实现类 verify() → true
 *  - [HookPrefs.disableHttpdns] = true → 阿里云 OSS HttpDNS 强制关闭
 *
 * [install] 由 [MainHook.handleLoadPackage] 在应用进程中调用。
 * [onClassLoaded] 由 ClassLoader 监听器在相关类延迟加载时调用。
 */
object NetworkHooks {

    private var bootstrap = false
    private var ossInstalled = false
    private var okhttpInstalled = false
    private var trustManagerInstalled = false
    private val hookedVerifierClasses = HashSet<String>()

    private val permissiveVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }

    // ── Entry points ────────────────────────────────────────────────────

    fun install(classLoader: ClassLoader) {
        if (bootstrap) return
        bootstrap = true
        if (HookPrefs.bypassSsl) installTrustManagerBypass()
        if (HookPrefs.bypassSsl || HookPrefs.disableHttpdns) installOssHttpDnsBypass(classLoader)
        if (HookPrefs.bypassSsl) installOkHttpPinningBypass(classLoader)
    }

    fun onClassLoaded(name: String, loader: ClassLoader, clazz: Class<*>) {
        if (HookPrefs.bypassSsl) {
            installHostnameVerifierForClass(name, clazz)
        }
        if (HookPrefs.disableHttpdns && !ossInstalled && name.startsWith("com.alibaba.sdk.android.oss")) {
            installOssHttpDnsBypass(loader)
        }
        if (HookPrefs.bypassSsl && !okhttpInstalled && name.startsWith("okhttp3")) {
            installOkHttpPinningBypass(loader)
        }
    }

    // ── TrustManager bypass ──────────────────────────────────────────────

    private fun installTrustManagerBypass() {
        if (trustManagerInstalled) return
        var installed = false

        try {
            val clazz = Class.forName("com.android.org.conscrypt.TrustManagerImpl")
            for (method in clazz.declaredMethods) {
                if (method.name != "verifyChain") continue
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (param.args.isNotEmpty()) param.result = param.args[0]
                    }
                })
            }
            installed = true
            XposedBridge.log("TankeHook: Hooked TrustManagerImpl.verifyChain()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: TrustManagerImpl hook failed: ${e.message}")
        }

        try {
            val m = javax.net.ssl.HttpsURLConnection::class.java
                .getDeclaredMethod("getDefaultHostnameVerifier")
            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    param.result = permissiveVerifier
                }
            })
            installed = true
            XposedBridge.log("TankeHook: Hooked HttpsURLConnection.getDefaultHostnameVerifier()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: HttpsURLConnection hook failed: ${e.message}")
        }

        trustManagerInstalled = installed
    }

    // ── OSS HttpDNS bypass ───────────────────────────────────────────────

    private fun installOssHttpDnsBypass(classLoader: ClassLoader) {
        if (ossInstalled) return
        try {
            XposedHelpers.findAndHookMethod(
                "com.alibaba.sdk.android.oss.ClientConfiguration", classLoader,
                "isHttpDnsEnable",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) { param.result = false }
                }
            )
            XposedHelpers.findAndHookMethod(
                "com.alibaba.sdk.android.oss.ClientConfiguration", classLoader,
                "setHttpDnsEnable", Boolean::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) { param.args[0] = false }
                }
            )
            XposedHelpers.findAndHookMethod(
                "com.alibaba.sdk.android.oss.internal.InternalRequestOperation", classLoader,
                "checkIfHttpDnsAvailable", Boolean::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) { param.result = false }
                }
            )
            XposedHelpers.findAndHookConstructor(
                "com.alibaba.sdk.android.oss.internal.InternalRequestOperation", classLoader,
                android.content.Context::class.java,
                java.net.URI::class.java,
                XposedHelpers.findClass("com.alibaba.sdk.android.oss.common.auth.OSSCredentialProvider", classLoader),
                XposedHelpers.findClass("com.alibaba.sdk.android.oss.ClientConfiguration", classLoader),
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        try {
                            val client = XposedHelpers.getObjectField(param.thisObject, "innerClient")
                            val builder = XposedHelpers.callMethod(client, "newBuilder")
                            XposedHelpers.callMethod(builder, "hostnameVerifier", permissiveVerifier)
                            val rebuilt = XposedHelpers.callMethod(builder, "build")
                            XposedHelpers.setObjectField(param.thisObject, "innerClient", rebuilt)
                        } catch (_: Throwable) {}
                    }
                }
            )
            ossInstalled = true
            XposedBridge.log("TankeHook: OSS HttpDNS + hostname hooks installed")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: OSS hooks deferred: ${e.message}")
        }
    }

    // ── OkHttp pinning bypass ────────────────────────────────────────────

    private fun installOkHttpPinningBypass(classLoader: ClassLoader) {
        if (okhttpInstalled) return
        try {
            val certPinnerClass = XposedHelpers.findClass("okhttp3.CertificatePinner", classLoader)

            val checkList = certPinnerClass.getDeclaredMethod("check", String::class.java, List::class.java)
            XposedBridge.hookMethod(checkList, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) { param.result = null }
            })

            val certArrayClass = Class.forName("[Ljava.security.cert.Certificate;")
            val checkArray = certPinnerClass.getDeclaredMethod("check", String::class.java, certArrayClass)
            XposedBridge.hookMethod(checkArray, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) { param.result = null }
            })

            val defaultPinner = certPinnerClass.getDeclaredField("DEFAULT").get(null)
            XposedHelpers.findAndHookMethod(
                "okhttp3.OkHttpClient\$Builder", classLoader,
                "certificatePinner", certPinnerClass,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) { param.args[0] = defaultPinner }
                }
            )

            try {
                XposedHelpers.findAndHookMethod(
                    "okhttp3.internal.tls.OkHostnameVerifier", classLoader,
                    "verify", String::class.java, javax.net.ssl.SSLSession::class.java,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) { param.result = true }
                    }
                )
            } catch (_: Throwable) {}

            okhttpInstalled = true
            XposedBridge.log("TankeHook: OkHttp pinning + hostname hooks installed")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: OkHttp hooks deferred: ${e.message}")
        }
    }

    // ── Dynamic HostnameVerifier hook ────────────────────────────────────

    private fun installHostnameVerifierForClass(className: String, clazz: Class<*>) {
        if (hookedVerifierClasses.contains(className)) return
        if (!javax.net.ssl.HostnameVerifier::class.java.isAssignableFrom(clazz)) return
        try {
            val m = clazz.getDeclaredMethod(
                "verify", String::class.java, javax.net.ssl.SSLSession::class.java
            )
            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) { param.result = true }
            })
            hookedVerifierClasses.add(className)
            XposedBridge.log("TankeHook: Hooked HostnameVerifier.verify for $className")
        } catch (_: Throwable) {}
    }
}
