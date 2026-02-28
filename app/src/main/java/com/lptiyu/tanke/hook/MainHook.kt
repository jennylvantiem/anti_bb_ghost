package com.lptiyu.tanke.hook

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

class MainHook : IXposedHookLoadPackage {

    private val suspiciousKeywords = arrayOf(
        "org.lsposed",
        "de.robv.android.xposed",
        "LSPHooker",
        "com.elder.xposed",
        "HookBridge",
        "SandHook",
        "EdXposed",
        "me.weishu.epic",
        "top.canyie.pine",
        "com.swift.sandhook"
    )

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName != "com.lptiyu.tanke") {
            return
        }
        XposedBridge.log("TankeHook: loading for ${lpparam.packageName}")

        bypassStackTraceDetection()

        try {
            System.loadLibrary("tanke-hook")
            XposedBridge.log("TankeHook: successfully loaded libtanke-hook.so")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: error loading library: ${e.message}")
            try {
                val appInfo = lpparam.appInfo
                val libDir = appInfo.nativeLibraryDir
                XposedBridge.log("TankeHook: appInfo nativeLibraryDir is $libDir")
            } catch (e2: Throwable) {
            }
        }
    }

    /**
     * 洗白堆栈，将框架的痕迹抹去
     */
    private fun scrubStackTrace(throwable: Throwable?) {
        var cause = throwable
        while (cause != null) {
            val originalTrace = cause.stackTrace
            if (originalTrace != null) {
                val cleanTrace = originalTrace.filter { element ->
                    val className = element.className
                    val methodName = element.methodName
                    // 如果栈帧包含可疑关键字，则剔除
                    suspiciousKeywords.none { keyword ->
                        className.contains(keyword) || methodName.contains(keyword)
                    }
                }.toTypedArray()

                if (cleanTrace.size != originalTrace.size) {
                    cause.stackTrace = cleanTrace
                    XposedBridge.log("TankeHook: scrubbed ${originalTrace.size - cleanTrace.size} suspicious frames from Throwable.")
                }
            }
            cause = cause.cause
        }
    }

    private fun bypassStackTraceDetection() {
        XposedBridge.log("TankeHook: Initializing Ghost Instance detection bypass...")

        // Hook LoadedApk.createOrUpdateClassLoaderLocked
        try {
            val loadedApkClass = XposedHelpers.findClass("android.app.LoadedApk", null)
            val createClassLoaderMethod = XposedHelpers.findMethodExact(
                loadedApkClass,
                "createOrUpdateClassLoaderLocked",
                List::class.java
            )

            XposedBridge.hookMethod(createClassLoaderMethod, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (param.hasThrowable()) {
                        scrubStackTrace(param.throwable)
                    }
                }
            })
            XposedBridge.log("TankeHook: Hooked LoadedApk.createOrUpdateClassLoaderLocked successfully")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Failed to hook LoadedApk: ${e.message}")
        }

        // Hook ActivityThread.attach just in case they check it
        try {
            val activityThreadClass = XposedHelpers.findClass("android.app.ActivityThread", null)
            val attachMethod = XposedHelpers.findMethodExact(
                activityThreadClass,
                "attach",
                Boolean::class.javaPrimitiveType,
                Long::class.javaPrimitiveType
            )

            XposedBridge.hookMethod(attachMethod, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (param.hasThrowable()) {
                        scrubStackTrace(param.throwable)
                    }
                }
            })
            XposedBridge.log("TankeHook: Hooked ActivityThread.attach successfully")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Failed to hook ActivityThread: ${e.message}")
        }

        // Catch Throwable getStackTrace globally for this app
        try {
            val getStackTraceMethod = Throwable::class.java.getDeclaredMethod("getStackTrace")
            XposedBridge.hookMethod(getStackTraceMethod, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val elements = param.result as? Array<StackTraceElement> ?: return
                    val cleanElements = elements.filter { element ->
                        suspiciousKeywords.none { keyword ->
                            element.className.contains(keyword) || element.methodName.contains(keyword)
                        }
                    }.toTypedArray()

                    if (cleanElements.size != elements.size) {
                        param.result = cleanElements
                    }
                }
            })
            XposedBridge.log("TankeHook: Hooked Throwable.getStackTrace successfully")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Failed to hook Throwable.getStackTrace: ${e.message}")
        }
    }
}
