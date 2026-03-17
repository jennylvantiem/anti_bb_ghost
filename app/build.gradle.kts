plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val ndkVer = providers.gradleProperty("androidNdkVersion").orElse("29.0.14206865")
val cmakeVer = providers.gradleProperty("androidCmakeVersion").orElse("3.22.1")
val buildToolsVer = providers.gradleProperty("androidBuildToolsVersion").orElse("36.1.0")

android {
    namespace = "com.lptiyu.tanke.hook"
    compileSdk = 36
    buildToolsVersion = buildToolsVer.get()
    ndkVersion = ndkVer.get()

    defaultConfig {
        applicationId = "com.lptiyu.tanke.hook"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = cmakeVer.get()
        }
    }
}

dependencies {
    compileOnly("de.robv.android.xposed:api:82")
}
