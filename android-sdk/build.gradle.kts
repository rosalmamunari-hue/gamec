plugins {
    id("com.android.library") version "8.5.2"
    id("org.jetbrains.kotlin.android") version "1.9.24"
}

android {
    namespace = "com.gamec.shield"
    compileSdk = 34
    defaultConfig {
        // TLS 1.3 is only available from Android 10 (API 29); the edge node requires it.
        minSdk = 29
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    // android.jar's org.json is a stub in JVM unit tests; use the real implementation there.
    testImplementation("org.json:json:20240303")

    // On-device tests (run on an emulator or phone, see src/androidTest)
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test:runner:1.5.2")
}
