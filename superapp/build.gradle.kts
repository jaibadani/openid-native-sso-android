import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties()

if (keystorePropertiesFile.exists()) {
    keystorePropertiesFile.inputStream().use { keystoreProperties.load(it) }
}

android {
    namespace = "com.decode03.superapp"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.decode03.superapp"
        minSdk = 28
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                val storePath = keystoreProperties.getProperty("storeFile")
                    ?: throw GradleException("Missing 'storeFile' in keystore.properties")
                val resolvedStoreFile = rootProject.file(storePath)
                if (!resolvedStoreFile.exists()) {
                    throw GradleException("Keystore file not found at: ${resolvedStoreFile.absolutePath}")
                }
                storeFile = resolvedStoreFile
                storePassword = keystoreProperties.getProperty("storePassword")
                    ?: throw GradleException("Missing 'storePassword' in keystore.properties")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                    ?: throw GradleException("Missing 'keyAlias' in keystore.properties")
                keyPassword = keystoreProperties.getProperty("keyPassword")
                    ?: throw GradleException("Missing 'keyPassword' in keystore.properties")
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            } else {
                // If assembleRelease is executed without keystore.properties, fail immediately with clear error
                gradle.taskGraph.whenReady {
                    if (hasTask(":superapp:assembleRelease") || hasTask(":superapp:packageRelease")) {
                        throw GradleException(
                            "BUILD FAILED: 'keystore.properties' is missing from the project root directory (${rootProject.projectDir.absolutePath})! " +
                            "Both Super App and Child App must be signed with the same release keystore. " +
                            "Please copy 'keystore.properties.example' to 'keystore.properties' and set your key details."
                        )
                    }
                }
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        debug {
            // Can optionally use release signing if available to test signature permissions locally
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }
}

dependencies {
    implementation(project(":sso-common"))

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("androidx.browser:browser:1.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
