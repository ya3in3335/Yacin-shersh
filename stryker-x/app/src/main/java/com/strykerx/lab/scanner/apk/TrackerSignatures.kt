package com.strykerx.lab.scanner.apk

/**
 * Cherlogons Privacy Radar — our own, in-house signature database for detecting
 * third-party trackers, ad networks, analytics and crash/profiling SDKs bundled
 * inside an APK. Detection is fully offline: each signature is a DEX type-descriptor
 * marker matched against the strings already extracted during the DEX scan. No
 * external service is contacted — this capability is entirely ours.
 *
 * Presence of an SDK's classes in the DEX is a verifiable fact (the SDK is bundled),
 * so matches are reported as CONFIRMED. Whether a tracker is actively used at runtime
 * is a separate question the owner confirms.
 */
object TrackerSignatures {

    enum class Category(val label: String) {
        ADVERTISING("Advertising"),
        ANALYTICS("Analytics"),
        CRASH("Crash reporting"),
        LOCATION("Location"),
        PROFILING("Profiling / attribution"),
        IDENTIFICATION("Identification"),
        PUSH("Push / engagement")
    }

    data class Tracker(val name: String, val category: Category, val marker: String)

    /** Our curated signature set. `marker` is a DEX type-descriptor path fragment. */
    val ALL: List<Tracker> = listOf(
        // --- Advertising ---
        Tracker("Google AdMob", Category.ADVERTISING, "com/google/android/gms/ads"),
        Tracker("Facebook Ads (Audience Network)", Category.ADVERTISING, "com/facebook/ads"),
        Tracker("Unity Ads", Category.ADVERTISING, "com/unity3d/ads"),
        Tracker("ironSource", Category.ADVERTISING, "com/ironsource"),
        Tracker("AppLovin", Category.ADVERTISING, "com/applovin"),
        Tracker("Vungle", Category.ADVERTISING, "com/vungle"),
        Tracker("Chartboost", Category.ADVERTISING, "com/chartboost"),
        Tracker("InMobi", Category.ADVERTISING, "com/inmobi"),
        Tracker("Tapjoy", Category.ADVERTISING, "com/tapjoy"),
        Tracker("Mintegral", Category.ADVERTISING, "com/mbridge/msdk"),
        Tracker("Pangle (TikTok Ads)", Category.ADVERTISING, "com/bytedance/sdk/openadsdk"),

        // --- Analytics ---
        Tracker("Google Firebase Analytics", Category.ANALYTICS, "com/google/firebase/analytics"),
        Tracker("Google Analytics", Category.ANALYTICS, "com/google/android/gms/analytics"),
        Tracker("Google Tag Manager", Category.ANALYTICS, "com/google/android/gms/tagmanager"),
        Tracker("Flurry", Category.ANALYTICS, "com/flurry"),
        Tracker("Mixpanel", Category.ANALYTICS, "com/mixpanel/android"),
        Tracker("Amplitude", Category.ANALYTICS, "com/amplitude/api"),
        Tracker("Segment", Category.ANALYTICS, "com/segment/analytics"),
        Tracker("Umeng", Category.ANALYTICS, "com/umeng"),
        Tracker("Yandex Metrica", Category.ANALYTICS, "com/yandex/metrica"),
        Tracker("Tencent Stat (MTA)", Category.ANALYTICS, "com/tencent/stat"),
        Tracker("Matomo", Category.ANALYTICS, "org/matomo/sdk"),

        // --- Crash / performance ---
        Tracker("Firebase Crashlytics", Category.CRASH, "com/google/firebase/crashlytics"),
        Tracker("Crashlytics (legacy)", Category.CRASH, "com/crashlytics/android"),
        Tracker("Sentry", Category.CRASH, "io/sentry"),
        Tracker("Bugsnag", Category.CRASH, "com/bugsnag/android"),
        Tracker("New Relic", Category.CRASH, "com/newrelic/agent"),
        Tracker("Instabug", Category.CRASH, "com/instabug/library"),

        // --- Profiling / attribution ---
        Tracker("AppsFlyer", Category.PROFILING, "com/appsflyer"),
        Tracker("Adjust", Category.PROFILING, "com/adjust/sdk"),
        Tracker("Branch", Category.PROFILING, "io/branch/referral"),
        Tracker("Kochava", Category.PROFILING, "com/kochava"),
        Tracker("Singular", Category.PROFILING, "com/singular/sdk"),

        // --- Identification ---
        Tracker("Facebook Login/SDK", Category.IDENTIFICATION, "com/facebook/login"),

        // --- Push / engagement ---
        Tracker("OneSignal", Category.PUSH, "com/onesignal"),
        Tracker("Braze (Appboy)", Category.PUSH, "com/braze"),
        Tracker("Appboy (legacy)", Category.PUSH, "com/appboy"),
        Tracker("MoEngage", Category.PUSH, "com/moengage"),
        Tracker("Pushwoosh", Category.PUSH, "com/pushwoosh"),
        Tracker("CleverTap", Category.PUSH, "com/clevertap/android"),

        // --- Location ---
        Tracker("Google Location (FusedLocationProvider)", Category.LOCATION,
            "com/google/android/gms/location/FusedLocationProviderClient"),
        Tracker("Radar.io", Category.LOCATION, "io/radar/sdk"),
        Tracker("Gimbal", Category.LOCATION, "com/gimbal/android")
    )
}
