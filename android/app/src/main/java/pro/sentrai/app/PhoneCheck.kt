package pro.sentrai.app

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.File

/** Looks at the phone's own settings. Runs only on the phone; [CheckRules.report] decides what is sent. */
object PhoneCheck {
    /** Where apps may come from without being flagged: Google Play and the big phone makers' own stores. */
    private val STORES = setOf("com.android.vending", "com.google.android.feedback", "com.sec.android.app.samsungapps",
        "com.huawei.appmarket", "com.heytap.market", "com.oppo.market", "com.xiaomi.market", "com.xiaomi.mipicks",
        "com.bbk.appstore", "com.amazon.venezia")
    private val SU_PATHS = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/xbin/su",
        "/data/local/bin/su", "/system/app/Superuser.apk", "/data/adb/magisk")

    fun run(context: Context): PhoneFacts {
        val pm = context.packageManager
        val outside = outsideApps(context, pm)
        val readers = screenReaders(context).filter { it in outside.keys }.mapNotNull { outside[it] }
        return PhoneFacts(
            screenLock = (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure,
            usbDebugging = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1,
            rooted = SU_PATHS.any { File(it).exists() } || (Build.TAGS ?: "").contains("test-keys"),
            encrypted = (context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager).storageEncryptionStatus in
                setOf(DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE, DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER),
            outsideAppNames = outside.values.sorted(),
            screenReadingAppNames = readers.sorted(),
            android = Build.VERSION.SDK_INT,
            patch = Build.VERSION.SECURITY_PATCH ?: "",
            appVersion = BuildConfig.VERSION_NAME,
        )
    }

    /** Apps the person installed that didn't come from an app store: package -> name shown on the phone. */
    @Suppress("DEPRECATION")
    private fun outsideApps(context: Context, pm: PackageManager): Map<String, String> {
        val apps = pm.getInstalledApplications(0)
        return apps.filter { a ->
            a.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0 &&
                a.packageName != context.packageName
        }.filter { a ->
            val installer = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) pm.getInstallSourceInfo(a.packageName).installingPackageName
                else pm.getInstallerPackageName(a.packageName)
            } catch (e: Exception) { null }
            installer == null || installer !in STORES
        }.associate { it.packageName to pm.getApplicationLabel(it).toString() }
    }

    private fun screenReaders(context: Context): Set<String> =
        (Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: "")
            .split(':').mapNotNull { it.substringBefore('/').takeIf { p -> p.isNotBlank() } }.toSet()

    /** Opens the settings page that fixes a finding. */
    fun open(context: Context, fix: Fix) {
        val action = when (fix) {
            Fix.SECURITY_SETTINGS -> Settings.ACTION_SECURITY_SETTINGS
            Fix.UPDATE_SETTINGS -> "android.settings.SYSTEM_UPDATE_SETTINGS"
            Fix.ACCESSIBILITY_SETTINGS -> Settings.ACTION_ACCESSIBILITY_SETTINGS
            Fix.DEVELOPER_SETTINGS -> Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS
            Fix.APPS_SETTINGS -> Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS
        }
        try {
            context.startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (e: ActivityNotFoundException) {
            context.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
    }
}
