package pro.sentrai.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Every few hours, when the phone is online: runs the phone check, sends its yes/no answers, and shows a
 * notification for each new coaching note (and, for owners, new alerts). No Google push service is needed.
 */
class SyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val store = Store(applicationContext)
        if (!store.signedIn) return@withContext Result.success()
        try {
            sync(applicationContext, store)
            Result.success()
        } catch (e: PanelError) {
            if (e.status == 401) store.signOut()
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }

    companion object {
        private const val WORK = "sentrai-sync"
        const val CHANNEL = "coach"

        fun schedule(context: Context) {
            val req = PeriodicWorkRequestBuilder<SyncWorker>(6, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.KEEP, req)
        }

        fun cancel(context: Context) = WorkManager.getInstance(context).cancelUniqueWork(WORK)

        /** One round: check the phone, fetch notes and alerts, notify about what's new. Returns the latest /mobile/me. */
        fun sync(context: Context, store: Store): JSONObject {
            val client = store.client()
            client.post("/mobile/check", JSONObject(CheckRules.report(PhoneCheck.run(context))))
            val me = client.get("/mobile/me")
            val seen = store.notified.toMutableSet()
            val fresh = mutableListOf<Pair<String, String>>()
            me.optJSONObject("coach")?.optJSONArray("notes")?.objects()?.forEach { n ->
                val id = n.str("id")
                if (id !in seen && n.str("status") == "new") fresh += id to n.str("text").split("\n\n").drop(1).firstOrNull().orEmpty()
                seen += id
            }
            if (me.optBoolean("sees_alerts")) {
                client.get("/mobile/alerts").optJSONArray("alerts")?.objects()?.forEach { a ->
                    val id = "alert:" + a.str("id")
                    if (id !in seen) fresh += id to (a.str("title") + ": " + a.str("what"))
                    seen += id
                }
            }
            store.notified = seen
            fresh.take(5).forEach { (id, text) -> notify(context, id, text) }
            return me
        }

        private fun notify(context: Context, id: String, text: String) {
            if (Build.VERSION.SDK_INT >= 33 &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "Notes from SentrAI", NotificationManager.IMPORTANCE_DEFAULT))
            val open = PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val title = if (id.startsWith("alert:")) "New alert" else "A note from SentrAI"
            val n = NotificationCompat.Builder(context, CHANNEL)
                .setSmallIcon(R.drawable.ic_notify)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setContentIntent(open)
                .setAutoCancel(true)
                .build()
            try {
                NotificationManagerCompat.from(context).notify(id.hashCode(), n)
            } catch (e: SecurityException) {
                // notifications were turned off for the app
            }
        }
    }
}
