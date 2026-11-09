# SentrAI for Android

The phone app for staff and owners. It talks to the panel's `/mobile/*` endpoints
([API reference](../docs/api/mobile.md)) through the same address as the web dashboard.

## What it does

| | Staff | Owners, Admins, Auditors |
| --- | --- | --- |
| Sign in | work email and a password, set once from an app invite (Coach page, or `sentrai coach app-invite EMAIL`) | the web dashboard's email, password and authenticator code |
| Home | their own coaching notes, with one-tap answers and one-minute lessons | the same, if they are on the coach's list |
| Phone check | screen lock, updates, apps from outside the Play Store, apps that can read the screen, USB debugging, rooting | the same |
| Link checker | paste a link or share it to SentrAI; checked on the phone, never sent | the same |
| Something looks wrong | a staff report | the same |
| Alerts | | open alerts in plain words, staff reports, team totals |

Every 6 hours, when online, the app runs the phone check and shows a notification for each new note
(and new alerts for owners). It needs no Google push account.

## Privacy

- Only yes/no answers and two counts leave the phone (`CheckRules.report`). App names and links stay on it.
- Nothing about messages, photos, browsing, location or contacts is read.
- The sign-in key is encrypted with a key in Android's keystore; the app turns backups off.
- A panel with its own (self-signed) certificate is trusted only after the person checks its fingerprint
  with their admin; the app then pins it.

## Build

GitHub builds the app on every pull request that touches `android/` (workflow "Android app") and keeps
the APK as the `sentrai-android-debug` download on the run's page. To build it yourself you need JDK 17
and the Android SDK (Android Studio has both):

```bash
cd android
./gradlew testDebugUnitTest assembleDebug   # app/build/outputs/apk/debug/app-debug.apk
```

Install the APK by opening it on the phone (allow "install unknown apps" for the browser or Files app
once), or push it with your company's device management.

## The Play Store, later

The phone check needs `QUERY_ALL_PACKAGES` to count apps from outside the Play Store. Google allows it
for security apps after a review of the store listing, so a Play Store release needs: a release signing
key, the permission declaration form, a privacy policy page and the Data safety form (what is sent: the
yes/no answers above). Until then, install the APK directly or through device management.
