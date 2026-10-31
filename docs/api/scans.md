---
title: Scans, quarantine and backups
nav: api
description: Scan the running programs and chosen folders, move a dangerous file into quarantine and back, and make, check and restore backups.
---

# Scans, quarantine and backups

These endpoints look after the machine the core runs on. The process scan lists the running programs
and suggests their log files. The threat scan looks inside chosen folders for web shells, crypto
miners and other signs of a break-in, and a file it flags can be moved into quarantine and back.
Backups keep copies of chosen folders and of SentrAI's own records. The dashboard's **Collector**
page runs the scans and the quarantine, and its **Backups** page the backups. To scan or back up a
machine that joined a central panel, queue a job for it with
[`POST /fleet/jobs`](fleet.html#post-fleetjobs): the job runs on that machine.

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.

Both scans only read. A file moves only when a person asks for it by its id from the latest scan,
and quarantine never deletes it.

## Scan the running programs

### `POST /system/scan`

List the programs running on this machine, recognise the known ones (web servers, databases, remote
access, SentrAI's own parts) and suggest where they keep their logs. The collector reads none of them
until a person approves a file with [`POST /log-sources`](events.html#post-log-sources). The scan
also looks for hostile-looking programs, such as a crypto miner or a shell wired to a remote address:
each critical or high one opens or joins a `malware` incident, once per program and sign. The scan is
written to the audit trail as `system_scan` and replaces the previous one, which is kept in memory only.

**Body** (optional)

```json
{"operator": "erick"}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `operator` | string | `operator` | who asked for the scan |

**Returns**, trimmed to one process and one suggestion:

```json
{
  "platform": "Linux", "enabled": true, "scanned": 81, "skipped_protected": 0, "recognised": 1,
  "threats": [
    {"key": "deleted-exe", "label": "program whose file was deleted after it started", "severity": "high",
     "pid": 85, "name": "kworker", "exe": "/usr/local/lib/.x/kworker (deleted)", "account": "(user)"}
  ],
  "notes": [], "error": null, "took_s": 0.02, "scanned_at": "2026-10-27T02:45:12+00:00", "new_alerts": 1,
  "processes": [
    {"pid": 3847, "name": "python", "program": "Python app", "layer": "web", "path": "/usr/bin/python3.11",
     "account": "root", "service": "", "log_options": []}
  ],
  "suggestions": [
    {
      "path": "/var/log/app/app.log", "kind": "file", "program": "app-server", "recognised": false,
      "layer": "web", "format": "text", "reasons": ["open by the process right now"],
      "files_found": 1, "already_watched": false, "id": "s1",
      "files": [
        {"id": "s1f1", "name": "/var/log/app/app.log", "size": 35335, "modified": "2026-10-27T02:42:38", "watched": false}
      ]
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `platform` | `Linux`, `Windows` or `Darwin` (macOS) |
| `scanned`, `recognised` | how many programs were looked at, and how many SentrAI knows; those are in `processes` (at most 400) |
| `skipped_protected` | programs counted but never described: password managers, credential stores and sensitive system programs such as `lsass`, plus the names in `process_scan.skip_processes` of the system profile |
| `threats` | hostile-looking programs. `key` and `label` name the sign, `severity` is `critical`, `high` or `medium`, `exe` is the program file and `account` the account it runs as |
| `new_alerts` | only when `threats` is not empty: how many of them were raised for the first time |
| `notes` | tips about recognised programs, such as a setting their logs need |
| `error` | why the list of programs could not be read, or `null` |
| `processes` | `program` is what SentrAI takes it for, `layer` where its logs belong, `path` the program file, `service` its Windows service, `log_options` the log options on its command line |
| `suggestions` | at most 40, those not yet read and the recognised ones first. Each is a file or a folder (`kind`) with the program it belongs to, why it was suggested (`reasons`), and the `layer` and `format` to read it with. `files` lists its files (at most 8 for a folder), each with the `id` that `POST /log-sources` takes, `modified` in the machine's local time, and `watched`, `true` once the collector reads it |

Personal details stay out: command lines are cut to the program and its log options with secrets
masked, home folders show as `~`, and a personal account shows as `(user)`. With process scanning
turned off (`process_scan.enabled` set to `false` in the system profile), the answer has
`"enabled": false`, a `note` and no programs or suggestions.

### `GET /system/scan`

The latest process scan, the same as the answer of [`POST /system/scan`](#post-systemscan), without
running a new one. Before the first scan, and after the core restarts, it is empty:

```json
{"suggestions": [], "processes": [], "scanned_at": null}
```

## Look for threats in files

### `POST /threats/scan`

Look inside the chosen folders for signs that a break-in already happened: a web shell in an upload
folder, a reverse shell or a downloader in a startup script, a crypto miner, a tool for breaking out
of a container, or a file on your own list of known-bad SHA-256 fingerprints. It only reads. Each
critical or high finding becomes an event that opens or joins a `malware` incident, once per file
and sign; a file that changes counts as new. Medium findings are only listed. The scan is written to
the audit trail as `threat_scan` and replaces the previous one, which is kept in memory only.

The folders are `threat_scan.paths` in the system profile or, when it names none,
`SENTRAI_THREAT_PATHS` (separated by `:`, or `;` on Windows). SentrAI's own folders are always
skipped, and so are files that match a pattern in `threat_scan.allow` and files over
`threat_scan.max_file_mb` (10). With folders set, the scan also runs on its own every
`threat_scan.every_minutes` (60).

**Body** (optional)

```json
{"operator": "erick", "paths": ["/var/www/site"]}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `operator` | string | `operator` | who asked for the scan |
| `paths` | list of strings | the folders above | folders, or single files, to scan this time instead |

**Returns**

```json
{
  "roots": ["/var/www/site"], "missing": [], "files_checked": 2, "files_not_checked": 0,
  "counts": {"critical": 1, "high": 0, "medium": 0},
  "took_s": 0.0, "scanned_at": "2026-10-27T02:45:12+00:00", "new_alerts": 1,
  "findings": [
    {
      "path": "/var/www/site/uploads/img.php",
      "sha256": "41b3ad0435f917526c725f98b62e3741a77784ce0123d2fda9af90b0325063f5",
      "size": 31, "key": "php-eval-request", "kind": "webshell", "severity": "critical",
      "label": "runs code sent in a web request", "line": 1,
      "snippet": "<?php @eval($_POST['cmd']); ?>", "id": "t1"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `roots`, `missing` | the folders scanned, and those of them that do not exist |
| `files_checked`, `files_not_checked` | files looked at, and files left over after the limit of 50,000 per scan |
| `counts` | findings per severity |
| `new_alerts` | findings raised for the first time by this scan |
| `findings` | worst first, at most 300. `id` (`t1`, `t2` and so on) is what [`POST /threats/{finding_id}/quarantine`](#post-threatsfinding_idquarantine) takes, until the next scan. `kind` is `webshell`, `backdoor`, `reverse_shell`, `miner`, `dropper`, `obfuscation`, `container_escape`, `persistence` or `known_malware`; `key` and `label` name the sign that matched. `line` and `snippet` show the matching line, cut to 160 characters with secrets masked. A match inside a Java archive has `entry`, the file inside it, and `line` is `null` |

When there is nothing to scan, the answer says why and the previous scan stays:

```json
{"enabled": true, "findings": [], "roots": [], "note": "No folders to scan. Add threat_scan.paths to the system profile, or pass paths."}
```

With `threat_scan.enabled` set to `false`, `enabled` is `false` and the note says threat scanning is
turned off.

```bash
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"operator": "erick"}' http://127.0.0.1:8000/threats/scan
```

### `GET /threats`

The latest threat scan, whoever started it (a person or the schedule), the same as the answer of
[`POST /threats/scan`](#post-threatsscan). Before the first scan, and after the core restarts:

```json
{"findings": [], "scanned_at": null, "every_minutes": 60}
```

`every_minutes` is how often the scan runs on its own, or `null` when no folders are set.

## Check packages for known vulnerabilities

The dependency scan lists what is installed on the core's machine: SentrAI's own Python environment,
every virtualenv, npm project (package-lock.json) and pinned requirements file under the folders in
`dep_scan.paths` in the system profile (or `SENTRAI_DEP_PATHS`), and Debian or Ubuntu packages
(`SENTRAI_DEP_OS=off` skips them). It asks [OSV](https://osv.dev), the open vulnerability database,
about each name and version (`SENTRAI_OSV_URL` sets another server) and reports each vulnerable
package with the version that fixes it. Only names and versions leave the machine. It changes nothing:
on this machine each finding says what to do (`how`). Joined machines run the same scan as a
[`dep_scan` job](fleet.html#post-fleetjobs), where one-press updates with undo are offered.

### `POST /deps/scan`

Runs the scan now and waits for it. Written to the audit trail as `dep_scan`.

**Body**: `{"operator": "erick"}` (optional).

**Returns**

```json
{
  "scanned_at": "2026-10-31T05:10:00+00:00",
  "roots": ["/srv/app"],
  "missing": [],
  "sources": [{"kind": "python", "ecosystem": "PyPI", "path": "/srv/app/.venv", "packages": 35}],
  "packages_checked": 35,
  "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "no_fix_os": 0},
  "took_s": 2.1,
  "findings": [{"id": "3f1c9a0b7d2e4f61", "kind": "python", "ecosystem": "PyPI", "name": "requests",
                "version": "2.32.3", "fixed": "2.33.0", "severity": "high", "vuln_count": 1,
                "vulns": [{"id": "GHSA-9hjg-9r4m-mvj7", "aliases": ["CVE-2026-0001"], "summary": "..."}],
                "update": "safe", "how": "Update requests 2.32.3 → 2.33.0 (SentrAI can undo it).",
                "path": "/srv/app/.venv"}],
  "note": null
}
```

| Field | Meaning |
| --- | --- |
| `kind` | `python` (a virtualenv, or SentrAI's own), `npm`, `pinned` (a requirements file) or `os` |
| `fixed` | the lowest version that fixes every known vulnerability, or `null` when none does yet |
| `severity` | the worst rating among them: `critical`, `high`, `medium` (also unrated) or `low` |
| `update` | `safe`: one press on a joined machine updates it and can undo it; `manual`: `how` says the step; `none`: no fix yet |
| `counts.no_fix_os` | OS packages with flaws the distribution has not fixed yet (counted, not listed) |
| `note` | why the scan could not finish, such as OSV being out of reach; then `findings` is empty |

### `GET /deps`

The latest dependency scan of this machine, as [`POST /deps/scan`](#post-depsscan) returned it.
Before the first one, and after the core restarts: `{"findings": [], "scanned_at": null}`.

## Quarantine a file

### `POST /threats/{finding_id}/quarantine`

Move one file from the latest threat scan out of reach, by its finding id. It is moved, never
deleted, into the core's `data/quarantine` folder (`SENTRAI_QUARANTINE` sets another) and made
read-only so it cannot run there, with a note of where it came from. It is moved only if its
contents still match what the scan saw. Written to the audit trail as `file_quarantined`.

**Body**

```json
{"operator": "erick", "reason": "web shell in uploads"}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `operator` | string | required | who quarantines it |
| `reason` | string | `""` | why, kept with the file and in the audit trail |

**Returns**

```json
{
  "ok": true,
  "quarantine_id": "q-20261027024512-41b3ad04",
  "file": "/var/www/site/uploads/img.php",
  "note": "Moved out of reach, not deleted. Restore puts it back."
}
```

`quarantine_id` is `q-`, the time and the first 8 characters of the file's SHA-256.

**Errors**

- 404 `t9 is not in the latest threat scan; scan again`: no such finding in the latest scan, or the
  core restarted since.
- 409 `that file is gone or unreadable; scan again`: it was moved, deleted or quarantined already.
- 409 `that file changed since the scan; scan again before quarantining it`.
- 409 `could not move the file (PermissionError); SentrAI may lack write access there`: the core's
  account may not change the folder the file is in.

### `GET /quarantine`

Every file in quarantine, oldest first.

**Returns**

```json
[
  {
    "id": "q-20261027024512-41b3ad04",
    "original": "/var/www/site/uploads/img.php", "name": "img.php",
    "sha256": "41b3ad0435f917526c725f98b62e3741a77784ce0123d2fda9af90b0325063f5", "size": 31,
    "finding": {"key": "php-eval-request", "kind": "webshell", "severity": "critical",
                "label": "runs code sent in a web request", "line": 1, "entry": null},
    "operator": "erick", "reason": "web shell in uploads", "at": "2026-10-27T02:45:12", "mode": 420
  }
]
```

`finding` is what the scan matched. `at` is when the file was moved, in the machine's local time.
`mode` is the file's permission bits as a number (420 is `0644`), put back on restore. `reason` is
`null` when none was given.

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/quarantine
```

### `POST /quarantine/{qid}/restore`

Put a quarantined file back where it came from, with its old permissions. Written to the audit trail
as `file_restored`.

**Body**

```json
{"operator": "erick"}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `operator` | string | required | who restores it |
| `justification` | string | `null` | accepted, but not used here |

**Returns**

```json
{"ok": true, "file": "/var/www/site/uploads/img.php"}
```

**Errors**

- 404 `q-20261027024512-41b3ad04 is not in quarantine`: no such id, or it was restored already.
- 409 `a file already exists at the original location; move it first`.

## Back up and restore

A backup copies the folders in `backup.paths` of the system profile (or `SENTRAI_BACKUP_PATHS`) and
SentrAI's own data: the settings file, the data folder and a consistent snapshot of the audit
database. Each one is a `.tar.gz` with a list of every file and its SHA-256 inside, plus a note
beside it. The archive's own SHA-256 goes into the audit trail, so a backup changed later fails its
check. Backups run every `backup.every_hours` (24) and the newest `backup.keep` (7) are kept; see
[Backups](../settings.html#backups) for the settings. Only one backup, check or restore runs at a
time; another request waits for it to finish.

### `GET /backups`

The backup settings in use, when the next backup is due, and every backup kept, newest first.

**Returns**

```json
{
  "enabled": true, "every_hours": 24.0, "keep": 7,
  "folders": ["/var/www/site"], "include_sentrai": true, "copy_to": null,
  "stored_in": "/var/lib/sentrai/core/backups",
  "next_due": "2026-10-28T02:45:12+00:00", "overdue": false, "last_error": null,
  "backups": [ ... ]
}
```

| Field | Meaning |
| --- | --- |
| `enabled` | `false` when `backup.enabled` is `false` in the system profile |
| `every_hours` | hours between scheduled backups; `null` when the schedule is off |
| `folders`, `include_sentrai` | what each backup holds: these folders, and SentrAI's own data unless `backup.include_sentrai` is `false` |
| `copy_to` | where a second copy of each backup goes, such as another drive or share, or `null` |
| `stored_in` | where backups are kept: `SENTRAI_BACKUP_DIR`, by default `backups` beside the audit database |
| `next_due` | when the next scheduled backup runs: `now` before the first one, `null` when the schedule is off |
| `overdue` | `true` when the last backup is more than twice the interval old |
| `last_error` | the last failure since the core started, `{"at", "reason", "error"}`, or `null`; a backup that works clears it |
| `backups` | every backup kept, newest first, each a [backup record](#the-backup-record) |

### `POST /backups`

Take a backup now, with the reason `manual`. Big folders take a while; the dashboard waits up to 10
minutes. A backup that works is written to the audit trail as `backup_made`, and the oldest backups
beyond `keep` are then deleted (`backup_pruned`). A backup that fails is written as `backup_failed`
and queues a `backup_failed` alert for the person on duty, and so does a second copy that fails.

**Body** (optional): `{"operator": "erick"}`. `operator` is a string, who asked for it, by default
`operator`.

**Returns** the new [backup record](#the-backup-record), with `ok` and the backups deleted to stay
within `keep`:

```json
{
  "ok": true, "id": "b-20261027-024512",
  "created": "2026-10-27T02:45:12+00:00", "created_ts": 1793069112.6452723,
  "by": "erick", "reason": "manual", "folders": ["/var/www/site"], "missing": [], "sentrai": true,
  "files": 11, "bytes": 182151, "archive_bytes": 27047,
  "sha256": "aac085c1b1250db7a332bf2984caf24613e2a6ca8fc3e642605a4143e7ea8fe4",
  "manifest_sha256": "b42637b3e963acfbe1e281244ffcd6401f4ce27efc5ae42fbad5f681226c2e60",
  "skipped": [], "copy": null, "verified": null, "pruned": []
}
```

A backup that fails still answers 200, with `ok` set to `false`, the reason in `error` and the note
`The backup failed; nothing was kept.` The usual reasons: nothing to back up (no folders set and
SentrAI's own data left out), folders larger than `backup.max_total_mb` (5,120 MB), or not enough
free disk space. With backups turned off in the system profile, the answer is
`{"ok": false, "note": "Backups are turned off in the system profile."}`.

```bash
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"operator": "erick"}' http://127.0.0.1:8000/backups
```

### `POST /backups/{bid}/verify`

Check that a backup is intact: the archive against its note and against its `backup_made` record in
the audit trail, then every file inside against its SHA-256. The result is saved on the backup as
`verified` and written to the audit trail as `backup_verified`.

**Body** (optional): `{"operator": "erick"}`, as for [`POST /backups`](#post-backups).

**Returns**

```json
{"ok": true, "backup": "b-20261027-024512", "files_checked": 11, "problems": []}
```

A backup that fails its check still answers 200, with `ok` set to `false` and each problem in plain
words, such as `the archive does not match the fingerprint in the audit trail`.

**Errors**

- 404 `b-20261026-024500 is not a backup`: no backup has that id.
- 404 `b-20261026-024500 has lost its archive`: its note is there, but the `.tar.gz` is gone.

### `POST /backups/{bid}/restore`

Unpack a backup. It is checked first, as by `verify`. By default the files go into a new folder and
nothing live changes: compare them, then copy back what you need. With `in_place` and the backup's id
typed again in `confirm`, they go back over the original folders, after a safety backup of those
folders (reason `before_restore`), so the restore itself can be undone. Files made after the backup
are left alone. SentrAI's own data is never written over while the core runs: a new-folder restore
unpacks it into a `sentrai` folder, an in-place one skips it, and the `note` says how to swap it in.
Written to the audit trail as `backup_restored`, with a `backup_restored` alert for the person on
duty.

**Body**

```json
{"operator": "erick"}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `operator` | string | required | the person asking for the restore; it may not be empty |
| `in_place` | boolean | `false` | put the files back where they came from |
| `confirm` | string | `""` | the backup's id, typed again; needed with `in_place` |
| `target` | string | `restores/<id>-<time>` beside the audit database | the folder for a new-folder restore, empty or not there yet; not used with `in_place` |

In a new-folder restore, each backed-up folder goes into `files/<n>-<folder name>` and SentrAI's own
data into `sentrai`. To restore in place:

```json
{"operator": "erick", "in_place": true, "confirm": "b-20261027-024512"}
```

**Returns**

```json
{
  "ok": true, "backup": "b-20261027-024512", "in_place": false,
  "restored_to": "/var/lib/sentrai/core/restores/b-20261027-024512-20261027-031502",
  "files_restored": 11, "failed": [], "safety_backup": null,
  "note": "Nothing live was changed. Compare the restored files, then copy back what you need, or restore again with 'in place'. SentrAI's own data is never written over while it runs. It is in the sentrai folder. To use it: stop SentrAI, copy sentrai/data into the core's data folder and sentrai/config.json to the settings file, then start SentrAI."
}
```

`restored_to` is the folder, or `in place`. `failed` lists the files that could not be written, with
why (at most 20); `ok` is `false` when any failed or nothing was written. `safety_backup` is the id
of the safety backup an in-place restore took: restore that one in place to undo this one.

On a server installed with `deploy/install.sh`, the core may only write under `/var/lib/sentrai/core`.
To restore in place there, add the folders to `ReadWritePaths=` in `sentrai-core.service`, or restore
into a new folder and copy back by hand.

**Errors**

- 404 `b-20261026-024500 is not a backup`, or `has lost its archive`, as for `verify`.
- 409 `a restore needs the name of the person asking for it`: `operator` is empty.
- 409 `putting files back in place overwrites live files: type the backup id (b-20261027-024512) as confirmation`:
  `in_place` without the right `confirm`.
- 409 `this backup failed its check, so it will not be restored: ...`, with the first problem found.
- 409 `could not take a safety backup of the current files first, so nothing was restored: ...`.
- 409 `the restore folder is not empty; pick a new one`: `target` holds files already.

## The backup record

What `GET /backups` lists and `POST /backups` answers with, as in the example above.

| Field | Meaning |
| --- | --- |
| `id` | `b-` and the machine's local date and time, such as `b-20261027-024512`; `-2`, `-3` are added when two land in the same second |
| `created`, `created_ts` | when it was made, as ISO 8601 and as Unix time in seconds |
| `by` | who asked for it: a person's name, or `schedule` |
| `reason` | `manual`, `schedule` or `before_restore` (the safety backup an in-place restore takes) |
| `folders`, `missing` | the folders it holds, and the ones that did not exist at the time |
| `sentrai` | `true` when SentrAI's own data is in it |
| `files`, `bytes` | how many files it holds and their total size |
| `archive_bytes` | the size of the `.tar.gz` |
| `sha256` | the archive's SHA-256, also in its `backup_made` audit record |
| `manifest_sha256` | the SHA-256 of the file list inside the archive |
| `skipped` | files that could not be read, so are not in it (at most 50) |
| `copy` | the second copy: `null` without `copy_to`, else `{"ok", "to"}`, with `error` when it failed |
| `verified` | the last check: `null` until `verify` or a restore runs, then `{"ok", "at", "problems"}` |
