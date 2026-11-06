---
title: The agent's antivirus
nav: docs
description: What the SentrAI agent checks on each machine between scans, how a file is locked away, and the shared list of known-bad files.
---

# The agent's antivirus

Every antivirus does five things: it knows what bad files look like, it makes educated guesses about
files it has never seen, it checks files as they appear, it locks bad files away instead of deleting
them, and it keeps its lists up to date. The SentrAI agent does all five, with no extra packages to
install, and reports to the panel. It never deletes or stops anything itself: a person decides.

## What it checks

| Check | When | What it finds |
| --- | --- | --- |
| **Threat scan** | when someone presses Scan (or `sentrai jobs scan HOST`) | every file in the scan folders: web shells, reverse shells, crypto miners, droppers, container escapes, also inside `.jar` plugins |
| **File watch** | every 30 seconds | new or changed files in the same folders, checked right away |
| **Disguised programs** | in both | a program pretending to be a picture or document (`cat.jpg` that is really a program), double extensions (`invoice.pdf.exe`), a program in an upload or temporary folder, packed programs |
| **Known-bad fingerprints** | in both | files on the panel's shared list (below) |
| **Important files** | every 30 seconds | changes to SSH login keys, sudo rules, cron jobs, startup scripts, `/etc/ld.so.preload`, the Windows Startup folders; also changes made while the agent was stopped |
| **Ransomware** | every 30 seconds | 20 or more files rewritten into scrambled data or renamed to a new ending in one look, a ransom note, or a decoy file touched |
| **Running programs** | every 5 minutes | crypto miners, reverse shells, programs started from `/tmp` or whose file was deleted |
| **ClamAV** | with the threat scan, when ClamAV is installed | everything in ClamAV's own signature database |

Critical and high finds open a **Malware found** incident for that machine on the panel and alert
whoever answers for it. Medium ones (a packed program, a changed hosts file) are only listed and
written to the audit trail. If the panel cannot be reached, finds wait on the machine and are sent
when it answers.

The folders are the ones set on the machine itself, never chosen by the panel:
`SENTRAI_THREAT_PATHS` in `/etc/sentrai/agent.env` on Linux. The file watch uses them too, unless
`SENTRAI_WATCH_PATHS` names others.

## Lock a file away (quarantine)

```bash
sudo sentrai jobs threats web-01                       # what the file watch found, with ids
sudo sentrai jobs quarantine web-01 3f9c0a7d1e2b4c5a   # or an id from a threat scan's result
sudo sentrai jobs restore web-01 q-1a2b3c4d            # undo
```

The agent only moves a file it flagged itself, and only if it is still exactly the file it flagged.
The file is scrambled into the agent's quarantine folder so it cannot run from there, with a note of
where it was and its permissions. Restore puts it back exactly, and refuses if something else now
sits in its place.

On Linux the agent's service may only change files in its own folder, so it can read your folders
but not move a file out of them. To let it lock files away from a folder, allow that folder once:

```bash
sudo systemctl edit sentrai-agent      # add the two lines below, save, then:
sudo systemctl restart sentrai-agent
```

```ini
[Service]
ReadWritePaths=/srv/site
```

Without it, a quarantine job fails with a message saying so, and the file is left where it is.

## The shared fingerprint list

The panel keeps one list of known-bad files by fingerprint (SHA-256 or MD5). Every agent fetches it
about every 30 minutes and keeps a copy for when the panel is out of reach. It grows in two ways:

- **On its own.** A file a person locks away, on any machine or the panel, joins the list. The same
  file is then flagged on every other machine at its next look. This is what paid antivirus calls
  cloud reputation, kept inside your own machines.
- **By import.** `sudo sentrai signatures import FILE` reads a plain list (one fingerprint per line),
  a CSV export with a `sha256` column such as [MalwareBazaar](https://bazaar.abuse.ch/export/)'s
  (a free key is needed to download it), or ClamAV's `.hdb` / `.hsb` hash files.

Only fingerprints and short names are kept and sent. No file ever leaves a machine.

## Use ClamAV as well

ClamAV is free and has millions of signatures that it keeps up to date itself. When it is installed
on a machine, the agent's threat scan runs it on the same folders and adds what it finds. SentrAI
only calls the program; none of ClamAV's code is part of SentrAI.

```bash
sudo apt install clamav clamav-daemon     # Debian, Ubuntu. clamd makes scans much faster
sudo systemctl enable --now clamav-freshclam clamav-daemon
```

## Settings

In `/etc/sentrai/agent.env` (then `sudo systemctl restart sentrai-agent`):

| Setting | Default | What it does |
| --- | --- | --- |
| `SENTRAI_WATCH` | `on` | `off` turns the file watch, important files, ransomware and program checks off |
| `SENTRAI_WATCH_EVERY_S` | `30` | seconds between looks |
| `SENTRAI_WATCH_PATHS` | the scan folders | other folders to watch |
| `SENTRAI_WATCH_FILES` | | more important files or folders to watch (separated by `:`, `;` on Windows) |
| `SENTRAI_WATCH_IMPORTANT` | `on` | `off` stops watching the built-in list of important files |
| `SENTRAI_DECOYS` | `off` | `on` places a decoy file, `0000-sentrai-decoy-do-not-open.txt`, in each watched folder (on Linux the folder needs `ReadWritePaths` as for quarantine). Not for a website's public folder: visitors could see it |
| `SENTRAI_RANSOM_BURST` | `20` | how many scrambled or renamed files in one look raise the ransomware alarm |
| `SENTRAI_CLAMAV` | `auto` | `off`, or the path to `clamdscan` / `clamscan` |

`python -m agent status` on the machine shows what the watch keeps there: folders, important files,
decoys, the size of its copy of the fingerprint list and how many files are in quarantine.

## What it does not do

- Delete files or stop programs. Locking a file away is the strongest step, and only a person takes it.
- Hook into the operating system's kernel the way some paid products do. A look every 30 seconds
  catches nearly the same, with no driver to install.
- Send files to anyone. Only fingerprints leave a machine.
