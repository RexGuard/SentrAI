# CactAI: Recording Checklist (Windows 11)

Deadline: video due **2026-09-29**. Aim to have a usable take by the evening of the 28th and keep the 29th for re-takes and editing.

Owner: Erick records the demo, Ishmail records narration, Hozen runs this checklist and names/backs up files.

---

## 1. The day before

- [ ] `mvp\run_demo.ps1` runs end to end on a clean start (core :8000, lab app :5000, dashboard :8501, notifier).
- [ ] `POST /demo/reset` works, so every take starts from risk ≈ 8, green, empty incident queue.
- [ ] Telegram bot token set; a test message arrives on the demo phone / Telegram Desktop. If Telegram is unavailable, the dashboard alert panel is the fallback (say so on camera).
- [ ] TypeSafe API key set and Jev answers. If not, rules fallback is on and the script line **[FALLBACK]** is read.
- [ ] Replay mode tested (see section 5).
- [ ] `DEMO_SPEED=60` confirmed (1 real minute = 1 demo hour). For a shorter video, a higher value (for example 240, 1 real minute = 4 demo hours) makes the gauge climb faster; if you change it, change the spoken line too.
- [ ] Slides exported to PDF and PNG (one PNG per slide) for inserting in the edit.
- [ ] All `[SOURCE PENDING]` and `[CHECK]` items resolved or removed from the script.

## 2. Machine prep (15 minutes before recording)

- [ ] Plug in the charger; Windows power mode: **Best performance**.
- [ ] Turn on **Do not disturb** (Settings > System > Notifications). Close Outlook, Teams, Discord, WhatsApp, browser tabs with personal info.
- [ ] Hide desktop icons (right-click desktop > View > uncheck Show desktop icons). Use a plain wallpaper.
- [ ] Display scale 100% or 125%; resolution 1920×1080. Record at 1080p.
- [ ] Browser: new profile or guest window, bookmarks bar hidden, zoom 110 to 125% so the gauge is readable in the video.
- [ ] Terminal: Windows Terminal, font size 16 to 18, dark or light theme consistently, clear the screen (`cls`) before each take.
- [ ] Make sure no real personal data, tokens or API keys are visible anywhere (env vars, `.env` files, terminal history). Run `cls` after setting keys.

## 3. Screen layout

Recommended 1920×1080 layout (Win + arrow keys to snap):

| Area | Window | Why |
| --- | --- | --- |
| Left 2/3 | Browser: dashboard `http://127.0.0.1:8501` | The gauge and incident queue are the star |
| Right top 1/3 | Telegram Desktop (or phone mirrored via Phone Link) | Shows the ignored alert and buttons |
| Right bottom 1/3 | Windows Terminal: "attacker" tab | Shows brute force, SQLi, then HTTP 403 |

Keep a second terminal tab for services (started by `run_demo.ps1`) but do **not** show it on camera; its logs are noisy.

Extra browser tabs, opened in advance, in this order:
1. Dashboard `http://127.0.0.1:8501`
2. Evidence report `http://127.0.0.1:8000/reports/<incident_id>.md` (or the dashboard's report view)
3. Audit log `http://127.0.0.1:8000/audit` (shows `chain_valid: true`)

## 4. Order of commands during the take

Fill in the exact commands from `mvp\run_demo.ps1` once the lead finalises it. Placeholders:

| Step | Script time | Action | Command / click (placeholder) |
| --- | --- | --- | --- |
| 0 | before take | Start everything | `.\mvp\run_demo.ps1` [exact flags TBD] |
| 0b | before take | Reset state | `.\mvp\run_demo.ps1 -Reset` or `POST /demo/reset` [TBD] |
| 1 | 1:40 | Show green dashboard | dashboard **Review** page (the home page is Configuration) |
| 2 | 1:55 | Brute force | `[TBD: brute-force command from mvp\lab]` |
| 3 | 2:05 | Point at the Classifier bubble, then the classification | **Classifier** page |
| 4 | 2:18 | Telegram alert arrives | do **not** press any button |
| 5 | 2:30 | Wait for penalty to climb | wait ~2 to 6 real minutes (cut in edit, see section 7) |
| 6 | 2:50 | SQL injection | `[TBD: SQLi command from mvp\lab]` |
| 7 | 3:02 | Show Needle approval and the blocks | **Action taker** page (Needle reviews panel) |
| 8 | 3:10 | Show blocklist with TTL 2h | **Action taker** page, Active containment |
| 9 | 3:14 | Attacker retries, gets 403 | `[TBD: retry command]` |
| 10 | 3:18 | Open evidence report | **Reports** page |
| 11 | 3:28 | Rollback or Make Permanent with justification | **Approvals** page |
| 12 | 3:36 | Show audit log, chain valid | **Audit trail** page |

## 5. Backup: replay mode

Use if the live attack is flaky, slow or the network misbehaves.

- [ ] Command: `[TBD: replay command from mvp\lab, e.g. python simulate.py / replay script]`
- [ ] Replay feeds recorded attack logs through the same collector → core pipeline; the dashboard, Telegram, report and blocklist behave the same.
- [ ] Read the **[REPLAY]** line in the script. Do not present a replay as live.
- [ ] If Jev fails mid-take, keep going on the rules fallback and read the **[FALLBACK]** line; incident card should show `classified_by: rules`.
- [ ] Last resort: record the dashboard screen-by-screen as stills and narrate over them.

## 6. Recording tools

**Option A: OBS Studio (recommended)**
- Settings > Output: Recording format **MKV** (safe if OBS crashes), then File > Remux Recordings to MP4. Encoder: hardware (NVENC/AMF/QuickSync) if available.
- Settings > Video: Base and Output 1920×1080, 30 fps.
- Source: **Display Capture** for the whole layout, or three **Window Capture** sources arranged in a scene.
- Audio: disable Desktop Audio (or keep it low) so Telegram pings don't clip; add Mic/Aux only if narrating live.
- Set a hotkey for Start/Stop recording so no menus appear in the video.

**Option B: Xbox Game Bar (built in)**
- `Win + Alt + R` starts/stops recording; `Win + G` opens the bar.
- Limitation: records **one app window** only, not the desktop or multiple windows. Use it only as a quick backup (for example, record the dashboard browser window alone).
- Files land in `C:\Users\<you>\Videos\Captures`.

**Option C: Snipping Tool screen recording** (`Win + Shift + R`) also works for a region with multiple windows.

## 7. Handling the waiting time

The inaction penalty needs several real minutes at `DEMO_SPEED=60`.
- Keep recording; in the edit, speed up that segment (4× to 8×) with an on-screen caption "time sped up" and a clock overlay, or cut with a "6 demo hours later" card.
- Never fake the gauge values; only speed up or cut real footage.

## 8. Audio

- [ ] Record narration separately (Ishmail, Hozen) in a quiet, soft-furnished room; phone voice memo close to the mouth is better than a far laptop mic.
- [ ] Headset or USB mic if available; mic 10 to 15 cm from mouth, slightly off-axis.
- [ ] Record 5 seconds of silence first (for noise reduction in the editor).
- [ ] Speak slower than feels natural; pause between lines so they are easy to cut.
- [ ] Erick can narrate the demo live while recording, or voice over afterwards if the take needs speeding up.
- [ ] Check levels: peaks around -6 dB, never clipping. Normalise all voices to the same loudness in the editor.
- [ ] No background music under speech, or very quiet (-25 dB or lower).

## 9. File naming and storage

Store raw files in a shared folder (not in the git repo; video files are large).

```
CactAI_<part>_<take>_<YYYYMMDD>.<ext>
CactAI_demo_take01_20260928.mkv
CactAI_demo_replay_take02_20260928.mkv
CactAI_voice_ishmail_hook_take01_20260928.wav
CactAI_slides_v3_20260928.pdf
CactAI_final_v1_20260929.mp4
```

- [ ] Hozen copies every good take to a second location (USB or cloud drive) right after recording.
- [ ] Keep a short `takes.txt` note: file name, good/bad, what went wrong, whether it is live or replay.

## 10. Editing

- [ ] Order follows `VIDEO_SCRIPT.md` timestamps.
- [ ] Captions/subtitles for all speech (auto-generate in Clipchamp/CapCut, then fix names: CactAI, Jev, Saguaro, Needle, PDPC).
- [ ] Zoom in on the gauge, the Telegram "Ack: none" and `chain_valid: true` moments.
- [ ] Label on screen when footage is sped up, replayed, or uses fallback classification.
- [ ] Source citations on screen for every factual claim (PDPC case, PDPA penalty, Computer Misuse Act).

## 11. Submission checklist

- [ ] Final length matches the hackathon limit [CHECK the rules: assumed 5:00, trim plan to 3:00 in `VIDEO_SCRIPT.md`].
- [ ] Export: MP4 (H.264 + AAC), 1920×1080, 30 fps.
- [ ] Watch the full export once end to end with sound, and once on a phone.
- [ ] No personal data, real tokens, API keys or notifications visible in any frame.
- [ ] All `[SOURCE PENDING]` / `[CHECK]` resolved; all `{values}` match what is on screen.
- [ ] Team names and roles correct on the team slide.
- [ ] File named `CactAI_final_<date>.mp4`; uploaded to the required platform; the link opens in a private/incognito window.
- [ ] Slides PDF, architecture diagram and repo link attached if the submission form allows.
- [ ] Submit before the deadline with at least a few hours of margin; screenshot the confirmation.
