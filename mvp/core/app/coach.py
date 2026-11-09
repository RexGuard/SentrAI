"""Security Coach: SentrAI teaches each member of staff, right after they do something risky with a work account.

Connectors (added in later updates) read the activity log that work apps such as Google Workspace or Microsoft 365
keep for their admins and send SentrAI one short record per action: who, which app, what kind of action, when, from
which country. This module turns a risky action into a "moment", picks a one-minute lesson for it (a deeper one when
the same slip happens again), writes a kind note for the person, and keeps their progress.

Privacy by design, enforced here rather than only promised in the notice:
- Nothing is recorded until an Owner or Admin has shared the staff notice and ticked the checklist for each region
  the company works in.
- Only the apps, kinds of action and people the admin chose are recorded; everything else is dropped on arrival.
- Each record keeps a fixed, short set of fields. Message and file contents are never accepted. File names are
  dropped unless the admin turns them on; by default a file shows only as "a spreadsheet", "a document" and so on.
  Sign-in addresses are reduced to a country.
- Where the law leans on consent (see REGIONS), nothing about a person is recorded until they confirm the notice.
- Raw activity and coaching notes are deleted when their retention period (set on the Privacy page) runs out.
- Owners see team totals; names show only for urgent moments (a likely stolen account) unless the admin turns
  names on, which the staff notice then says.
- A person's data can be exported or erased in one step.

The data lives in coach.json (sentrai_paths "core.coach"). Every settings change, erase and urgent moment goes on
the audit record.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable

DAY = 86400.0
MONTH = 30.4 * DAY
REPEAT_WINDOW = 90 * DAY  # a slip again within this window gets the next, deeper lesson
MAX_EVENTS = 500  # per call
LEVELS = ("tip", "fix_soon", "urgent")
LEVEL_WORDS = {"tip": "Tip", "fix_soon": "Fix soon", "urgent": "Urgent"}

# --------------------------------------------------------------------------- the apps SentrAI can connect to
# status: "sample" = only sample data until its connector ships; "planned" = in a later wave.
APPS: list[dict[str, Any]] = [
    {"key": "google", "name": "Google Workspace", "covers": "Gmail, Drive, Meet, Google sign-in", "wave": 1,
     "sees": "Sign-ins, file sharing, mail forwarding rules, apps given access to the account, blocked phishing.",
     "needs": "Any Workspace plan, and a read-only admin connection."},
    {"key": "microsoft", "name": "Microsoft 365 and Entra ID", "covers": "Outlook, OneDrive, SharePoint, Teams, "
     "Microsoft sign-in", "wave": 1,
     "sees": "Sign-ins, file sharing, mail forwarding rules, apps given access, Teams sharing, blocked phishing.",
     "needs": "The audit log (on by default). Some sign-in detail needs Entra ID P1."},
    {"key": "okta", "name": "Okta", "covers": "Single sign-on", "wave": 2,
     "sees": "Sign-ins, 2-step sign-in changes, new devices.", "needs": "Any plan, with a read-only API token."},
    {"key": "slack", "name": "Slack", "covers": "Chat", "wave": 2,
     "sees": "Sign-ins, public file links, apps added, outside people invited.",
     "needs": "The full activity log needs Enterprise Grid; smaller plans show sign-ins only."},
    {"key": "zoom", "name": "Zoom", "covers": "Meetings", "wave": 2,
     "sees": "Sign-ins, meetings without a passcode, recordings shared publicly.", "needs": "Pro plan or above."},
    {"key": "dropbox", "name": "Dropbox", "covers": "File storage", "wave": 2,
     "sees": "File and folder sharing, large downloads.", "needs": "A Business plan."},
    {"key": "box", "name": "Box", "covers": "File storage", "wave": 2,
     "sees": "File and folder sharing, large downloads.", "needs": "A Business plan."},
    {"key": "github", "name": "GitHub", "covers": "Code", "wave": 2,
     "sees": "Code made public, secrets pushed into code, outside collaborators.", "needs": "An organisation plan."},
    {"key": "salesforce", "name": "Salesforce", "covers": "Customer records", "wave": 2,
     "sees": "Sign-ins, large exports of customer data.", "needs": "Login history on all plans; exports need Event "
     "Monitoring."},
    {"key": "atlassian", "name": "Jira and Confluence", "covers": "Projects and wiki", "wave": 3,
     "sees": "Sign-ins and public sharing, where the plan's log allows.", "needs": "Atlassian Guard or Enterprise."},
    {"key": "notion", "name": "Notion", "covers": "Notes and wiki", "wave": 3,
     "sees": "Pages shared to the web, outside guests.", "needs": "Enterprise plan."},
    {"key": "hubspot", "name": "HubSpot", "covers": "Sales and marketing", "wave": 3,
     "sees": "Sign-ins and large exports.", "needs": "Enterprise plan."},
    {"key": "zoho", "name": "Zoho", "covers": "Office apps and records", "wave": 3,
     "sees": "Sign-ins and sharing.", "needs": "Zoho One or Workplace admin access."},
    {"key": "xero", "name": "Xero", "covers": "Accounts", "wave": 3,
     "sees": "Sign-ins and new connected apps.", "needs": "Adviser or admin access."},
    {"key": "phone", "name": "SentrAI phone app", "covers": "Android phones", "wave": 1,
     "sees": "Only yes or no answers from the phone check: screen lock, updates, apps from outside the app store, "
             "apps that can read the screen, developer settings. Never messages, photos, browsing or app names.",
     "needs": "Staff install the SentrAI app and sign in with the invite from this page."},
    {"key": "browser", "name": "SentrAI browser helper", "covers": "Chrome and Edge", "wave": 3,
     "sees": "Only one thing: a known bad or look-alike website being opened. It warns before the page loads.",
     "needs": "Installed by the admin through Google or Microsoft device management."},
]
APP_KEYS = {a["key"] for a in APPS}
for _a in APPS:
    _a["status"] = "live" if _a["key"] == "phone" else "sample" if _a["wave"] == 1 else "planned"

# --------------------------------------------------------------------------- lessons
# Each lesson: a short card (what happened, why it matters, what to do) and two quick questions.
# `next` is the deeper lesson for the second time the same slip happens.


def _q(q: str, options: list[str], answer: int) -> dict[str, Any]:
    return {"q": q, "options": options, "answer": answer}


LESSONS: dict[str, dict[str, Any]] = {
    "public-links": {
        "title": "Share with people, not with \"anyone with the link\"",
        "card": "A link that works for anyone can be forwarded, posted or guessed. Whoever has it can open the file, "
                "and you will never know.",
        "steps": ["Share with the person's work email instead.", "If you must use a link, set it to expire.",
                  "Check what is already shared in your drive once a month."],
        "questions": [_q("Who can open a file shared as \"anyone with the link\"?",
                         ["Only people in our company", "Anyone who gets the link", "Only the person I sent it to"], 1),
                      _q("What is the safer way to share a file with a client?",
                         ["Add their email address to the file", "Post the link in a group chat",
                          "Make the folder public"], 0)],
        "next": "public-links-2"},
    "public-links-2": {
        "title": "Find and close old open links",
        "card": "Open links stay open long after the job is done. Old ones are how files leak months later.",
        "steps": ["Open your drive's \"Shared\" view and sort by date.", "Turn off links you no longer need.",
                  "For a folder clients use all the time, ask your admin for a shared space instead."],
        "questions": [_q("When should an open link be turned off?",
                         ["Never, it might be needed", "As soon as the person has the file", "Once a year"], 1),
                      _q("Where do you see what you have shared?", ["The \"Shared\" view of your drive",
                                                                     "Your email inbox", "The bin"], 0)]},
    "outside-sharing": {
        "title": "Work files stay in work accounts",
        "card": "Sending work files to a personal email moves them somewhere the company cannot protect or get back.",
        "steps": ["Keep work files in your work drive.", "To work from home, use your work account there.",
                  "If someone outside needs a file, share it from your work account with an end date."],
        "questions": [_q("Why not email work files to your personal address?",
                         ["Personal mail is slower", "The company can't protect or recover them there",
                          "It uses up storage"], 1),
                      _q("You need a file at home. What do you do?", ["Sign in to your work account at home",
                                                                       "Forward it to your personal email",
                                                                       "Copy it to a USB stick"], 0)],
        "next": "outside-sharing-2"},
    "outside-sharing-2": {
        "title": "Big batches leaving the company",
        "card": "Sharing many files outside at once is how most data leaks happen, often by accident.",
        "steps": ["Share one folder with an end date instead of many files.", "Double-check the email address.",
                  "Ask your admin if a client needs ongoing access."],
        "questions": [_q("What is the safer way to give a client many files?",
                         ["One shared folder with an end date", "Attach them all to one email",
                          "Upload them to a free file site"], 0),
                      _q("What should you check before sharing outside?", ["The exact email address",
                                                                            "The file colour", "Nothing"], 0)]},
    "mail-forwarding": {
        "title": "Rules that forward your mail outside",
        "card": "A rule that sends your mail to another address copies every email, including passwords and invoices. "
                "Attackers set these up quietly after they get into an account.",
        "steps": ["Remove the rule if you don't need it.", "If you didn't make it, tell us now: someone may be in "
                  "your account.", "Use your phone's work mail app instead of forwarding."],
        "questions": [_q("You find a forwarding rule you didn't make. What does that mean?",
                         ["Nothing, it's normal", "Someone else may be in your account", "Your inbox is full"], 1),
                      _q("What is the safe way to read work mail on your phone?",
                         ["The work mail app, signed in to your work account", "Forward everything to Gmail",
                          "Screenshots"], 0)],
        "next": "account-takeover"},
    "app-access": {
        "title": "Before you click \"Allow\"",
        "card": "Apps that ask to \"read your mail\" or \"see your files\" get that access until you take it back. "
                "Fake apps use this to steal data without needing your password.",
        "steps": ["Only allow apps your company has approved.", "Read what the app asks for. Mail and files are the "
                  "big ones.", "Remove apps you no longer use from your account settings."],
        "questions": [_q("An unknown app asks to read all your email. What do you do?",
                         ["Allow it, it's quicker", "Say no and ask your admin", "Allow it, then delete it later"], 1),
                      _q("Does changing your password remove an app's access?",
                         ["Yes, always", "No, you have to remove the app", "Only on Fridays"], 1)],
        "next": "app-access-2"},
    "app-access-2": {
        "title": "Clean up the apps on your account",
        "card": "Old app connections are forgotten doors into your account.",
        "steps": ["Open your account's security page and find \"Third-party apps\" or \"App permissions\".",
                  "Remove anything you don't recognise or no longer use."],
        "questions": [_q("Where do you see apps connected to your account?",
                         ["The account's security page", "The desktop", "Your calendar"], 0),
                      _q("Should you keep apps you no longer use?", ["Yes", "No, remove them"], 1)]},
    "phishing": {
        "title": "Spotting a fake email",
        "card": "Our mail system stopped a link or file that was dangerous. Fake emails look urgent, come from "
                "names you know, and ask you to sign in or pay.",
        "steps": ["Check the sender's real address, not just the name.", "Hover over a link before you click.",
                  "When in doubt, call the person on a number you already have.",
                  "Report it: forwarding a fake email to IT is always a good move."],
        "questions": [_q("An email from your boss urgently asks you to buy gift cards. What do you do?",
                         ["Buy them quickly", "Call your boss on their usual number", "Reply to ask why"], 1),
                      _q("What does a fake email usually want?", ["You to sign in, pay or open a file",
                                                                   "To wish you a nice day", "Nothing"], 0)],
        "next": "phishing-2"},
    "phishing-2": {
        "title": "Fake sign-in pages",
        "card": "The most common trick is a page that looks exactly like your work sign-in. The web address is the "
                "giveaway.",
        "steps": ["Sign in by typing the address or using a bookmark, not from an email link.",
                  "A password manager won't fill in a fake site. If it doesn't fill, stop."],
        "questions": [_q("How do you reach your work sign-in page safely?",
                         ["From a bookmark or by typing it", "From a link in an email", "From a search ad"], 0),
                      _q("Your password manager doesn't fill in the password. Why might that be?",
                         ["The site may be fake", "It's broken", "The internet is slow"], 0)]},
    "two-step": {
        "title": "Keep 2-step sign-in on",
        "card": "2-step sign-in (a code or a tap on your phone) stops most account break-ins, even when a password "
                "has leaked.",
        "steps": ["Turn 2-step sign-in back on now.", "Use an authenticator app or a security key rather than "
                  "text messages.", "Never read your code to anyone, even IT."],
        "questions": [_q("Someone calls saying they're from IT and asks for your sign-in code. What do you do?",
                         ["Give it to them", "Refuse and report the call", "Give half of it"], 1),
                      _q("Which is the strongest second step?", ["A security key or authenticator app",
                                                                  "A text message", "A second password"], 0)],
        "next": "account-takeover"},
    "new-sign-in": {
        "title": "Was that you signing in?",
        "card": "We saw a sign-in to your account from somewhere new. If it was you, great. If not, acting in the "
                "first few minutes matters most.",
        "steps": ["If it wasn't you: change your password and tell us straight away.",
                  "If it was you on holiday or a new phone, just confirm."],
        "questions": [_q("A sign-in from another country that wasn't you. First step?",
                         ["Change your password and tell IT", "Wait and see", "Delete the alert"], 0),
                      _q("Why does a quick answer matter?", ["Attackers move fast once inside",
                                                              "It doesn't matter"], 0)],
        "next": "account-takeover"},
    "failed-sign-ins": {
        "title": "Someone is guessing your password",
        "card": "There were many wrong passwords on your account. Someone may be trying a leaked or guessed password.",
        "steps": ["Use a long, unique password: three or four random words work well.",
                  "Never reuse your work password anywhere else.", "Make sure 2-step sign-in is on."],
        "questions": [_q("Which password is strongest?", ["Summer2026!", "correct-orbit-lamp-tulip",
                                                          "Password123"], 1),
                      _q("Is it OK to use your work password on a shopping site?", ["Yes", "No, never"], 1)],
        "next": "account-takeover"},
    "account-takeover": {
        "title": "When your account might not be yours",
        "card": "Signs someone else is in your account: rules you didn't make, sign-ins you don't recognise, "
                "sent emails you didn't write. Speed beats everything here.",
        "steps": ["Change your password.", "Tell IT or reply \"Not me\" to this note.",
                  "Check your mail rules and connected apps."],
        "questions": [_q("You see sent emails you didn't write. What now?",
                         ["Change password and tell IT straight away", "Delete them", "Ignore it"], 0),
                      _q("Who should you tell?", ["IT or the SentrAI note", "Nobody", "Only your friends"], 0)]},
    "bulk-download": {
        "title": "Taking lots of files at once",
        "card": "Downloading or exporting many files at once looks the same as someone stealing them, so it gets "
                "checked. Copies on laptops and USB sticks are easy to lose.",
        "steps": ["Work on files where they are, in the work drive.", "If you need a big export, tell your manager "
                  "first.", "Delete local copies when you're done."],
        "questions": [_q("Where is the safest place to keep work files?", ["The work drive", "A USB stick",
                                                                           "Your desktop"], 0),
                      _q("You need a full customer export. What first?", ["Tell your manager why",
                                                                          "Just do it at night"], 0)]},
    "public-code": {
        "title": "Keep company code private",
        "card": "Code made public can show passwords, keys and how our systems work. Search engines find it in "
                "minutes.",
        "steps": ["Make it private again.", "If it held any keys or passwords, tell IT so they can change them.",
                  "Ask before making anything public."],
        "questions": [_q("A key was in code that went public for an hour. Is it safe now that it's private?",
                         ["Yes", "No, the key must be changed"], 1),
                      _q("Who decides if code goes public?", ["Ask first, following company rules",
                                                               "Anyone"], 0)]},
    "secret-in-code": {
        "title": "Passwords don't belong in code",
        "card": "A password or key was pushed into code. Anyone who can read the code can now use it.",
        "steps": ["Tell IT so the key can be changed.", "Keep keys in the company's secret store, not in files."],
        "questions": [_q("Is deleting the line enough?", ["Yes", "No, the key must be changed"], 1),
                      _q("Where should keys live?", ["A secret store", "In the code", "In a chat message"], 0)]},
    "open-meetings": {
        "title": "Lock your meetings",
        "card": "Meetings without a passcode or waiting room can be joined by anyone who finds the link, and "
                "shared recordings can be watched by anyone.",
        "steps": ["Turn on a passcode or waiting room.", "Share recordings with named people only."],
        "questions": [_q("Who can join a meeting with no passcode?", ["Anyone with the link", "Only invitees"], 0),
                      _q("Safest way to share a recording?", ["With named people", "Publicly"], 0)]},
    "outside-guests": {
        "title": "Guests in private spaces",
        "card": "Outside people added to private channels or pages can read everything there, including old "
                "messages.",
        "steps": ["Use a separate shared channel for clients.", "Remove guests when the project ends."],
        "questions": [_q("A client needs to chat with you. Where?", ["A separate shared channel",
                                                                     "Our internal team channel"], 0),
                      _q("When do guests leave?", ["When the project ends", "Never"], 0)]},
    "bad-website": {
        "title": "That website wasn't what it seemed",
        "card": "The page you opened is known for scams or looks like a real site but isn't. Look-alike addresses "
                "change one letter, like rnicrosoft instead of microsoft.",
        "steps": ["Close the page. Don't enter anything.", "If you typed a password there, change it now and tell IT."],
        "questions": [_q("Which is the look-alike?", ["microsoft.com", "rnicrosoft.com"], 1),
                      _q("You typed your password on a fake page. Next?", ["Change it and tell IT", "Nothing"], 0)]},
    "phone-lock": {
        "title": "Lock your phone",
        "card": "A phone with no screen lock opens for anyone who picks it up: your work email, chats and files "
                "with it.",
        "steps": ["Set a PIN of 6 digits or more, or a fingerprint or face unlock.",
                  "Set the screen to lock after a minute or less."],
        "questions": [_q("Who can read your work email on a phone with no lock?", ["Only you", "Anyone holding it"],
                         1),
                      _q("Which is the better lock?", ["A 6-digit PIN or fingerprint", "A swipe"], 0)]},
    "phone-updates": {
        "title": "Keep your phone up to date",
        "card": "Updates close holes that attackers already know how to use. A phone months behind is an easy "
                "target, even if you are careful.",
        "steps": ["Open Settings, then System, then Software update, and install what is waiting.",
                  "Turn on automatic updates."],
        "questions": [_q("Why do updates matter for security?", ["They close known holes", "They only add emojis"],
                         0),
                      _q("Best time to install an update?", ["As soon as it arrives", "Never"], 0)]},
    "phone-apps": {
        "title": "Get apps from the Play Store",
        "card": "Apps from websites, chats or file shares skip Google's checks. Fake versions of real apps are a "
                "common way to steal passwords and bank codes.",
        "steps": ["Remove apps you don't recognise or no longer use.",
                  "Install new apps only from the Play Store or your company's app list."],
        "questions": [_q("Someone sends you an app file in a chat. What do you do?",
                         ["Install it", "Don't install it, find the app in the Play Store"], 1),
                      _q("Where should work apps come from?", ["The Play Store or the company's list",
                                                                "Any website"], 0)]},
    "phone-screen-readers": {
        "title": "Apps that can read your screen",
        "card": "Some apps ask for \"accessibility\" access. That lets them read everything on screen and tap for "
                "you, including codes and passwords. Scam apps ask for it all the time.",
        "steps": ["Open Settings, then Accessibility, and turn off apps you don't need there.",
                  "Only allow it for apps you trust and actually use for accessibility."],
        "questions": [_q("What can an app with accessibility access do?", ["Read your screen and tap for you",
                                                                         "Only change the font size"], 0),
                      _q("An app you just installed asks for it. What do you do?",
                         ["Say no unless you really need it", "Always allow it"], 0)]},
    "phone-dev-mode": {
        "title": "Turn off developer settings",
        "card": "USB debugging lets a computer plugged into your phone read and install things. It's for app "
                "makers, and most people never need it.",
        "steps": ["Open Settings, then System, then Developer options, and turn off USB debugging.",
                  "If you don't make apps, turn Developer options off."],
        "questions": [_q("Who needs USB debugging on?", ["People making apps", "Everyone"], 0),
                      _q("Is it safe to leave on when charging at public places?", ["Yes", "No"], 1)]},
    "phone-rooted": {
        "title": "This phone's safety locks are off",
        "card": "The phone has been changed to let apps go around Android's safety locks (rooted). Any app can then "
                "read other apps' data, including work email.",
        "steps": ["Talk to IT before using work apps on this phone.", "Restore the phone's normal software."],
        "questions": [_q("What does rooting a phone remove?", ["Android's safety locks", "Nothing important"], 0),
                      _q("Who should you tell?", ["IT", "Nobody"], 0)]},
}

# --------------------------------------------------------------------------- kinds of risky moment
# kind -> level, plain title, why it matters, the fix button, the lesson.
KINDS: dict[str, dict[str, Any]] = {
    "file_shared_public": {"group": "Sharing", "level": "fix_soon", "title": "shared {what} with anyone who has "
                           "the link", "fix": "Make it private again", "lesson": "public-links"},
    "file_shared_personal": {"group": "Sharing", "level": "fix_soon", "title": "shared {what} with a personal "
                             "email address", "fix": "Stop sharing", "lesson": "outside-sharing"},
    "bulk_shared_outside": {"group": "Sharing", "level": "fix_soon", "title": "shared many files outside the "
                            "company at once", "fix": "Review the sharing", "lesson": "outside-sharing-2"},
    "mail_forward_outside": {"group": "Mail", "level": "urgent", "title": "has a rule that forwards mail to an "
                             "outside address", "fix": "Remove the rule", "lesson": "mail-forwarding"},
    "phishing_blocked": {"group": "Mail", "level": "tip", "title": "received a fake email that was stopped",
                         "fix": None, "lesson": "phishing"},
    "phishing_clicked": {"group": "Mail", "level": "fix_soon", "title": "tried to open a dangerous link or file "
                         "that was blocked", "fix": None, "lesson": "phishing"},
    "app_access_granted": {"group": "App access", "level": "fix_soon", "title": "gave an unknown app access to "
                           "their account", "fix": "Remove the app", "lesson": "app-access"},
    "two_step_off": {"group": "Sign-in", "level": "fix_soon", "title": "turned off 2-step sign-in",
                     "fix": "Turn it back on", "lesson": "two-step"},
    "sign_in_new_place": {"group": "Sign-in", "level": "tip", "title": "signed in from a new country or device",
                          "fix": None, "lesson": "new-sign-in"},
    "sign_in_failed_many": {"group": "Sign-in", "level": "fix_soon", "title": "had many wrong passwords in a row",
                            "fix": None, "lesson": "failed-sign-ins"},
    "sign_in_risky": {"group": "Sign-in", "level": "urgent", "title": "had a sign-in the app itself marked as "
                      "risky", "fix": "Sign out everywhere", "lesson": "account-takeover"},
    "bulk_download": {"group": "Data leaving", "level": "tip", "title": "downloaded or exported many files at once",
                      "fix": None, "lesson": "bulk-download"},
    "repo_made_public": {"group": "Data leaving", "level": "urgent", "title": "made company code public",
                         "fix": "Make it private again", "lesson": "public-code"},
    "secret_in_code": {"group": "Data leaving", "level": "urgent", "title": "pushed a password or key into code",
                       "fix": None, "lesson": "secret-in-code"},
    "meeting_open": {"group": "Meetings and chat", "level": "tip", "title": "held a meeting anyone could join",
                     "fix": "Turn on a passcode", "lesson": "open-meetings"},
    "recording_public": {"group": "Meetings and chat", "level": "fix_soon", "title": "shared a meeting recording "
                         "publicly", "fix": "Make it private", "lesson": "open-meetings"},
    "guest_added": {"group": "Meetings and chat", "level": "tip", "title": "added an outside guest to a private "
                    "space", "fix": None, "lesson": "outside-guests"},
    "bad_site_opened": {"group": "Browsing", "level": "fix_soon", "title": "opened a known scam or look-alike "
                        "website", "fix": None, "lesson": "bad-website"},
    "phone_no_lock": {"you": "your phone has no screen lock", "group": "Phone", "level": "fix_soon", "title": "has no screen lock on their phone",
                      "fix": "Set a screen lock", "lesson": "phone-lock"},
    "phone_out_of_date": {"you": "your phone is months behind on updates", "group": "Phone", "level": "fix_soon", "title": "has a phone that is months behind on "
                          "updates", "fix": "Update the phone", "lesson": "phone-updates"},
    "phone_outside_apps": {"you": "your phone has apps from outside the Play Store", "group": "Phone", "level": "tip", "title": "has apps on their phone from outside the "
                           "Play Store", "fix": "Review the apps", "lesson": "phone-apps"},
    "phone_screen_readers": {"you": "an app from outside the Play Store can read your phone's screen", "group": "Phone", "level": "fix_soon", "title": "has an app from outside the Play "
                             "Store that can read the phone's screen", "fix": "Review screen access",
                             "lesson": "phone-screen-readers"},
    "phone_dev_mode": {"you": "your phone has USB debugging turned on", "group": "Phone", "level": "tip", "title": "has USB debugging turned on",
                       "fix": "Turn it off", "lesson": "phone-dev-mode"},
    "phone_rooted": {"you": "your phone's safety locks are off (it is rooted)", "group": "Phone", "level": "urgent", "title": "uses a phone whose safety locks are off "
                     "(rooted)", "fix": None, "lesson": "phone-rooted"},
}
# Sign-in moments are urgent when the person says "not me".

# What a file can be called when names are off (data minimisation).
FILE_TYPES = {"spreadsheet": "a spreadsheet", "document": "a document", "presentation": "a presentation",
              "pdf": "a PDF", "folder": "a folder", "image": "a picture", "video": "a video", "code": "some code",
              "file": "a file"}
DEVICES = ("computer", "phone", "tablet", "unknown")
REACH = ("email", "slack", "teams", "app")  # "app": the SentrAI phone app

# --------------------------------------------------------------------------- regions
# The checklist an admin ticks before coaching starts for staff in that region. `consent`: nothing about a person
# is recorded until they confirm the notice. Starting points to check with a lawyer, not legal advice.
REGIONS: dict[str, dict[str, Any]] = {
    "sg": {"name": "Singapore", "law": "PDPA 2012", "consent": False, "checks": [
        "Staff have been told the purpose before collection starts (the staff notice).",
        "If relying on legitimate interests, a short written assessment is on file.",
        "A named contact for data questions is in the notice."]},
    "eu": {"name": "European Union", "law": "GDPR", "consent": False, "checks": [
        "A data protection impact assessment (DPIA) has been done for staff monitoring.",
        "The legal basis is legitimate interests, with a balancing test on file (consent is rarely valid at work).",
        "Where needed (e.g. Germany, France), the works council or staff representatives have agreed.",
        "Staff have the notice before monitoring starts."]},
    "uk": {"name": "United Kingdom", "law": "UK GDPR", "consent": False, "checks": [
        "A DPIA has been done, following the ICO's guidance on monitoring workers.",
        "Staff have the notice before monitoring starts."]},
    "my": {"name": "Malaysia", "law": "PDPA 2010", "consent": False, "checks": [
        "A written notice in English and Malay has been given to staff.",
        "The purpose is stated and limited to security."]},
    "id": {"name": "Indonesia", "law": "PDP Law 2022", "consent": True, "checks": [
        "Each person gives clear consent before their activity is recorded.",
        "The purpose and retention period are in the notice."]},
    "ph": {"name": "Philippines", "law": "Data Privacy Act 2012", "consent": False, "checks": [
        "Staff have the notice, including the purpose and how long data is kept.",
        "A data protection officer is named."]},
    "us-ca": {"name": "California, USA", "law": "CCPA / CPRA", "consent": False, "checks": [
        "A notice at collection has been given to staff.",
        "Staff can ask to see and delete their data (the My data export and Erase)."]},
    "au": {"name": "Australia", "law": "Privacy Act, plus state workplace surveillance laws", "consent": False,
           "checks": ["In NSW and the ACT, staff have had written notice at least 14 days before monitoring starts.",
                      "The notice says what is monitored and how."]},
}

LEVEL_NAMES = ("Starter", "Learner", "Careful", "Sharp", "Guardian")
POINTS = {"lesson": 10, "fixed": 5, "reported": 5}


class CoachError(ValueError):
    """Something the request asked for that the coach can't do; the message says why in plain words."""


def _now_iso(now: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))


def _email(v: Any) -> str:
    e = str(v or "").strip().lower()
    if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}\.[a-z]{2,}", e):
        raise CoachError(f"Not a work email address: {str(v)[:80]!r}")
    return e


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def level_of(points: int) -> dict[str, Any]:
    i = min(len(LEVEL_NAMES) - 1, max(0, points) // 30)
    return {"name": LEVEL_NAMES[i], "step": i + 1, "of": len(LEVEL_NAMES), "points": points,
            "next_at": None if i == len(LEVEL_NAMES) - 1 else (i + 1) * 30}


DEFAULTS: dict[str, Any] = {
    "notice_shared": False, "notice_shared_at": None, "apps_on": [], "kinds_on": sorted(KINDS),
    "groups_off": [], "regions": [], "region_checks": {}, "show_names": False, "file_names": False,
    "updated_at": None, "updated_by": None,
}


class Coach:
    """The coach's records, in one JSON file. `months(kind)` reads a retention period from the privacy policy."""

    def __init__(self, path: Path, months: Callable[[str], int | None] | None = None,
                 clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self._months = months or (lambda k: {"coach_activity": 1, "coach_notes": 12}.get(k))
        self._clock = clock
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ storage
    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        settings = {**DEFAULTS, **(data.get("settings") or {})}
        return {"settings": settings, "people": data.get("people") or {}, "activity": data.get("activity") or [],
                "moments": data.get("moments") or [], "notes": data.get("notes") or []}

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)

    # ------------------------------------------------------------------ settings
    def settings(self) -> dict[str, Any]:
        with self._lock:
            return self._load()["settings"]

    def ready(self, s: dict[str, Any] | None = None) -> tuple[bool, str]:
        """Whether recording may start, and if not, why (in plain words)."""
        s = s or self.settings()
        if not s["regions"]:
            return False, "Pick the regions your staff work in."
        for r in s["regions"]:
            done = set(s["region_checks"].get(r) or [])
            if len(done) < len(REGIONS[r]["checks"]):
                return False, f"Finish the checklist for {REGIONS[r]['name']}."
        if not s["notice_shared"]:
            return False, "Share the staff notice, then mark it as shared."
        return True, ""

    def save_settings(self, body: dict[str, Any], by: str) -> dict[str, Any]:
        with self._lock:
            data = self._load()
            s = dict(data["settings"])
            if "apps_on" in body:
                apps = list(dict.fromkeys(body.get("apps_on") or []))
                bad = [a for a in apps if a not in APP_KEYS]
                if bad:
                    raise CoachError(f"Unknown app: {bad[0]}")
                s["apps_on"] = apps
            if "kinds_on" in body:
                kinds = list(dict.fromkeys(body.get("kinds_on") or []))
                bad = [k for k in kinds if k not in KINDS]
                if bad:
                    raise CoachError(f"Unknown kind of action: {bad[0]}")
                s["kinds_on"] = kinds
            if "groups_off" in body:
                s["groups_off"] = sorted({str(g).strip()[:60] for g in body.get("groups_off") or [] if str(g).strip()})
            if "regions" in body:
                regions = list(dict.fromkeys(body.get("regions") or []))
                bad = [r for r in regions if r not in REGIONS]
                if bad:
                    raise CoachError(f"Unknown region: {bad[0]}")
                s["regions"] = regions
            if "region_checks" in body:
                checks = {}
                for r, ticks in (body.get("region_checks") or {}).items():
                    if r not in REGIONS:
                        raise CoachError(f"Unknown region: {r}")
                    n = len(REGIONS[r]["checks"])
                    checks[r] = sorted({int(t) for t in ticks or [] if isinstance(t, int) and not isinstance(t, bool)
                                        and 0 <= t < n})
                s["region_checks"] = checks
            for flag in ("show_names", "file_names"):
                if flag in body:
                    s[flag] = bool(body[flag])
            if "notice_shared" in body:
                shared = bool(body["notice_shared"])
                if shared and not s["notice_shared"]:
                    s["notice_shared_at"] = _now_iso(self._clock())
                s["notice_shared"] = shared
            s["updated_at"], s["updated_by"] = _now_iso(self._clock()), by
            data["settings"] = s
            self._save(data)
            return s

    # ------------------------------------------------------------------ people
    def upsert_person(self, body: dict[str, Any]) -> dict[str, Any]:
        email = _email(body.get("email"))
        with self._lock:
            data = self._load()
            cur = data["people"].get(email) or {"email": email, "added_at": _now_iso(self._clock()),
                                                 "notice_confirmed_at": None, "coaching": True, "points": 0,
                                                 "lessons_done": [], "reach": "email"}
            if "name" in body:
                cur["name"] = str(body.get("name") or "").strip()[:80]
            if "group" in body:
                cur["group"] = str(body.get("group") or "").strip()[:60]
            if "region" in body:
                region = str(body.get("region") or "").strip().lower()
                if region and region not in REGIONS:
                    raise CoachError(f"Unknown region: {region}")
                cur["region"] = region
            if "coaching" in body:
                cur["coaching"] = bool(body["coaching"])
            if "reach" in body:
                if body["reach"] not in REACH:
                    raise CoachError("Reach people by " + ", ".join(REACH) + ".")
                cur["reach"] = body["reach"]
            if body.get("notice_confirmed") is True and not cur.get("notice_confirmed_at"):
                cur["notice_confirmed_at"] = _now_iso(self._clock())
            if body.get("notice_confirmed") is False:
                cur["notice_confirmed_at"] = None
            if body.get("sample"):
                cur["sample"] = True
            data["people"][email] = cur
            self._save(data)
            return cur

    def erase_person(self, email: str) -> dict[str, int]:
        """Delete everything the coach holds about one person (their right to erasure)."""
        email = _email(email)
        with self._lock:
            data = self._load()
            gone = {"person": int(data["people"].pop(email, None) is not None)}
            for key in ("activity", "moments", "notes"):
                before = len(data[key])
                data[key] = [r for r in data[key] if r.get("person") != email]
                gone[key] = before - len(data[key])
            self._save(data)
            return gone

    def my_data(self, email: str) -> dict[str, Any]:
        """Everything the coach holds about one person, for them to see or download."""
        email = _email(email)
        with self._lock:
            data = self._load()
        person = data["people"].get(email)
        if not person:
            raise CoachError("SentrAI's coach holds nothing about this person.")
        mine = lambda key: [r for r in data[key] if r.get("person") == email]  # noqa: E731
        return {"person": {**person, "level": level_of(int(person.get("points") or 0))},
                "activity": mine("activity"), "moments": mine("moments"), "notes": mine("notes"),
                "kept": {"activity": self._kept("coach_activity"), "notes": self._kept("coach_notes")}}

    def _kept(self, key: str) -> str:
        m = self._months(key)
        if m is None:
            return "while it exists"
        if m == 0:
            return "not kept after the coaching note is written"
        return f"{m} month{'' if m == 1 else 's'}"

    # ------------------------------------------------------------------ the main flow
    def _region_of(self, person: dict[str, Any], s: dict[str, Any]) -> str:
        return person.get("region") or (s["regions"][0] if len(s["regions"]) == 1 else "")

    def _clean(self, e: dict[str, Any], s: dict[str, Any], now: float) -> dict[str, Any]:
        """Keep only the fixed, minimal fields. Anything else in the record is dropped, never stored."""
        kind = str(e.get("kind") or "")
        ts = e.get("ts")
        when = float(ts) if isinstance(ts, (int, float)) and not isinstance(ts, bool) else now
        when = min(when, now)
        ftype = str(e.get("file_type") or "file").lower()
        what = FILE_TYPES.get(ftype, "a file")
        rec = {"id": _id("a"), "person": _email(e.get("person")), "app": str(e.get("app")), "kind": kind,
               "ts": when, "at": _now_iso(when), "what": what}
        country = str(e.get("country") or "").strip().upper()
        if re.fullmatch(r"[A-Z]{2}", country):
            rec["country"] = country
        device = str(e.get("device") or "").lower()
        if device in DEVICES:
            rec["device"] = device
        if s["file_names"] and e.get("label"):
            rec["label"] = str(e["label"]).strip()[:80]
        if e.get("count") is not None:
            try:
                rec["count"] = max(0, min(1_000_000, int(e["count"])))
            except (TypeError, ValueError):
                pass
        if e.get("sample"):
            rec["sample"] = True
        return rec

    def ingest(self, events: list[dict[str, Any]], sample: bool = False) -> dict[str, Any]:
        """Turn activity records from connectors into moments and coaching notes. Out-of-scope records are dropped
        without being stored. Returns counts and the urgent moments (so the caller can put them on the audit
        record)."""
        if not isinstance(events, list):
            raise CoachError("Send a list of activity records.")
        if len(events) > MAX_EVENTS:
            raise CoachError(f"Send at most {MAX_EVENTS} records at a time.")
        now = self._clock()
        with self._lock:
            data = self._load()
            s = data["settings"]
            ok, why = self.ready(s)
            if not ok:
                raise CoachError("The coach is not switched on yet. " + why)
            out = {"recorded": 0, "moments": 0, "dropped": 0, "why_dropped": {}, "urgent": []}

            def drop(reason: str) -> None:
                out["dropped"] += 1
                out["why_dropped"][reason] = out["why_dropped"].get(reason, 0) + 1

            keep_activity = self._months("coach_activity") != 0
            for e in events:
                if not isinstance(e, dict):
                    drop("not a record")
                    continue
                try:
                    email = _email(e.get("person"))
                except CoachError:
                    drop("no work email")
                    continue
                person = data["people"].get(email)
                if not person:
                    drop("person not added to the coach")
                    continue
                if not person.get("coaching", True) or (person.get("group") and person["group"] in s["groups_off"]):
                    drop("person left out by the admin")
                    continue
                if e.get("app") not in APP_KEYS or (not (sample and e.get("sample")) and e["app"] not in s["apps_on"]):
                    drop("app not switched on")
                    continue
                if e.get("kind") not in KINDS or e["kind"] not in s["kinds_on"]:
                    drop("kind of action not switched on")
                    continue
                region = self._region_of(person, s)
                if region and region not in s["regions"]:
                    drop("person's region not set up")
                    continue
                if region and REGIONS[region]["consent"] and not person.get("notice_confirmed_at"):
                    drop("waiting for the person's consent")
                    continue
                rec = self._clean({**e, "sample": bool(sample and e.get("sample"))}, s, now)
                if keep_activity:
                    data["activity"].append(rec)
                out["recorded"] += 1
                moment = self._moment(data, rec, person)
                out["moments"] += 1
                if moment["level"] == "urgent":
                    out["urgent"].append({"id": moment["id"], "person": email, "kind": moment["kind"]})
            self._prune(data, now)
            self._save(data)
            return out

    def _moment(self, data: dict[str, Any], rec: dict[str, Any], person: dict[str, Any]) -> dict[str, Any]:
        rule = KINDS[rec["kind"]]
        since = rec["ts"] - REPEAT_WINDOW
        times = 1 + sum(1 for m in data["moments"] if m["person"] == rec["person"] and m["kind"] == rec["kind"]
                        and m["ts"] >= since)
        lesson = rule["lesson"]
        for _ in range(times - 1):
            lesson = LESSONS[lesson].get("next") or lesson
        moment = {"id": _id("m"), "person": rec["person"], "app": rec["app"], "kind": rec["kind"],
                  "group": rule["group"], "level": rule["level"], "ts": rec["ts"], "at": rec["at"],
                  "activity": rec["id"], "lesson": lesson, "times": times, "status": "new",
                  "title": rule["title"].format(what=rec.get("label") and f"\"{rec['label']}\"" or rec["what"]),
                  "fix": rule["fix"]}
        if rec.get("sample"):
            moment["sample"] = True
        data["moments"].append(moment)
        data["notes"].append(self._note(moment, person, rec))
        return moment

    def _note(self, m: dict[str, Any], person: dict[str, Any], rec: dict[str, Any]) -> dict[str, Any]:
        """The message the person gets: kind, short, one clear next step. Held until they've seen the notice."""
        lesson = LESSONS[m["lesson"]]
        first = (person.get("name") or "").split(" ")[0] or "there"
        app = next(a["name"] for a in APPS if a["key"] == m["app"])
        where = f" from {rec['country']}" if rec.get("country") and m["group"] == "Sign-in" else ""
        you = KINDS[m["kind"]].get("you")
        lines = [f"Hi {first}, quick one from SentrAI about {app}.",
                 f"Your phone check found that {you}." if you else
                 f"It looks like you {m['title']}{where}." if m["kind"] not in ("phishing_blocked",)
                 else f"You {m['title']}. Nothing to fix, nice work not falling for it.",
                 lesson["card"]]
        if m["times"] > 1:
            lines.append(f"This is the {m['times']}{'nd' if m['times'] == 2 else 'rd' if m['times'] == 3 else 'th'} "
                         "time recently, so here's a slightly deeper tip.")
        lines.append("What to do: " + lesson["steps"][0])
        buttons = ([m["fix"]] if m["fix"] else []) + (["Yes, that was me", "No, that wasn't me"]
                                                      if m["group"] in ("Sign-in", "Mail") and m["kind"] not in
                                                      ("phishing_blocked", "phishing_clicked") else []) \
            + ["One-minute lesson"]
        held = not person.get("notice_confirmed_at")
        note = {"id": _id("n"), "person": m["person"], "moment": m["id"], "lesson": m["lesson"], "ts": m["ts"],
                "at": m["at"], "reach": person.get("reach", "email"), "text": "\n\n".join(lines),
                "buttons": buttons, "status": "held for notice" if held else "ready to send",
                "lesson_done": False}
        if held:
            note["held_reason"] = "The person hasn't confirmed the staff notice yet. Their first message will be " \
                                  "the notice, then this."
        if m.get("sample"):
            note["sample"] = True
        return note

    def respond(self, moment_id: str, answer: str, by: str = "") -> dict[str, Any]:
        """The person's answer to a note: fixed, was_me, not_me (raises it to urgent) or reported."""
        if answer not in ("fixed", "was_me", "not_me", "reported", "dismissed"):
            raise CoachError("Answer fixed, was_me, not_me, reported or dismissed.")
        with self._lock:
            data = self._load()
            m = next((x for x in data["moments"] if x["id"] == moment_id), None)
            if not m:
                raise CoachError("No such moment (it may have passed its retention period).")
            m["status"] = {"not_me": "needs help"}.get(answer, answer.replace("_", " "))
            m["answered_at"], m["answered_by"] = _now_iso(self._clock()), by or m["person"]
            if answer == "not_me":
                m["level"] = "urgent"
            person = data["people"].get(m["person"])
            if person and answer in ("fixed", "reported"):
                person["points"] = int(person.get("points") or 0) + POINTS[answer]
            self._save(data)
            return m

    def answer_lesson(self, email: str, lesson_id: str, answers: list[int]) -> dict[str, Any]:
        """Mark the two-question check. Passing it counts the lesson as done and adds points once."""
        email = _email(email)
        lesson = LESSONS.get(lesson_id)
        if not lesson:
            raise CoachError("No such lesson.")
        if not isinstance(answers, list) or len(answers) != len(lesson["questions"]):
            raise CoachError(f"Answer all {len(lesson['questions'])} questions.")
        right = [isinstance(a, int) and a == q["answer"] for a, q in zip(answers, lesson["questions"])]
        passed = all(right)
        with self._lock:
            data = self._load()
            person = data["people"].get(email)
            if not person:
                raise CoachError("This person hasn't been added to the coach.")
            if passed and lesson_id not in person.get("lessons_done", []):
                person.setdefault("lessons_done", []).append(lesson_id)
                person["points"] = int(person.get("points") or 0) + POINTS["lesson"]
                for n in data["notes"]:
                    if n["person"] == email and n["lesson"] == lesson_id:
                        n["lesson_done"] = True
            self._save(data)
            return {"passed": passed, "right": right, "level": level_of(int(person.get("points") or 0)),
                    "tip": None if passed else "Have another look at the card, then try again. No rush."}

    # ------------------------------------------------------------------ retention
    def _prune(self, data: dict[str, Any], now: float) -> dict[str, int]:
        gone = {}
        for key, months in (("activity", self._months("coach_activity")),
                            ("moments", self._months("coach_notes")), ("notes", self._months("coach_notes"))):
            if months is None:
                gone[key] = 0
                continue
            cut = now - months * MONTH
            before = len(data[key])
            data[key] = [r for r in data[key] if r.get("ts", now) >= cut] if months else \
                ([] if key == "activity" else data[key])
            gone[key] = before - len(data[key])
        return gone

    def prune(self) -> dict[str, int]:
        """Delete what is past its retention period. Runs on every ingest and on each page load."""
        with self._lock:
            data = self._load()
            gone = self._prune(data, self._clock())
            if any(gone.values()):
                self._save(data)
            return gone

    # ------------------------------------------------------------------ views
    def overview(self) -> dict[str, Any]:
        """The Coach page: settings, readiness, team totals, open moments (names only where allowed)."""
        self.prune()
        with self._lock:
            data = self._load()
        s = data["settings"]
        ok, why = self.ready(s)
        now = self._clock()
        recent = [m for m in data["moments"] if m["ts"] >= now - 30 * DAY]
        by_group: dict[str, int] = {}
        by_kind: dict[str, int] = {}
        for m in recent:
            by_group[m["group"]] = by_group.get(m["group"], 0) + 1
            by_kind[m["kind"]] = by_kind.get(m["kind"], 0) + 1
        people = data["people"]
        lessons_done = sum(len(p.get("lessons_done") or []) for p in people.values())
        notes = data["notes"]

        def who(m: dict[str, Any]) -> str:
            if s["show_names"] or m["level"] == "urgent":
                p = people.get(m["person"]) or {}
                return p.get("name") or m["person"]
            return "A team member"

        open_moments = [{**{k: m[k] for k in ("id", "app", "kind", "group", "level", "at", "lesson", "times",
                                              "status", "title", "fix")},
                         "who": who(m), "level_word": LEVEL_WORDS[m["level"]], "sample": bool(m.get("sample"))}
                        for m in sorted(data["moments"], key=lambda m: (LEVELS.index(m["level"]) * -1, -m["ts"]))
                        if m["status"] in ("new", "needs help")][:50]
        team = {"people": len(people), "coaching_on": sum(1 for p in people.values() if p.get("coaching", True)),
                "notice_confirmed": sum(1 for p in people.values() if p.get("notice_confirmed_at")),
                "moments_30d": len(recent), "urgent_open": sum(1 for m in data["moments"] if m["level"] == "urgent"
                                                               and m["status"] in ("new", "needs help")),
                "fixed_30d": sum(1 for m in recent if m["status"] == "fixed"),
                "lessons_done": lessons_done,
                "notes_ready": sum(1 for n in notes if n["status"] == "ready to send"),
                "notes_held": sum(1 for n in notes if n["status"] == "held for notice"),
                "by_group": by_group,
                "top": sorted(({"kind": k, "count": c, "lesson": KINDS[k]["lesson"],
                                "title": LESSONS[KINDS[k]["lesson"]]["title"]} for k, c in by_kind.items()),
                              key=lambda r: -r["count"])[:5]}
        roster = None
        if s["show_names"]:
            roster = [{"email": p["email"], "name": p.get("name", ""), "group": p.get("group", ""),
                       "region": p.get("region", ""), "coaching": p.get("coaching", True),
                       "notice_confirmed": bool(p.get("notice_confirmed_at")),
                       "level": level_of(int(p.get("points") or 0)), "lessons_done": len(p.get("lessons_done") or [])}
                      for p in sorted(people.values(), key=lambda p: p.get("name") or p["email"])]
        return {"settings": s, "ready": ok, "why_not_ready": why, "apps": APPS,
                "kinds": [{"key": k, **{f: v[f] for f in ("group", "level", "lesson")},
                           "title": v["title"].format(what="a file")} for k, v in KINDS.items()],
                "regions": [{"key": k, **v} for k, v in REGIONS.items()],
                "team": team, "moments": open_moments, "people": roster,
                "kept": {"activity": self._kept("coach_activity"), "notes": self._kept("coach_notes")},
                "has_sample": any(p.get("sample") for p in people.values())}

    # ------------------------------------------------------------------ the phone app (mobile.py)
    def person(self, email: str) -> dict[str, Any] | None:
        with self._lock:
            return self._load()["people"].get(_email(email))

    def for_phone(self, email: str) -> dict[str, Any]:
        """What one person sees in the app: their notes (newest first), open moments and progress. Notes the
        person can now see are marked as delivered through the app."""
        email = _email(email)
        self.prune()
        with self._lock:
            data = self._load()
            person = data["people"].get(email)
            if not person:
                return {"in_coach": False}
            confirmed = bool(person.get("notice_confirmed_at"))
            notes = [n for n in data["notes"] if n["person"] == email]
            changed = False
            if confirmed:
                for n in notes:
                    if n["status"] in ("ready to send", "held for notice"):
                        n["status"], n["sent_via"], n["sent_at"] = "sent", "app", _now_iso(self._clock())
                        n.pop("held_reason", None)
                        changed = True
            if changed:
                self._save(data)
            moments = {m["id"]: m for m in data["moments"] if m["person"] == email}
        ok, _ = self.ready(data["settings"])
        out_notes = []
        for n in sorted(notes, key=lambda n: -n["ts"])[:30] if confirmed else []:
            m = moments.get(n["moment"]) or {}
            out_notes.append({"id": n["id"], "moment": n["moment"], "at": n["at"], "text": n["text"],
                              "buttons": n["buttons"], "lesson": n["lesson"], "lesson_done": n["lesson_done"],
                              "level": m.get("level", "tip"), "level_word": LEVEL_WORDS[m.get("level", "tip")],
                              "status": m.get("status", "new"), "fix": m.get("fix"), "kind": m.get("kind", "")})
        return {"in_coach": True, "coaching_on": ok and person.get("coaching", True), "name": person.get("name", ""),
                "notice_confirmed": confirmed, "level": level_of(int(person.get("points") or 0)),
                "points": int(person.get("points") or 0), "lessons_done": person.get("lessons_done") or [],
                "notes": out_notes,
                "open": sum(1 for m in moments.values() if m["status"] in ("new", "needs help"))}

    def moment_person(self, moment_id: str) -> str | None:
        with self._lock:
            m = next((x for x in self._load()["moments"] if x["id"] == moment_id), None)
        return m["person"] if m else None

    def lessons(self) -> list[dict[str, Any]]:
        return [{"id": k, "title": v["title"], "card": v["card"], "steps": v["steps"],
                 "questions": [{"q": q["q"], "options": q["options"]} for q in v["questions"]],
                 "deeper": v.get("next")} for k, v in LESSONS.items()]

    def clear_sample(self) -> dict[str, int]:
        with self._lock:
            data = self._load()
            gone = {}
            sample_people = {e for e, p in data["people"].items() if p.get("sample")}
            for key in ("activity", "moments", "notes"):
                before = len(data[key])
                data[key] = [r for r in data[key] if not r.get("sample") and r.get("person") not in sample_people]
                gone[key] = before - len(data[key])
            for e in sample_people:
                data["people"].pop(e, None)
            gone["people"] = len(sample_people)
            self._save(data)
            return gone


# --------------------------------------------------------------------------- sample data
SAMPLE_PEOPLE = [
    {"email": "maya.tan@example.com", "name": "Maya Tan", "group": "Front desk", "reach": "email"},
    {"email": "ravi.kumar@example.com", "name": "Ravi Kumar", "group": "Teachers", "reach": "teams"},
    {"email": "lena.ong@example.com", "name": "Lena Ong", "group": "Accounts", "reach": "slack"},
]


def sample_events(now: float) -> list[dict[str, Any]]:
    h = 3600.0
    return [
        {"person": "maya.tan@example.com", "app": "google", "kind": "file_shared_public", "file_type": "spreadsheet",
         "ts": now - 30 * h},
        {"person": "maya.tan@example.com", "app": "google", "kind": "phishing_clicked", "ts": now - 20 * h},
        {"person": "ravi.kumar@example.com", "app": "microsoft", "kind": "app_access_granted", "ts": now - 12 * h},
        {"person": "ravi.kumar@example.com", "app": "microsoft", "kind": "sign_in_new_place", "country": "VN",
         "device": "phone", "ts": now - 8 * h},
        {"person": "lena.ong@example.com", "app": "microsoft", "kind": "mail_forward_outside", "ts": now - 4 * h},
        {"person": "lena.ong@example.com", "app": "google", "kind": "file_shared_personal", "file_type": "pdf",
         "ts": now - 2 * h},
        {"person": "maya.tan@example.com", "app": "google", "kind": "file_shared_public", "file_type": "document",
         "ts": now - 1 * h},
        {"person": "ravi.kumar@example.com", "app": "google", "kind": "phishing_blocked", "ts": now - 0.5 * h},
    ]


# --------------------------------------------------------------------------- the staff notice
def notice(overview: dict[str, Any], org: str, contact: str) -> str:
    """The Security Coach staff notice, built from the live settings. Says only what the code really does."""
    s = overview["settings"]
    org = org or "Our organisation"
    contact = contact or "your manager or HR"
    apps = [a["name"] for a in overview["apps"] if a["key"] in s["apps_on"]] or ["(no apps switched on yet)"]
    kinds = sorted({KINDS[k]["group"] for k in s["kinds_on"]}) or ["(none)"]
    lines = [f"# {org}: Security Coach notice to staff", "",
             "We use SentrAI's Security Coach to help everyone stay safe online at work. When you do something with "
             "your work account that could put you or the company at risk, you get a short, friendly note with a "
             "one-minute lesson and, where possible, a button to fix it. It is there to teach, not to catch people "
             "out.", "",
             "## What it looks at", "",
             f"The activity logs of these work apps: {', '.join(apps)}.", "",
             f"Only these kinds of action: {', '.join(kinds).lower()}.", "",
             "## What it keeps", "",
             "For each risky action: your work email, the app, the kind of action, the time, the country of a "
             "sign-in and the type of device. "
             + ("The name of a file you shared is kept too. " if s["file_names"] else
                "File names are not kept; a file shows only as \"a spreadsheet\", \"a document\" and so on. ")
             + "Internet addresses are reduced to a country.", "",
             "## What it never does", "",
             "It never reads the text of your emails, chats or files. It does not record your screen, your keys "
             "or the websites you visit"
             + (", except a warning when the SentrAI browser helper stops a known scam website" if "browser" in
                s["apps_on"] else "") + ". It does not watch personal accounts.", "",
             "## Who sees it", "",
             ("Owners and Admins of the security panel can see each person's coaching notes and progress."
              if s["show_names"] else
              "Owners and Admins of the security panel see team totals only, not names. The one exception is an "
              "urgent moment, such as a sign-in that looks like someone else is using your account: then they see "
              "who it is so they can help quickly."), "",
             "Coaching results are not used to rate your performance.", "",
             "## How long it is kept", "",
             f"Activity records: {overview['kept']['activity']}. Coaching notes and lesson progress: "
             f"{overview['kept']['notes']}. After that they are deleted automatically.", "",
             "## Your rights", "",
             f"You can see or download everything the coach holds about you, or ask for it to be erased. Contact: "
             f"{contact}.", ""]
    regions = [REGIONS[r] for r in s["regions"]]
    if regions:
        lines += ["## Local law", ""]
        for r in regions:
            extra = " We will ask for your consent before anything about you is recorded." if r["consent"] else ""
            lines.append(f"- {r['name']}: handled under the {r['law']}.{extra}")
        lines.append("")
    lines += ["_A starting point: check it with your data protection officer or lawyer before you share it._", ""]
    return "\n".join(lines)
