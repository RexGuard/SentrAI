---
title: SentrAI Gate
nav: docs
description: A standalone firewall for one Linux machine. No account, no sign-in, no panel. It drops attack traffic at the network card.
---

# SentrAI Gate

**SentrAI Gate** is SentrAI's standalone edition: a firewall for one Linux machine that needs no
account, no sign-in and no panel. It sits at the network card and drops flood traffic before the
rest of the system has to deal with it, so the machine stays reachable while it is under attack.

It holds the line and never crosses it: the gate only passes or drops packets arriving at this
machine. It never sends anything back at the sender.

> **Status: new, lightly tested.** The packet filter and its tests pass on a recent kernel
> (6.x), and it stopped floods on a test network. It has not yet run on a real internet-facing
> server or on kernels older than 6. Start in [watch-only mode](#watch-only-mode) on anything
> that matters.

## Install

One line, on the machine you want to guard:

```bash
curl -fsSL https://raw.githubusercontent.com/RexGuard/SentrAI/main/gate/install.sh | sudo bash
```

The installer:

1. gets the program (a ready-made download when one is published, otherwise it builds from
   source, fetching the Go build tool for that one build),
2. finds the network card that faces the internet,
3. picks a [profile](#profiles-and-traffic-levels) from the services it finds running,
4. puts **the address you are connected from on the allow list**, so the gate can never lock you
   out,
5. checks the machine (`sentrai-gate doctor`) and starts the gate as a background service.

To choose things yourself, add options after `bash -s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/RexGuard/SentrAI/main/gate/install.sh |
  sudo bash -s -- --profile game --level busy --observe
```

| Option | What it does |
| --- | --- |
| `--interface eth0` | Guard this network card |
| `--profile NAME` | Use this profile instead of the suggested one |
| `--level NAME` | How busy the machine is (default `normal`) |
| `--observe` | Start in watch-only mode: count what would be dropped, drop nothing |
| `--allow 1.2.3.4` | Also allow this address (repeatable) |
| `--no-start` | Install but do not start |
| `--ref BRANCH` | Install from another branch or tag |

**What you need:** Linux with kernel 5.10 or newer on a 64-bit Intel/AMD or ARM processor, and
`sudo`. systemd is used when present; without it, run `sudo sentrai-gate run` yourself.

**Remove:** `curl -fsSL https://raw.githubusercontent.com/RexGuard/SentrAI/main/gate/uninstall.sh | sudo bash`
(add `-s -- --purge` to delete settings and lists too).

## Everyday commands

```text
sentrai-gate stats               live screen
sentrai-gate status              one-screen summary
sentrai-gate doctor              check this machine can run the gate

sudo sentrai-gate allow add 1.2.3.4 office     never drop, limit or ban this sender
sudo sentrai-gate block add 5.6.7.0/24         always drop this sender
sudo sentrai-gate ban 1.2.3.4 2h               drop for a while (default 1 hour)
sudo sentrai-gate unban 1.2.3.4
sudo sentrai-gate bans                         who is banned right now

sudo sentrai-gate profile set game busy
sudo sentrai-gate observe on|off
sudo sentrai-gate reload                       apply edited settings and lists
sudo sentrai-gate events                       recent bans and attacks
sudo sentrai-gate start|stop|restart
```

Addresses can be IPv4 or IPv6, one address or a whole network such as `10.0.0.0/8`.

**Stopping is always safe.** If the gate is stopped, or ever crashes, the kernel removes the
filter and traffic flows exactly as before. The service then brings the gate back.

## The live screen

`sentrai-gate stats` shows what is happening now. Keys `1` to `5` (or the arrow keys) switch
pages, `q` quits.

| Page | Shows |
| --- | --- |
| Overview | Packets and speed now, peak, the learned normal level, graphs of traffic and drops, and where in the pipeline packets were stopped |
| Bans | Who is banned, how long is left, and why |
| Events | Bans, network bans, attacks starting and ending, newest first |
| Attacks | Past attacks: kind, length, peak, how much was dropped |
| System | Kernel, mode, what the kernel offers and what the gate fell back to, the limits in use |

## How it decides

Every arriving packet goes through the same stages, in this order. The first stage with an answer
wins.

| # | Stage | What it does |
| --- | --- | --- |
| 1 | Read | Works out who sent the packet and what it is. Anything that is not internet traffic (for example the messages machines on the same wire use to find each other) passes untouched |
| 2 | Allow list | Senders you trust skip every later stage |
| 3 | Banned | Drops senders and networks that are banned or on your block list |
| 4 | Breaker | If one processor is swamped, sheds a share of traffic so the machine stays alive |
| 5 | Checks | Drops packets that cannot be real: broken headers, senders that cannot exist on the internet, impossible TCP flag mixes, and (under attack) fragments |
| 6 | Reflection | Drops replies nobody on this machine asked for: oversized answers from services that attackers bounce traffic off (DNS, time servers and others), and "yes, let's connect" replies to calls this machine never made |
| 7 | Rate | Scores each sender against its limits and bans at the line |

### Scores and bans

Each sender is measured every second on six things: packets, data, TCP packets, UDP packets, ICMP
(ping) packets and new connections. Passing a limit adds points; passing it twice or four times
over adds more. A clean second takes points off again. At **100 points** the sender is banned.

One broken limit alone is a warning, not a ban. Two together, or one broken four times over,
crosses the line. During a flood the gate does not wait for the second to end: it looks every 256
packets, so a flooding sender is banned within a few hundred packets.

A first ban lasts the profile's ban time (an hour by default). Each repeat lasts longer: 2, 4, 8,
24 and then 72 times as long, up to 30 days.

When 8 addresses from the same network of 256 are banned at once, the whole network is banned for
twice the ban time. (Off in the `game`, `hosting` and `edge` profiles, where many real people can
share one network.)

### Learning what is normal

The gate keeps a moving average of the machine's traffic that leans on recent minutes, and how
much that traffic normally wobbles. From these it draws an **attack line**: the highest of a fixed
floor, four times normal, and normal plus six times the usual wobble.

When traffic stays over the line for 3 seconds in a row, the gate calls an attack and gets
stricter until it has been calm for 20 seconds:

- every per-sender limit is halved,
- each sender gets a hard cap, however it scores,
- never-seen senders are let in at a limited rate, because a flood of brand-new addresses is
  almost always forged,
- fragments are dropped.

Only calm seconds teach the normal level, and one second can only teach so much, so neither an
attack nor a slow climb toward the line can train it upward. The first 20 seconds after a start
are learning only. What was learned is kept across restarts.

### Telling answers from attacks

A machine also receives traffic it asked for: downloads, updates, DNS answers. On kernel 6.6 or
newer the gate notes every connection **this machine starts**, so the far end of a download is
never scored as a flood, a DNS answer you asked for is never mistaken for a bounced attack, and a
reply to a call you never made is dropped on sight. The notes are read-only: outgoing traffic is
never dropped or changed.

## Profiles and traffic levels

A profile says what the machine is for. A level scales the profile to how busy it is.

| Profile | For | Packets / new connections per sender each second (at `normal`) |
| --- | --- | --- |
| `locked-down` | Admin panels, login pages, a private site | 300 / 40 |
| `website` | Blogs, shops and company sites | 700 / 120 |
| `balanced` | A bit of everything. The safe default | 1200 / 200 |
| `api` | Busy web apps and APIs, reverse proxies | 2500 / 500 |
| `game` | Game and voice servers | 2500 / 250 |
| `database` | Database, storage, backup and mail servers | 4000 / 100 |
| `hosting` | Machines that carry other people's servers | 6000 / 1200 |
| `edge` | Content delivery, large proxies, download servers | 12000 / 2500 |

| Level | Limits are multiplied by |
| --- | --- |
| `quiet` | 0.5 |
| `light` | 0.75 |
| `normal` | 1 |
| `busy` | 1.5 |
| `heavy` | 2.5 |
| `extreme` | 4 |

`sentrai-gate profile list` shows them on the machine, `sentrai-gate profile suggest` picks one
from the services it finds listening, and `sudo sentrai-gate profile set game busy` switches.

If real visitors get banned, go up a level. If attackers get too much room, go down one.

## Watch-only mode

`sudo sentrai-gate observe on` makes the gate count everything it **would** drop while dropping
nothing. The live screen says WATCHING ONLY and shows "Would drop". Run like this for a day on a
new machine, read the Bans and Events pages, and switch to `observe off` once nothing surprising
shows up.

## Settings

Settings live in `/etc/sentrai-gate/config.yaml`. Only four lines matter to most people:

```yaml
interface: eth0
observe: false
profile: balanced
level: normal
```

Everything else is optional and listed in the file as comments with the profile's values. Remove
the `#` from a line to set your own value, then run `sudo sentrai-gate reload`.

| Section | Controls |
| --- | --- |
| `limits` | The six per-sender limits |
| `scoring` | Points per broken limit, the ban line, points forgiven per clean second |
| `bans` | Ban time, how repeats grow, when a whole network is banned |
| `checks` | The "cannot be real" tests. `private_senders: true` also drops private-range senders (leave off on cloud machines, whose own services use them). `fragments` is `pass`, `drop` or `attack` |
| `reflection` | The services watched for bounced replies and the size that counts as oversized; `unasked_replies` for the connection check |
| `token_bucket` | An optional smooth per-sender limiter, off by default |
| `attack` | The attack line, how long before an attack is called and ended, how much stricter the gate gets |
| `breaker` | The per-processor overload breaker |
| `sizes` | How many senders and bans the gate can remember (change needs a restart) |

The lists are plain files, one address or network per line, with a note after `#`:
`/etc/sentrai-gate/allow.list` and `/etc/sentrai-gate/block.list`. The `allow` and `block`
commands edit them for you.

## Works with the kernel you have

The gate asks the kernel what it offers and uses the best of it. When something is missing it
steps down instead of failing, and the System page (and `sentrai-gate doctor`) says what it did.

| If the machine lacks | The gate |
| --- | --- |
| A network card driver with the fastest mode | Uses the kernel's general mode. Slower, but still ahead of the normal firewall and the apps |
| Kernel 6.6 (connection notes) | Tells answers apart by port numbers instead, and does not trust that guess while under attack |
| Instant ban notices | Picks bans up by checking the ban list every second |
| Room for the full pipeline | Loads a simpler one: first without stages 4 and 6 and the extras of stage 7, then with the allow list, bans and checks only |

## Where things are

| | |
| --- | --- |
| Program | `/usr/local/bin/sentrai-gate` |
| Settings and lists | `/etc/sentrai-gate/` |
| Bans and the learned normal level, kept across restarts | `/var/lib/sentrai-gate/state.json` |
| Event and attack logs (one JSON line each) | `/var/log/sentrai-gate/events.log`, `attacks.log` |
| Service | `sentrai-gate.service` (`journalctl -u sentrai-gate`) |
| Source | [`gate/`](https://github.com/RexGuard/SentrAI/tree/main/gate) |

## Good to know

- **It guards one network card.** Traffic arriving on other cards is not filtered.
- **It protects the machine, not the line.** A flood bigger than your connection still fills the
  connection before it reaches the gate. That needs help from your provider.
- **Routers and machines with several internet lines:** turn `reflection.unasked_replies` off,
  since replies can come back on a different card than the call went out on. The `hosting`
  profile already does.
- **It does not replace the normal firewall.** Keep your port rules. The gate deals with floods
  and junk; it does not decide which ports are open.
- **SentrAI's panel is not involved.** The gate runs entirely on the machine and sends nothing
  anywhere.

## Something is wrong

| What you see | Do this |
| --- | --- |
| You are locked out | From the provider's console: `sudo sentrai-gate stop`. Then `sudo sentrai-gate allow add YOUR-ADDRESS` and start again |
| A real visitor is banned | `sudo sentrai-gate unban ADDRESS`, then go up a level, or `allow add` them |
| The gate will not start | `sentrai-gate doctor`, then `journalctl -u sentrai-gate -n 30` |
| Mode says `generic` | The card's driver has no fastest mode. The gate still works |
| Settings change did nothing | `sudo sentrai-gate reload`. It names any line it could not read and keeps the old settings |
