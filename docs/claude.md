---
title: Keep or undo blocks from Claude
nav: docs
description: Connect your own Claude (Claude Code or Claude Desktop) to SentrAI so it can list blocks and keep or undo them, with your OK each time.
---

# Keep or undo blocks from Claude

You can let your own Claude see what SentrAI is blocking and keep or undo those blocks, the same as the
**Keep** and **Undo** buttons in the web panel. It works with any Claude app that takes an MCP server, such
as Claude Code or Claude Desktop.

SentrAI's own chat assistant, Sentry, can already offer Keep and Undo as buttons under its answers in the
panel. This page is for the SentrAI team's own Claude.

## What Claude gets

| Tool | What it does |
| --- | --- |
| `list_blocks` | What SentrAI is blocking now, per incident: what happened, which machine, what is blocked, until when, and how real each block is |
| `undo_block` | Lifts every block on one incident and lets the address or account back in (the panel's Undo) |
| `keep_block` | Keeps an incident's blocks with no time limit and closes the incident (the panel's Keep) |

`undo_block` and `keep_block` are marked as changes, so Claude asks you before each one. Both need a short
reason, which goes into the activity log with the change under `claude:<your login>`. The core applies the
same rules as the panel: you can't undo an incident with nothing blocked, and keeping a block that has run
out puts it back.

Each block says how real it is:

- **test only**: recorded but not enforced, because the firewall or that kind of action runs in test mode.
  Keeping it does not make it real.
- **enforced by the firewall**: the panel server's own firewall stops it.
- **on the block list**: the machine's agent fetches the list and enforces it, unless that agent was installed
  in dry-run mode (the default until `SENTRAI_FIREWALL_ENFORCE=1`). The panel can't yet tell which, so check
  the machine if it matters.

## Connect it

The server is part of the team command line: `sudo sentrai mcp`. It finds the panel's address and API token
itself, like every other `sentrai` command, and talks MCP on its input and output.

**Claude Code on the panel server:**

```bash
claude mcp add sentrai -- sudo sentrai mcp
```

**Claude Code on your own computer**, through SSH to the panel server (your SSH key must already work, and
`sudo` must not ask for a password):

```bash
claude mcp add sentrai -- ssh you@panel.example.com sudo sentrai mcp
```

**Claude Desktop**: add this to `claude_desktop_config.json` (Settings, Developer, Edit config), then restart
Claude Desktop:

```json
{
  "mcpServers": {
    "sentrai": {
      "command": "ssh",
      "args": ["you@panel.example.com", "sudo", "sentrai", "mcp"]
    }
  }
}
```

Then ask Claude things like "What is SentrAI blocking?" or "Undo the block on RSK-2026-081, that was our
office".

## Without SSH

From a computer that can reach the core's API (see [Where the core listens](api/#where-the-core-listens)),
run the command line from a copy of the code with the address and token set:

```bash
SENTRAI_CORE_URL=http://127.0.0.1:8000 SENTRAI_API_TOKEN=... python app/sentrai_cli.py mcp
```

Keep the token secret: it can change anything.
