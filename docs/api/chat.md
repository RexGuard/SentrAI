---
title: Chat and AI
nav: api
description: Ask Cyanide about incidents in plain words, drive the guided setup, and check, reload or test the AI model.
---

# Chat and AI

Cyanide is SentrAI's assistant. In the chat it answers questions about incidents, addresses and
machines by looking things up in the core. It never acts on its own: when it thinks something should
be done, it offers a button the operator can press. Without an AI model it still answers, from the
core's own explanations.

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.

## The chat

### `GET /chat`

The conversation so far, oldest first. It is kept in the core's memory only (the last 200 messages),
so it starts empty after a restart. Every question and answer is also written to the audit trail.

**Query**

| Name | Type | Default | Meaning |
| --- | --- | --- | --- |
| `limit` | integer, 0 to 200 | 100 | the last this many messages; 0 returns none |

**Returns**

```json
{
  "assistant": "Cyanide",
  "model": "online (anthropic:claude-opus-5)",
  "messages": [
    {"id": 1, "role": "operator", "text": "Which incident should I deal with first?", "ts": "2026-10-27T02:45:11+00:00",
     "operator": "erick", "incident": null},
    {"id": 2, "role": "assistant", "text": "...", "ts": "2026-10-27T02:45:12+00:00", "incident": null,
     "source": "ai", "looked_at": ["risk overview"], "suggestions": []}
  ]
}
```

`model` says in words which model answers, or why none does.

### `POST /chat`

Asks Cyanide a question and waits for the answer. Written to the audit trail (`operator_chat`).

**Body**

| Field | Type | Meaning |
| --- | --- | --- |
| `operator` | string, required | who is asking |
| `message` | string, required | the question; cut at 2000 characters |
| `incident` | string | the incident the question is about, such as `RSK-2026-084` |

```json
{"operator": "erick", "message": "Which incident should I deal with first?"}
```

**Returns** Cyanide's answer.

```json
{
  "id": 2,
  "role": "assistant",
  "text": "Risk index is 92 of 100 (critical); autonomous containment starts at 80.\n- RSK-2026-085: malware (critical), open, not acknowledged. ...",
  "ts": "2026-10-27T02:45:12+00:00",
  "incident": null,
  "source": "fallback",
  "looked_at": ["risk overview"],
  "suggestions": []
}
```

| Field | Meaning |
| --- | --- |
| `source` | `ai` when the model answered, `fallback` when the core's explanations did (no model, or it failed) |
| `looked_at` | what Cyanide looked up to answer |
| `suggestions` | buttons to show the operator; nothing happens unless they press one |
| `blocks` | tables, charts and figures to draw under the text (below); the text is Markdown |
| `followups` | up to three short questions the operator may ask next, shown as chips |
| `question` | the question this answers (used by Retry) |
| `feedback` | `{"vote": "up" or "down", "note", "by"}` once someone rated the answer |

Each block has a `type`:

| Block | Fields |
| --- | --- |
| `"type": "table"` | `title`, `columns` (up to 8), `rows` (up to 50, plain text cells), `link` (`"incident"`: the first column opens that incident) |
| `"type": "chart"` | `title`, `kind` (`bar` or `line`), `labels`, `series` (up to 3 `{name, values}` on one scale), `unit` |
| `"type": "stats"` | `items`: `{label, value, tone}`, tone being a risk band (`green`, `amber`, `red`, `critical`) |

With an AI model, Cyanide makes tables, charts and follow-ups with its `show_table`, `show_chart` and
`suggest_followups` tools. Without one, the overview answer carries the risk figures, a table of active incidents
and the risk over time, and a question about the week carries incidents per day and per kind.

Each suggestion has a `label` and a `reason`, plus what pressing it does:

| Suggestion | Fields | Pressing it calls |
| --- | --- | --- |
| a decision on an incident | `incident`, `decision`, `status` | [`POST /incidents/{iid}/decision`](incidents.html#post-incidentsiiddecision) |
| `"kind": "watch_log"` | `file_id`, `layer` | [`POST /log-sources`](events.html#post-log-sources) |
| `"kind": "quarantine_file"` | `finding_id` | [`POST /threats/{finding_id}/quarantine`](scans.html#post-threatsfinding_idquarantine) |
| `"kind": "backup_now"` | | [`POST /backups`](scans.html#post-backups) |

**Errors**: `400` `empty message`.

### `POST /chat/stream`

Same body as `POST /chat`, but the answer arrives while Cyanide works, as newline-delimited JSON
(`application/x-ndjson`), one object per line:

| Line | Meaning |
| --- | --- |
| `{"type": "step", "text": "Looking at risk overview"}` | a lookup has started |
| `{"type": "text", "delta": "Risk "}` | the next piece of the answer |
| `{"type": "done", "message": {...}}` | the saved answer, as `POST /chat` returns it |
| `{"type": "error", "detail": "..."}` | the question could not be answered |

Closing the connection is the Stop button: the work ends at the next step, and the chat keeps the part
already sent, marked `"stopped": true` and without buttons, tables or charts.

**Errors** (before the stream starts): `400` empty message, bad attachment.

### Attachments

`POST /chat` and `POST /chat/stream` take up to 3 `attachments`, the message may then be empty:

| Kind | Fields |
| --- | --- |
| a log or other text file | `{"name": "auth.log", "kind": "text", "text": "..."}`, kept up to 200,000 characters |
| a screenshot | `{"name": "shot.png", "kind": "image", "media_type": "image/png", "data": "<base64>"}`, PNG, JPEG, WebP or GIF up to 4 MB |

The model reads text files (as untrusted data) and pictures. Without a model, Cyanide reads a log with simple rules
(addresses, failed or refused lines) and says it cannot read pictures. The chat stores only each file's name, kind
and size (`attachments` on the question), never its content.

### `POST /chat/{message_id}/feedback`

Thumbs up or down on one of Cyanide's answers. Kept on the message and written to the audit trail
(`chat_feedback`); the Tuning page counts them.

**Body**: `{"vote": "up" | "down" | null, "note": "optional, what was wrong"}`. `null` takes the vote back.

**Returns** the message with its `feedback`.

**Errors**: `400` bad vote, `404` no such answer.

### `POST /chat/clear`

Empties the conversation. The audit trail keeps its copy.

**Returns**: `{"ok": true}`

## The guided setup

### `POST /chat/setup/interpret`

The guided setup in the dashboard's Chat page asks scripted questions with buttons. When someone types
an answer instead of pressing a button, this asks the AI model which button they meant, or lets it
answer the question they asked instead. Nothing is saved and nothing is written to the audit trail:
the setup saves only when the user confirms its summary, and the dashboard never sends secrets here.

**Body**

| Field | Type | Meaning |
| --- | --- | --- |
| `question` | string, required | the setup question |
| `options` | list, required | the buttons, each `{"value": "...", "label": "..."}` (the first 12 are used) |
| `answer` | string, required | what the user typed |

```json
{
  "question": "How should I alert you?",
  "options": [{"value": "telegram", "label": "Telegram"}, {"value": "email", "label": "Email"}],
  "answer": "by mail please"
}
```

**Returns**: `{"ai": true, "choice": "email", "reply": "Email it is."}`

`choice` is one of the option values, or `""` when the answer matches none. Without an AI model
(or when it fails) the answer is `{"ai": false, "choice": "", "reply": ""}`, and the dashboard asks
the user to press a button.

## The AI model

Cyanide can use Anthropic (Claude), OpenAI, DeepSeek, Command Code or any OpenAI-compatible service.
It is set in the dashboard's Configuration page, section AI, or with the setup wizard.

### `GET /ai`

Which AI model the running core uses, or why it uses none.

**Returns**

```json
{
  "engine": "Cyanide",
  "planner": "off (CYANIDE_ENABLED=0 turns the AI model off); playbooks only",
  "chat": "offline (CYANIDE_ENABLED=0 turns the AI model off): answers from the core's explanations",
  "online": false,
  "provider": null,
  "model": null,
  "key_source": null,
  "off_reason": "CYANIDE_ENABLED=0 turns the AI model off"
}
```

| Field | Meaning |
| --- | --- |
| `planner` | what plans responses to incidents: the model, or the fixed playbooks only |
| `chat` | what answers in the chat |
| `online` | whether a model is in use |
| `provider`, `model` | which one |
| `key_source` | the name of the setting the key came from, such as `ANTHROPIC_API_KEY`, never the key |
| `off_reason` | why there is no model, or `null` |

### `POST /ai/reload`

Reads the saved AI settings again and rebuilds the planner and the chat's model, with no restart. The
Configuration page calls it after saving.

**Returns** the same as `GET /ai`, after the reload.

### `POST /ai/test`

Makes one small real request to the model, through the same call Cyanide plans with, so a pass means
Cyanide can plan. It never changes what the core uses.

**Body** (optional). Without a body it tests the model the core uses now. With one it tests these
settings, which may not be saved yet (the Configuration form's **Test connection**):

| Field | Type | Meaning |
| --- | --- | --- |
| `provider` | string, required | `anthropic`, `openai`, `deepseek`, `commandcode` or `compatible` |
| `api_key` | string | the key to test; required in practice |
| `base_url` | string | the service's address, for `compatible` |
| `model` | string | the model; empty for the provider's default |

The key is used for this one request and not kept.

**Returns**

```json
{"ok": true, "provider": "anthropic", "model": "claude-opus-5", "ms": 812, "error": null, "hint": null, "tested": "form"}
```

`tested` is `form` (the settings in the body) or `running` (the model in use). When `ok` is `false`,
`error` says why and `hint` gives a next step for the common cases (a rejected key, an unknown model,
no credit left, no connection), for example:

```json
{"ok": false, "provider": "anthropic", "model": null, "ms": 0, "error": "enter the API key first", "hint": null, "tested": "form"}
```

A failed test is still status `200`: the answer is in `ok`.
