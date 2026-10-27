# Website icons

[Lucide](https://lucide.dev) 1.55.0 icons (ISC licence, a few derived from Feather, MIT: see [LICENSE](LICENSE)), picked
from the [free icon resources](https://github.com/noahelhadedy/free-icon-resources) list. Each one is pasted inline into
the page as SVG (`index.html`, `_layouts/default.html`), so the site loads no icon files and nothing from a CDN.
The console uses the same set: `mvp/dashboard/sentrai_ui/icons/`.

| Icon | Where |
|---|---|
| `logs` | How it works: Collect |
| `shapes` | How it works: Classify |
| `gauge` | How it works: Score |
| `shield-check` | How it works: Respond |
| `trending-up` | Risk grows with inaction |
| `timer` | Every fix expires |
| `file-lock` | Tamper-evident evidence |
| `bot` | Cyanide, the AI planner |
| `message-circle-question-mark` | Ask before you approve |
| `bell-ring` | Escalation that reaches people |
| `eye` | The sentry principle: the post on the line |
| `arrow-up` | Back to top button on the docs pages |

To change one: copy the SVG from https://lucide.dev/icons, drop its `class`, `width` and `height`, and paste it over the
old `<svg viewBox="0 0 24 24" …>` in the page. The page's CSS sizes it (`.ico svg`, `.post-mark svg`, `.to-top svg`).
