# Console icons

[Lucide](https://lucide.dev) icons (ISC licence, a few derived from Feather, MIT: see [LICENSE](LICENSE)),
picked from the [free icon resources](https://github.com/noahelhadedy/free-icon-resources) list.
Bundled, so the console looks the same offline and loads nothing from a CDN.

| File | What |
|---|---|
| `sentrai-icons.woff2` | the Lucide icons `icons.json` names, as one font, built from `lucide-static` 1.55.0 |
| `icons.json` | the icon names the console uses, each with the Lucide icon drawn for it |
| `build_font.py` | rebuilds the font from `icons.json` and a copy of `lucide-static` |
| `preview.html` | every name next to its icon; open it in a browser after a rebuild |

## How it works

Streamlit draws every widget icon (`st.button(icon=":material/save:")`, chat avatars, expander arrows, its
own menus) as text in the "Material Symbols Rounded" font, with the icon's name as a ligature. `theme.icon_css()`
declares this font under that same family name, with the same metrics, so Streamlit's widgets and the console's
own `<span class="mi">name</span>` (app.py `icon()`, the routing editor) all draw Lucide, and app.py keeps using the Material names
listed in `icons.json`. A name the font does not know draws as one dashed square instead of leaking the name as
text; `tests/test_icons.py` fails when app.py or shaping.py uses a name that is not in `icons.json`.

## Adding or changing an icon

1. Find the Lucide icon at https://lucide.dev/icons and add or change the line in `icons.json`
   (`"material_name": "lucide-name"`).
2. Rebuild, from this folder:

       pip install fonttools brotli uharfbuzz
       npm pack lucide-static@1.55.0 && tar -xzf lucide-static-1.55.0.tgz
       python build_font.py package

   The build shapes every name with HarfBuzz first and stops if one would not turn into its icon.

   A newer `lucide-static` works too; update the version above and in the table.
3. Open `preview.html` to check the glyphs, then commit `sentrai-icons.woff2`, `icons.json`, `preview.html`
   and `LICENSE` (the build copies the package's licence).
