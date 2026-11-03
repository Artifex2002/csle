# CSLE (Cybersecurity Learning Environment) — engineering showcase

Public site: https://artifex2002.github.io/csle/

This branch contains the complete static showcase for Ashutosh Panda's Operational Technology extension to CSLE.

## Source

- `index.html`: project story, interactive topology, capabilities, tool explorer, and engineering decisions.
- `styles.css`: responsive Industrial lab design.
- `app.js`: endpoint, capability, tool, and integration-layer content and interactions.
- `.nojekyll`: serve the static files directly through GitHub Pages.

The project implementation remains on the [`emulation_OT` branch](https://github.com/Artifex2002/csle/tree/emulation_OT). The showcase links its claims to that source and distinguishes the OT additions from CSLE's existing infrastructure. The reviewed implementation snapshot is `3b590abe4e04aac204924e419ea8026bb3614d0f`.

## Publish

GitHub repository Settings → Pages → Deploy from a branch → `gh-pages` → `/(root)`.

Future pushes to this branch publish automatically. Use relative asset URLs so the site works under `/csle/`.

## Local preview

```sh
python3 -m http.server 4173 --bind 127.0.0.1
```

No build step, API keys, or backend are required. Google Fonts has system font fallbacks. The site explains the emulation; it does not run or connect to industrial equipment.
