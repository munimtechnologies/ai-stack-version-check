# AI Stack Version Check

A small browser extension (Chrome, Edge and other Chromium browsers, Manifest V3) that answers
one question: **is the version of the self-hosted AI app I run affected by a known security
advisory?**

Pick the app, type its version (or, for Ollama, Open WebUI and ComfyUI, click **Read from this
tab** while your app is open), and the extension lists the advisories that apply. Each one has its
IDs, a one-line summary, the affected range and a link to the source, plus the newest fixed version
among them.

It covers the 12 apps in [munimv2/ai-stack-advisories](https://github.com/munimv2/ai-stack-advisories)
(130 entries when this was written): Ollama, Open WebUI, vLLM, Langflow, Flowise, LiteLLM, n8n,
Dify, RAGFlow, AnythingLLM, ComfyUI and MCP Inspector. That feed includes advisories that have
no CVE or OSV.dev record, which version scanners built on those databases miss.

## Install (until it is in the stores)

1. Download this repository (Code > Download ZIP) and unzip it.
2. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
3. Click **Load unpacked** and choose the unzipped folder.

## What it does and doesn't do

- It downloads `advisories.json` from GitHub, at most every 6 hours, and keeps the last copy for
  offline use. Click **Update advisories** to refresh now.
- **Read from this tab** runs only when you click it, and only on the tab you have open. It asks
  that page's own address for its version (Ollama `/api/version`, Open WebUI `/api/config`,
  ComfyUI `/system_stats`), the same request the app's own interface makes. Nothing is sent
  anywhere else.
- It keeps your last app and version choice in the browser's extension storage. There are no
  analytics and no accounts. See [PRIVACY.md](PRIVACY.md).
- Permissions: `activeTab` and `scripting` (for Read from this tab), `storage`, and
  `raw.githubusercontent.com` (to download the feed).
- An empty result means that none of the *listed* advisories applies. It is not proof that a
  setup is safe: exposure, settings and plugins matter too. For a full local check, see
  [local-ai-checkup](https://github.com/munimv2/local-ai-checkup).

## Tests

These run before every change is published:

- `test_extension.py`: manifest and permissions, no remote or inline scripts, no unsafe DOM calls,
  and the version matching (through its Python twin `match_reference.py`) against
  `tests/vectors.json`.
- `test_feed.py`: downloads the live feed, checks that every version in it can be compared, and
  checks known answers (Ollama 0.1.33 is affected by CVE-2024-37032, 0.1.34 is not).
- `test_js.py`: runs `lib/match.js` itself on the same vectors under Node, and syntax-checks
  `popup.js`.

## About

Made by MV2 of Munim, Inc. The code was written with AI agents working in his name, and checked
by the tests above. Corrections and new advisories are welcome as issues or pull requests in
[munimv2/ai-stack-advisories](https://github.com/munimv2/ai-stack-advisories).

MIT License.
