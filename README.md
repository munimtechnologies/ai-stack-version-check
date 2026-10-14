# AI Stack Version Check

Answers one question: **is the version of the self-hosted AI app I run affected by a known
security advisory?** It comes in two forms:

- a **browser extension** (Chrome, Edge and other Chromium browsers, Manifest V3), and
- an **Open WebUI function** that checks the Open WebUI it runs in, its Ollama connections, or
  any app and version you type in a chat.

Both cover the 12 apps in [munimtechnologies/ai-stack-advisories](https://github.com/munimtechnologies/ai-stack-advisories)
(144 entries on 2026-10-14): Ollama, Open WebUI, vLLM, Langflow, Flowise, LiteLLM, n8n, Dify,
RAGFlow, AnythingLLM, ComfyUI and MCP Inspector. That feed includes advisories that have no CVE
or OSV.dev record, which version scanners built on those databases miss.

## Browser extension

Pick the app, type its version (or, for Ollama, Open WebUI, ComfyUI, Langflow and Flowise, click
**Read from this tab** while your app is open), and the extension lists the advisories that
apply. Each one has its IDs, a one-line summary, the affected range and a link to the source,
plus the newest fixed version among them.

### Install (until it is in the stores)

1. Download this repository (Code > Download ZIP) and unzip it.
2. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
3. Click **Load unpacked** and choose the unzipped folder.

### What it does and doesn't do

- It downloads `advisories.json` from GitHub, at most every 6 hours, and keeps the last copy for
  offline use. Click **Update advisories** to refresh now.
- **Read from this tab** runs only when you click it, and only on the tab you have open. It asks
  that page's own address for its version (Ollama `/api/version`, Open WebUI `/api/config`,
  ComfyUI `/system_stats`, Langflow and Flowise `/api/v1/version`), the same request the app's
  own interface makes. Nothing is sent anywhere else.
- It keeps your last app and version choice in the browser's extension storage. There are no
  analytics and no accounts. See [PRIVACY.md](PRIVACY.md).
- Permissions: `activeTab` and `scripting` (for Read from this tab), `storage`, and
  `raw.githubusercontent.com` (to download the feed).

## Open WebUI function

[`openwebui/ai_stack_version_check.py`](openwebui/ai_stack_version_check.py) is a Pipe: once
added, it shows up as a model called **AI Stack Version Check**.

### Install

1. In Open WebUI, go to **Admin Panel > Functions** and click **+** (new function).
2. Paste the whole file, keep the name, and save. Then switch the function on.
3. Start a chat with the **AI Stack Version Check** model.

### Use

- Send `check` (or an empty message) as an admin: it reads this Open WebUI's version and the
  version of each Ollama connection set up under Admin Panel > Settings > Connections, and
  reports the advisories that affect them.
- Or type apps and versions, several at once: `n8n 1.88.0, litellm==1.82.7`,
  `vllm/vllm-openai:v0.9.1`, `ghcr.io/open-webui/open-webui:v0.6.5`. Anyone with access to the
  model can do this; only admins can check the server itself.

### What it does and doesn't do

- It downloads `advisories.json` from GitHub (with jsDelivr as a fallback), at most every 6 hours.
  The Valves let you change the feed address, the cache time and the timeouts, or stop it reading
  Ollama versions.
- To read versions it asks each Ollama connection for `/api/version`, the same request Open WebUI
  itself makes. It sends no keys and nothing else leaves the server.
- It needs no extra Python packages. It is written for both of Open WebUI's settings stores
  (the older `app.state.config` and the `Config` store in recent releases such as 0.11 and 0.12) and tested against
  stand-ins for them, not yet on a live install. If it fails on yours, please open an issue
  with your Open WebUI version.

## Both

An empty result means that none of the *listed* advisories applies. It is not proof that a setup
is safe: exposure, settings and plugins matter too. For a check of a whole machine, see the free
[local-ai-checkup](https://github.com/munimtechnologies/local-ai-checkup) script, or the paid written
health check offered at [munimv2.github.io](https://munimv2.github.io/).

## Tests

These run before every change is published:

- `test_extension.py`: manifest and permissions, no remote or inline scripts, no unsafe DOM calls,
  and the version matching (through its Python twin `match_reference.py`) against
  `tests/vectors.json`.
- `test_feed.py`: downloads the live feed, checks that every version in it can be compared, and
  checks known answers (Ollama 0.1.33 is affected by CVE-2024-37032, 0.1.34 is not).
- `test_js.py`: runs `lib/match.js` itself on the same vectors under Node, and syntax-checks
  `popup.js`.
- `test_openwebui.py`: runs the Open WebUI function against the same vectors, a sample feed, a
  fake Ollama on 127.0.0.1 and stand-ins for both Open WebUI settings stores; checks how it reads
  apps and versions from a message, the admin-only server check, and the live feed.

## About

Made by MV2 of Munim, Inc. The code was written with AI agents working in his name, and checked
by the tests above. Corrections and new advisories are welcome as issues or pull requests in
[munimtechnologies/ai-stack-advisories](https://github.com/munimtechnologies/ai-stack-advisories).

Apache License 2.0.
