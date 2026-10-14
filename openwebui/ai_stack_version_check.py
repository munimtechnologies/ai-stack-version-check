"""
title: AI Stack Version Check
author: MV2 of Munim, Inc.
author_url: https://github.com/munimv2
funding_url: https://github.com/munimtechnologies/ai-stack-version-check
version: 0.1.0
license: Apache-2.0
description: Checks this Open WebUI, its Ollama connections, or any version you type (n8n, LiteLLM, vLLM, Dify, ComfyUI and more) against an open feed of security advisories, including ones missing from OSV.dev.
"""

# A Pipe: it shows up as a model named "AI Stack Version Check". Send it an empty message or
# "check" to check this server (admins only), or type apps and versions such as
# "n8n 1.88.0, litellm==1.82.7, vllm/vllm-openai:v0.9.1".
# The matching rules are the Python twin of lib/match.js in the browser extension.

import asyncio
import json
import re
import time
import urllib.request

from pydantic import BaseModel, Field

FEED_URL = "https://raw.githubusercontent.com/munimtechnologies/ai-stack-advisories/main/advisories.json"
FEED_MIRROR = "https://cdn.jsdelivr.net/gh/munimtechnologies/ai-stack-advisories@main/advisories.json"
REPO_URL = "https://github.com/munimtechnologies/ai-stack-version-check"
USER_AGENT = "ai-stack-version-check-openwebui/0.1.0"
MAX_TARGETS = 20

VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)(.*)$", re.I | re.A)
PRE = re.compile(r"^[-.]?(a|b|rc|alpha|beta|dev|pre|preview)(\d|[-.]|$)", re.I | re.A)

# A version written in a message: at least two numbers, an optional pre-release tag.
VERSION_TOKEN = re.compile(
    r"(?<![\w.])v?(\d+(?:\.\d+)+(?:[-.]?(?:a|b|rc|alpha|beta|dev|pre|preview)[\w.]*)?)(?!\w)(?!\.\d)",
    re.I | re.A,
)

# Names people use for the apps, squashed to lowercase letters and digits: image names
# (vllm/vllm-openai, langgenius/dify-api) and spellings (open-webui, anything llm).
ALIASES = {
    "vllmopenai": "vllm",
    "difyapi": "dify",
    "difyweb": "dify",
    "openwebui": "openwebui",
    "mcpinspector": "mcpinspector",
    "modelcontextprotocolinspector": "mcpinspector",
}

KIND_NOTES = {
    "feature": "Only if the affected feature is in use.",
    "windows": "Windows builds only.",
}

_CACHE = {"feed": None, "at": 0.0, "url": None}


def parse(version):
    m = VERSION.match(str(version).strip())
    if not m:
        return None
    return [int(n) for n in m.group(1).split(".")], (m.group(2) if PRE.match(m.group(2)) else "")


def is_version(version):
    return parse(version) is not None


def compare(a, b):
    x, y = parse(a), parse(b)
    if x is None or y is None:
        raise ValueError(f"not a version: {b if x else a}")
    for i in range(max(len(x[0]), len(y[0]))):
        d = (x[0][i] if i < len(x[0]) else 0) - (y[0][i] if i < len(y[0]) else 0)
        if d:
            return -1 if d < 0 else 1
    if x[1] == y[1]:
        return 0
    if not x[1]:
        return 1
    if not y[1]:
        return -1
    return -1 if x[1] < y[1] else 1


def affects(item, version):
    if item.get("only"):
        return any(compare(version, v) == 0 for v in item["only"])
    if item.get("introduced") and compare(version, item["introduced"]) < 0:
        return False
    if item.get("fixed"):
        return compare(version, item["fixed"]) < 0
    if item.get("lastAffected"):
        return compare(version, item["lastAffected"]) <= 0
    return True


def check(feed, product, version):
    matched, unchecked = [], 0
    for item in feed["products"][product]["items"]:
        try:
            if affects(item, version):
                matched.append(item)
        except ValueError:
            unchecked += 1
    return matched, unchecked


def upgrade_target(matched):
    upgrade_to, no_fix = None, 0
    for item in matched:
        if item.get("only"):
            continue
        if item.get("fixed"):
            if not upgrade_to or compare(item["fixed"], upgrade_to) > 0:
                upgrade_to = item["fixed"]
        else:
            no_fix += 1
    return upgrade_to, no_fix


def squash(text):
    return re.sub(r"[^a-z0-9]", "", str(text).lower())


def find_targets(text, products):
    """(app, version) pairs written in a message, and version-like words with no app before them."""
    names = dict(ALIASES)
    for slug, product in products.items():
        names.setdefault(squash(slug), slug)
        names.setdefault(squash(product.get("name", "")), slug)
    names = {k: v for k, v in names.items() if k and v in products}
    targets, skipped, start = [], [], 0
    for m in VERSION_TOKEN.finditer(text):
        before = squash(text[start:m.start()])
        start = m.end()
        version = m.group(1).rstrip(".")
        # The app named closest to the version wins; at the same place, the longer name.
        best = max(((before.rfind(k) + len(k), len(k), v) for k, v in names.items() if k in before), default=None)
        if not best:
            skipped.append(version)
        elif (best[2], version) not in targets:
            targets.append((best[2], version))
    return targets[:MAX_TARGETS], skipped


def message_text(body):
    for message in reversed(body.get("messages") or []):
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, list):
            return " ".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
        return str(content or "")
    return ""


def get_json(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read(5_000_000).decode("utf-8"))


def cell(text):
    return str(text).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").strip()


def describe_range(item):
    if item.get("only"):
        return "Bad releases: " + ", ".join(item["only"]) + "."
    start = f"from {item['introduced']} " if item.get("introduced") else ""
    if item.get("fixed"):
        return "Affected: " + (start or "all versions ") + f"before {item['fixed']}."
    if item.get("lastAffected"):
        return "Affected: " + start + f"up to {item['lastAffected']}, no fix yet."
    return "Affected: " + (start or "all versions") + ", no fix yet."


def advisory_row(item):
    title = ", ".join(item.get("ids") or []) or "Advisory"
    url = str(item.get("url") or "")
    if url.startswith("https://"):
        title = f"[{cell(title)}]({url.replace(')', '%29').replace(' ', '%20')})"
    else:
        title = cell(title)
    notes = [describe_range(item)]
    if KIND_NOTES.get(item.get("kind")):
        notes.append(KIND_NOTES[item["kind"]])
    if item.get("inPublicDatabases") is False:
        notes.append("Not in OSV.dev, so most scanners miss it.")
    return f"| {title} | {cell(item.get('severity') or '')} | {cell(item.get('summary') or '')} | {cell(' '.join(notes))} |"


def report_one(feed, product, version, where=""):
    if product not in feed["products"]:
        return f"### {product} {cell(version)}\n\nThe advisory feed doesn't cover this app yet."
    name = feed["products"][product]["name"]
    lines = [f"### {cell(name)} {cell(version)}" + (f" ({where})" if where else "")]
    if not is_version(version):
        lines.append(f"`{cell(version)}` is not a version number this check can compare.")
        return "\n".join(lines)
    matched, unchecked = check(feed, product, version)
    if not matched:
        count = len(feed["products"][product]["items"])
        if count == 0:
            lines.append(f"No advisories are listed for {name} yet.")
        elif count == 1:
            lines.append(f"The one advisory listed for {name} doesn't affect {version}.")
        else:
            lines.append(f"None of the {count} advisories listed for {name} affects {version}.")
    else:
        text = ("**1 known advisory affects this version.**" if len(matched) == 1
                else f"**{len(matched)} known advisories affect this version.**")
        upgrade_to, no_fix = upgrade_target(matched)
        if upgrade_to:
            text += f" The newest fix among them is in {upgrade_to}; check again after upgrading."
        if no_fix:
            text += " 1 has no fixed version yet." if no_fix == 1 else f" {no_fix} have no fixed version yet."
        lines += [text, "", "| Advisory | Severity | What | Affected |", "|---|---|---|---|"]
        lines += [advisory_row(item) for item in matched]
    if unchecked:
        lines.append(f"({unchecked} listed entries could not be compared.)")
    return "\n".join(lines)


def footer(feed):
    return (
        f"Advisories from [munimtechnologies/ai-stack-advisories](https://github.com/munimtechnologies/ai-stack-advisories), "
        f"checked {cell(feed.get('checked') or '?')}. It lists published advisories only, so a clean result "
        "is not proof that a setup is safe: exposure, settings and plugins matter too. "
        f"[AI Stack Version Check]({REPO_URL}) by MV2 of Munim, Inc."
    )


def help_text(feed):
    apps = ", ".join(sorted(p["name"] for p in feed["products"].values()))
    return (
        "Type an app and its version, for example `n8n 1.88.0`, `litellm==1.82.7` or "
        "`ghcr.io/open-webui/open-webui:v0.6.5`. Several at once are fine, separated by commas.\n\n"
        f"Apps covered: {apps}."
    )


def openwebui_version():
    try:
        from open_webui.env import VERSION as OPEN_WEBUI_VERSION

        return str(OPEN_WEBUI_VERSION)
    except Exception:
        pass
    try:
        from importlib.metadata import version

        return version("open-webui")
    except Exception:
        return None


async def ollama_urls(request):
    """The Ollama connections this server is set up with, skipping disabled ones."""
    try:
        from open_webui.models.config import Config  # recent releases (0.11, 0.12)

        enabled = await Config.get("ollama.enable", True)
        urls = await Config.get("ollama.base_urls", [])
        configs = await Config.get("ollama.api_configs", {})
    except Exception:
        try:
            config = request.app.state.config
            enabled = getattr(config, "ENABLE_OLLAMA_API", True)
            urls = config.OLLAMA_BASE_URLS
            configs = getattr(config, "OLLAMA_API_CONFIGS", {})
        except Exception:
            return []
    if not enabled:
        return []
    configs = configs if isinstance(configs, dict) else {}
    found = []
    for idx, url in enumerate(urls or []):
        url = str(url or "").rstrip("/")
        conf = configs.get(str(idx), configs.get(url, {}))
        if re.match(r"^https?://", url) and (not isinstance(conf, dict) or conf.get("enable", True)):
            found.append(url)
    return found[:10]


class Pipe:
    class Valves(BaseModel):
        FEED_URL: str = Field(default=FEED_URL, description="Where to download advisories.json from.")
        CACHE_HOURS: float = Field(default=6.0, description="How long a downloaded feed is reused.")
        CHECK_OLLAMA: bool = Field(default=True, description="Also read the version of each Ollama connection.")
        TIMEOUT_SECONDS: float = Field(default=10.0, description="Timeout for each download or version read.")

    def __init__(self):
        self.valves = self.Valves()

    async def load_feed(self):
        url = self.valves.FEED_URL or FEED_URL
        max_age = float(self.valves.CACHE_HOURS) * 3600
        if _CACHE["feed"] and _CACHE["url"] == url and time.time() - _CACHE["at"] < max_age:
            return _CACHE["feed"]
        errors = []
        for source in [url] + ([FEED_MIRROR] if url == FEED_URL else []):
            try:
                feed = await asyncio.to_thread(get_json, source, float(self.valves.TIMEOUT_SECONDS))
                if not isinstance(feed, dict) or not isinstance(feed.get("products"), dict):
                    raise ValueError("unexpected format")
                _CACHE.update(feed=feed, at=time.time(), url=url)
                return feed
            except Exception as e:
                errors.append(f"{source}: {e}")
        if _CACHE["feed"] and _CACHE["url"] == url:
            return _CACHE["feed"]
        raise RuntimeError("; ".join(errors))

    async def ollama_version(self, url):
        try:
            answer = await asyncio.to_thread(get_json, url + "/api/version", float(self.valves.TIMEOUT_SECONDS))
            version = answer.get("version") if isinstance(answer, dict) else None
            return (str(version), None) if version else (None, "no version in the answer")
        except Exception as e:
            return None, str(e)

    async def server_targets(self, request):
        """(app, version, where) for this Open WebUI and its Ollama connections, and notes on failures."""
        targets, notes = [], []
        version = openwebui_version()
        if version:
            targets.append(("openwebui", version, "this server"))
        else:
            notes.append("Couldn't read this Open WebUI's version. Type it instead, e.g. `open webui 0.6.5`.")
        if self.valves.CHECK_OLLAMA:
            for url in await ollama_urls(request):
                found, error = await self.ollama_version(url)
                if found:
                    targets.append(("ollama", found, f"at {url}"))
                else:
                    notes.append(f"Couldn't read the Ollama version at {url} ({cell(error)}). "
                                 "Type it instead, e.g. `ollama 0.12.3`.")
        return targets, notes

    async def pipe(self, body: dict, __user__: dict = None, __request__=None, __event_emitter__=None,
                   __task__=None) -> str:
        if __task__:
            task = str(__task__)
            if "title" in task:
                return json.dumps({"title": "AI stack version check"})
            if "tag" in task:
                return json.dumps({"tags": ["Security"]})
            if "follow" in task:
                return json.dumps({"follow_ups": []})
            return ""

        async def status(text, done=False):
            if __event_emitter__:
                await __event_emitter__({"type": "status", "data": {"description": text, "done": done}})

        await status("Downloading advisories...")
        try:
            feed = await self.load_feed()
        except Exception as e:
            await status("Couldn't download the advisories.", True)
            return f"Couldn't download the advisories ({cell(e)}). Check this server's internet access and try again."

        text = message_text(body)
        targets, skipped = find_targets(text, feed["products"])
        sections, notes = [], []
        if targets:
            sections = [report_one(feed, product, version) for product, version in targets]
        elif (__user__ or {}).get("role") != "admin":
            await status("Done.", True)
            return ("Only an admin can check this server's own versions.\n\n" + help_text(feed)
                    + "\n\n" + footer(feed))
        else:
            await status("Reading this server's versions...")
            found, notes = await self.server_targets(__request__)
            sections = [report_one(feed, product, version, where) for product, version, where in found]
        if skipped:
            notes.append("No app name before " + ", ".join(f"`{cell(v)}`" for v in skipped)
                         + ", so it was skipped. Put the app's name in front, e.g. `n8n 1.88.0`.")
        await status("Done.", True)
        parts = sections + notes
        if not sections:
            parts.append(help_text(feed))
        return "\n\n".join(parts + [footer(feed)])
