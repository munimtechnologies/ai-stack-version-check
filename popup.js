// Popup: choose an app and its version, see which advisories in the feed affect it.
"use strict";

const FEED_URL = "https://raw.githubusercontent.com/munimv2/ai-stack-advisories/main/advisories.json";
const MAX_AGE_MS = 6 * 60 * 60 * 1000;

// Apps whose own web page can tell their version: the path asked on the tab's address,
// and where the version sits in the JSON answer. Other apps: type the version.
const READERS = {
  ollama: { path: "/api/version", key: ["version"] },
  openwebui: { path: "/api/config", key: ["version"] },
  comfyui: { path: "/system_stats", key: ["system", "comfyui_version"] },
};

const KIND_NOTES = {
  feature: "Only if the affected feature is in use.",
  windows: "Windows builds only.",
};

const $ = (id) => document.getElementById(id);
let feed = null;

function setStatus(text) {
  $("status").textContent = text;
}

async function loadFeed(force) {
  const saved = await chrome.storage.local.get(["feed", "fetchedAt"]);
  if (saved.feed && !force && Date.now() - saved.fetchedAt < MAX_AGE_MS) return saved;
  try {
    const resp = await fetch(FEED_URL, { cache: "no-cache" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const fresh = await resp.json();
    if (!fresh || typeof fresh.products !== "object") throw new Error("unexpected format");
    const entry = { feed: fresh, fetchedAt: Date.now() };
    await chrome.storage.local.set(entry);
    return entry;
  } catch (e) {
    if (saved.feed) return { ...saved, error: e.message };
    throw e;
  }
}

async function fillProducts() {
  const select = $("product");
  const { last } = await chrome.storage.local.get("last");
  const current = select.value || (last && last.product);
  select.replaceChildren();
  const entries = Object.entries(feed.products).sort((a, b) => a[1].name.localeCompare(b[1].name));
  for (const [slug, product] of entries) {
    const option = document.createElement("option");
    option.value = slug;
    option.textContent = product.name;
    select.append(option);
  }
  if (current && feed.products[current]) select.value = current;
  if (last && last.product === select.value && !$("version").value) $("version").value = last.version;
  $("read").hidden = !READERS[select.value];
}

function describeRange(item) {
  if (item.only && item.only.length) return "Bad releases: " + item.only.join(", ") + ".";
  const from = item.introduced ? "from " + item.introduced + " " : "";
  if (item.fixed) return "Affected: " + (from || "all versions ") + "before " + item.fixed + ".";
  if (item.lastAffected) return "Affected: " + from + "up to " + item.lastAffected + ", no fix yet.";
  return "Affected: " + (from || "all versions") + ", no fix yet.";
}

function renderItem(item) {
  const li = document.createElement("li");
  const head = document.createElement("div");
  const title = item.ids && item.ids.length ? item.ids.join(", ") : "Advisory";
  if (/^https:\/\//.test(item.url || "")) {
    const link = document.createElement("a");
    link.href = item.url;
    link.target = "_blank";
    link.rel = "noopener";
    link.textContent = title;
    head.append(link);
  } else {
    head.append(title);
  }
  if (item.severity) {
    const sev = document.createElement("span");
    sev.className = "sev";
    sev.textContent = String(item.severity);
    head.append(" ", sev);
  }
  const summary = document.createElement("p");
  summary.textContent = item.summary || "";
  const range = document.createElement("p");
  range.className = "range";
  range.textContent = describeRange(item) + (KIND_NOTES[item.kind] ? " " + KIND_NOTES[item.kind] : "");
  li.append(head, summary, range);
  return li;
}

function runCheck() {
  const list = $("results");
  list.replaceChildren();
  if (!feed) {
    setStatus("The advisories haven't downloaded yet. Click 'Update advisories'.");
    return;
  }
  const product = $("product").value;
  const version = $("version").value.trim();
  if (!AiStackMatch.isVersion(version)) {
    setStatus("Type a version number, such as 0.6.34.");
    return;
  }
  chrome.storage.local.set({ last: { product, version } });
  const name = feed.products[product].name;
  const { matched, unchecked } = AiStackMatch.check(feed, product, version);
  let text;
  if (!matched.length) {
    const count = feed.products[product].items.length;
    text = `None of the ${count} advisories listed for ${name} affects ${version}. ` +
      "The list covers published advisories only, so this is not proof that a setup is safe.";
  } else {
    const { upgradeTo, noFix } = AiStackMatch.upgradeTarget(matched);
    text = matched.length === 1
      ? `1 known advisory affects ${name} ${version}.`
      : `${matched.length} known advisories affect ${name} ${version}.`;
    if (upgradeTo) text += ` The newest fix among them is in ${upgradeTo}; check again after upgrading.`;
    if (noFix) text += noFix === 1 ? " 1 has no fixed version yet." : ` ${noFix} have no fixed version yet.`;
    for (const item of matched) list.append(renderItem(item));
  }
  if (unchecked) text += ` (${unchecked} listed entries could not be compared.)`;
  setStatus(text);
}

// Runs inside the tab, so the request goes to the app's own address with its own login.
async function fetchVersion(path, key) {
  try {
    const resp = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!resp.ok) return { error: "the page answered HTTP " + resp.status };
    let value = await resp.json();
    for (const k of key) value = value == null ? undefined : value[k];
    return typeof value === "string" ? { version: value } : { error: "no version in the answer" };
  } catch (e) {
    return { error: String((e && e.message) || e) };
  }
}

async function readFromTab() {
  const product = $("product").value;
  const reader = READERS[product];
  if (!reader || !feed) return;
  const name = feed.products[product].name;
  setStatus("Reading the version from this tab...");
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !/^https?:\/\//.test(tab.url || "")) throw new Error(`open your ${name} page in this tab first`);
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      args: [reader.path, reader.key],
      func: fetchVersion,
    });
    const answer = injection && injection.result;
    if (!answer || answer.error) throw new Error((answer && answer.error) || "no answer");
    $("version").value = answer.version;
    runCheck();
  } catch (e) {
    setStatus(`Couldn't read the version (${e.message}). Type it instead: ${name} shows it in its settings or about page.`);
  }
}

async function start(force) {
  setStatus(force ? "Downloading advisories..." : "");
  try {
    const entry = await loadFeed(force);
    feed = entry.feed;
    $("feed-info").textContent = `Advisories checked ${feed.checked || "?"}, downloaded ` +
      new Date(entry.fetchedAt).toLocaleString() + ".";
    await fillProducts();
    setStatus(entry.error ? `Couldn't update (${entry.error}), so the saved copy is used.` : "");
  } catch (e) {
    setStatus(`Couldn't download the advisories (${e.message}). Check the connection and try again.`);
  }
}

$("form").addEventListener("submit", (e) => {
  e.preventDefault();
  runCheck();
});
$("product").addEventListener("change", () => {
  $("read").hidden = !READERS[$("product").value];
  $("results").replaceChildren();
  setStatus("");
});
$("read").addEventListener("click", readFromTab);
$("refresh").addEventListener("click", () => start(true));
start(false);
