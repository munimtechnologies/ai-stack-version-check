// Version matching for AI Stack Version Check. A plain script: popup.html loads it with
// <script>, and tests/match_test.js loads it with require(). match_reference.py is its
// Python twin; keep the two in step (test_extension.py compares their patterns).
(function (root) {
  "use strict";

  const VERSION = /^v?(\d+(?:\.\d+)*)(.*)$/i;
  const PRE = /^[-.]?(a|b|rc|alpha|beta|dev|pre|preview)(\d|[-.]|$)/i;

  function parse(version) {
    const m = String(version).trim().match(VERSION);
    if (!m) return null;
    return { nums: m[1].split(".").map(Number), pre: PRE.test(m[2]) ? m[2] : "" };
  }

  function isVersion(version) {
    return parse(version) !== null;
  }

  // -1, 0 or 1, like a sort comparator. 1.0 equals 1.0.0, and a pre-release such as
  // 0.12.0-rc1 sorts before 0.12.0. Other suffixes (.post1, +cu121) are ignored.
  function compare(a, b) {
    const x = parse(a);
    const y = parse(b);
    if (!x || !y) throw new Error("not a version: " + (x ? b : a));
    for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
      const d = (x.nums[i] || 0) - (y.nums[i] || 0);
      if (d) return d < 0 ? -1 : 1;
    }
    if (x.pre === y.pre) return 0;
    if (!x.pre) return 1;
    if (!y.pre) return -1;
    return x.pre < y.pre ? -1 : 1;
  }

  // One advisory entry from advisories.json: introduced (inclusive) up to fixed
  // (exclusive), or up to lastAffected (inclusive) when there is no fix, or exactly
  // the versions listed in only.
  function affects(item, version) {
    if (item.only && item.only.length) return item.only.some((v) => compare(version, v) === 0);
    if (item.introduced && compare(version, item.introduced) < 0) return false;
    if (item.fixed) return compare(version, item.fixed) < 0;
    if (item.lastAffected) return compare(version, item.lastAffected) <= 0;
    return true;
  }

  // Entries that affect this version, and how many could not be compared.
  function check(feed, product, version) {
    const entry = feed.products[product];
    if (!entry) throw new Error("unknown app: " + product);
    if (!isVersion(version)) throw new Error("not a version: " + version);
    const matched = [];
    let unchecked = 0;
    for (const item of entry.items) {
      try {
        if (affects(item, version)) matched.push(item);
      } catch (e) {
        unchecked++;
      }
    }
    return { matched, unchecked };
  }

  // The newest fixed version among the matched entries, and how many have no fix yet.
  // Entries naming bad releases (only) are left out: any other release avoids them.
  function upgradeTarget(matched) {
    let upgradeTo = null;
    let noFix = 0;
    for (const item of matched) {
      if (item.only && item.only.length) continue;
      if (item.fixed) {
        if (!upgradeTo || compare(item.fixed, upgradeTo) > 0) upgradeTo = item.fixed;
      } else {
        noFix++;
      }
    }
    return { upgradeTo, noFix };
  }

  const api = { isVersion, compare, affects, check, upgradeTarget };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.AiStackMatch = api;
})(this);
