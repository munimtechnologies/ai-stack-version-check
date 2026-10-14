// Runs tests/vectors.json against lib/match.js. Run: node tests/match_test.js
// Exits 1 and lists every failure, so test_js.py can show them in one message.
"use strict";

const assert = require("assert");
const path = require("path");
const M = require(path.join(__dirname, "..", "lib", "match.js"));
const V = require(path.join(__dirname, "vectors.json"));

const failures = [];

function expect(label, run, want) {
  let got;
  try {
    got = run();
    assert.deepStrictEqual(got, want);
  } catch (e) {
    failures.push(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}` +
      (e instanceof assert.AssertionError ? "" : ` (${e.message})`));
  }
}

for (const [a, b, want] of V.compare) expect(`compare(${a}, ${b})`, () => M.compare(a, b), want);
for (const [v, want] of V.isVersion) expect(`isVersion(${JSON.stringify(v)})`, () => M.isVersion(v), want);
for (const [item, v, want] of V.affects) {
  expect(`affects(${JSON.stringify(item)}, ${v})`, () => M.affects(item, v), want);
}
for (const c of V.check) {
  const label = `check(${c.product}, ${c.version})`;
  expect(label, () => {
    const r = M.check(c.feed, c.product, c.version);
    const u = M.upgradeTarget(r.matched);
    return { matched: r.matched.map((i) => i.ids[0]), unchecked: r.unchecked, upgradeTo: u.upgradeTo, noFix: u.noFix };
  }, { matched: c.matched, unchecked: c.unchecked, upgradeTo: c.upgradeTo, noFix: c.noFix });
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("all vectors pass");
