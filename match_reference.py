"""Python twin of lib/match.js, used by the tests. Keep the two in step."""

import re

VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)(.*)$", re.I | re.A)
PRE = re.compile(r"^[-.]?(a|b|rc|alpha|beta|dev|pre|preview)(\d|[-.]|$)", re.I | re.A)


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
    if not is_version(version):
        raise ValueError(f"not a version: {version}")
    matched, unchecked = [], 0
    for item in feed["products"][product]["items"]:
        try:
            if affects(item, version):
                matched.append(item)
        except ValueError:
            unchecked += 1
    return {"matched": matched, "unchecked": unchecked}


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
    return {"upgradeTo": upgrade_to, "noFix": no_fix}
