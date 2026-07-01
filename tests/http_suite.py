#!/usr/bin/env python3
"""Drive ALL scenarios through the live HTTP path and confirm 100%.

Per scenario: GET /scenario (server materialises + injects, returns run_id) ->
POST /submit blank (the debrief page reveals the per-run correct key) ->
POST /submit with those answers -> expect 100%. Pure HTTP (urllib), no imports
from the app. Run against a live tool instance.

Env:
  WSOC_URL   base URL of the running tool (default http://127.0.0.1:8101)
  WSOC_DIR   scenarios dir (default: ../scenarios relative to this file)

Note: this exercises the HTTP handler + scoring end to end. It leaves two
attempts rows per scenario under trainee 'http-suite' (a blank reveal submit +
the real one); purge them from training.db afterwards if you want a clean board.
"""
import json, glob, os, re, html, sys, time, urllib.parse, urllib.request

BASE = os.environ.get("WSOC_URL", "http://127.0.0.1:8101")
SC_DIR = os.environ.get(
    "WSOC_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scenarios"))
TRAINEE = "http-suite"

RE_RUN = re.compile(r"name=run_id value='([^']*)'")
RE_CORRECT = re.compile(r"Correct:</span> <span class=res-ok>(.*?)</span>")
RE_PCT = re.compile(r"<h1 style='margin:0'>([0-9.]+)%</h1>")


def http_get(path):
    return urllib.request.urlopen(BASE + path, timeout=15).read().decode()


def http_post(fields):
    data = urllib.parse.urlencode(fields, doseq=True).encode()
    return urllib.request.urlopen(BASE + "/submit", data=data, timeout=15).read().decode()


def load():
    out = []
    for p in sorted(glob.glob(os.path.join(SC_DIR, "*.json"))):
        out.append((os.path.basename(p), json.load(open(p))))
    order = {"beginner": 0, "intermediate": 1, "advanced": 2}
    out.sort(key=lambda x: (order.get(x[1].get("difficulty"), 9), x[0]))
    return out


def run_one(d):
    sid, qs = d["id"], d["questions"]
    page = http_get("/scenario?id=%s&trainee=%s" % (urllib.parse.quote(sid), TRAINEE))
    m = RE_RUN.search(page)
    if not m:
        return None, "no run_id in page"
    run_id = m.group(1)
    # reveal the per-run correct key via a blank submit
    res = http_post({"trainee": TRAINEE, "sid": sid, "run_id": run_id})
    corrects = [html.unescape(x) for x in RE_CORRECT.findall(res)]
    if len(corrects) != len(qs):
        return None, "parsed %d corrects != %d questions" % (len(corrects), len(qs))
    # Prefer the static JSON answer when it has no $token (avoids ambiguous
    # ", " re-splitting of the revealed multi display, e.g. an option that
    # itself contains ", "); use the revealed value only for randomised ones.
    fields = [("trainee", TRAINEE), ("sid", sid), ("run_id", run_id)]
    for q, corr in zip(qs, corrects):
        key, t, ans = "q_" + q["id"], q["type"], q.get("answer")
        tokened = "$" in json.dumps(ans)
        if not tokened:
            if t == "multi":
                for item in ans:
                    fields.append((key, item))
            elif t == "ipset":
                fields.append((key, ", ".join(ans)))
            elif t == "text":
                fields.append((key, ans[0] if isinstance(ans, list) else ans))
            else:
                fields.append((key, ans))
        else:
            if t == "multi":
                for item in corr.split(", "):
                    fields.append((key, item))
            elif t == "text":
                fields.append((key, corr.split(" / ")[0]))
            else:  # choice, ipset
                fields.append((key, corr))
    res2 = http_post(fields)
    mp = RE_PCT.search(res2)
    return (float(mp.group(1)) if mp else -1.0), "ok"


def main():
    rows = []
    for fname, d in load():
        pct, note = run_one(d)
        status = "PASS" if pct == 100.0 else "FAIL"
        rows.append((status, fname))
        print("%-4s %-12s %-34s %6s  %s" % (
            status, d.get("difficulty"), fname,
            ("%.1f" % pct) if pct is not None and pct >= 0 else "n/a", note))
        time.sleep(0.2)
    npass = sum(1 for r in rows if r[0] == "PASS")
    print("-" * 78)
    print("HTTP suite: %d/%d PASS" % (npass, len(rows)))
    return 0 if npass == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
