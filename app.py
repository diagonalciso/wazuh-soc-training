#!/usr/bin/env python3
"""wazuh-soc-training — web platform.

Instructor/trainee flow:
  1. trainee enters a name, picks a scenario
  2. 'Start drill' injects the scenario's labeled attack into the LIVE Wazuh
     manager (analysisd queue socket) — real alerts appear in the real dashboard
  3. trainee triages in the Wazuh dashboard (link provided), then answers the
     triage questions here
  4. answers are auto-graded against ground truth; debrief + score + leaderboard

Pure Python 3 stdlib. Runs ON the Wazuh manager (queue socket is local).
Read [docs/ADMIN.md]. This is a training tool, not a security control.
"""
import html
import json
import os
import glob
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import random
import threading

import config
import injector
import scoring
import randomizer

# ---------------------------------------------------------------- scenarios

def load_scenarios():
    out = {}
    for path in sorted(glob.glob(os.path.join(config.SCENARIO_DIR, "*.json"))):
        try:
            with open(path) as f:
                sc = json.load(f)
            out[sc["id"]] = sc
        except (OSError, ValueError, KeyError) as e:
            print("[scenario] skip %s: %s" % (path, e))
    return out


SCENARIOS = load_scenarios()

# Difficulty levels a trainee can pick, in order, restricted to what exists.
_LEVEL_ORDER = ["beginner", "intermediate", "advanced"]
LEVELS = [d for d in _LEVEL_ORDER
          if any(s.get("difficulty") == d for s in SCENARIOS.values())]

# Materialised (randomised) scenario per run_id — grading must use the SAME
# concrete answer key that was injected, not the static template. Bounded.
RUN_STORE = {}
_RUN_LOCK = threading.Lock()
_RUN_CAP = 500


def _store_run(run_id, concrete):
    with _RUN_LOCK:
        RUN_STORE[run_id] = concrete
        if len(RUN_STORE) > _RUN_CAP:
            for k in list(RUN_STORE)[:len(RUN_STORE) - _RUN_CAP]:
                RUN_STORE.pop(k, None)


def _get_run(run_id):
    with _RUN_LOCK:
        return RUN_STORE.get(run_id)


def pick_scenario(difficulty):
    """Random scenario at a difficulty (blind). '' / 'any' = any level."""
    pool = [s for s in SCENARIOS.values()
            if not difficulty or difficulty == "any"
            or s.get("difficulty") == difficulty]
    return random.choice(pool) if pool else None

# ---------------------------------------------------------------- html

CSS = """
:root{--bg:#0d1117;--pan:#161b22;--bd:#30363d;--fg:#c9d1d9;--mut:#8b949e;
--acc:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--cy:#39d0d8}
*{box-sizing:border-box}body{background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:900px;margin:0 auto;padding:24px}
h1,h2,h3{color:#fff;font-weight:600}h1{font-size:22px}
.top{display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--bd);
padding-bottom:14px;margin-bottom:20px}
.badge{font-size:11px;padding:2px 8px;border-radius:10px;border:1px solid var(--bd);
color:var(--mut)}.pan{background:var(--pan);border:1px solid var(--bd);
border-radius:8px;padding:16px;margin:14px 0}
.card{display:block;background:var(--pan);border:1px solid var(--bd);border-radius:8px;
padding:14px;margin:10px 0}.card:hover{border-color:var(--acc);text-decoration:none}
.diff{font-size:11px;padding:1px 7px;border-radius:8px;margin-left:8px}
.beginner{background:#123524;color:var(--ok)}.intermediate{background:#3a2f12;color:var(--warn)}
.advanced{background:#3a1518;color:var(--bad)}
input,button,select{font:inherit}input[type=text]{background:#0d1117;border:1px solid var(--bd);
color:var(--fg);border-radius:6px;padding:8px 10px;width:100%}
.btn{background:var(--acc);color:#04121f;border:none;border-radius:6px;padding:9px 16px;
font-weight:600;cursor:pointer}.btn:hover{opacity:.9}.btn.g{background:var(--ok)}
.q{margin:16px 0;padding-bottom:8px;border-bottom:1px solid var(--bd)}
.q label.opt{display:block;padding:4px 0;color:var(--fg);font-weight:400;cursor:pointer}
.mut{color:var(--mut)}.right{float:right}.mono{font-family:ui-monospace,monospace}
.res-ok{color:var(--ok)}.res-part{color:var(--warn)}.res-bad{color:var(--bad)}
.bar{height:8px;background:#0d1117;border-radius:4px;overflow:hidden;border:1px solid var(--bd)}
.bar>i{display:block;height:100%;background:var(--cy)}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px 8px;
border-bottom:1px solid var(--bd)}th{color:var(--mut);font-weight:500}
.warnbox{background:#3a1518;border:1px solid var(--bad);border-radius:6px;padding:10px;
color:#ffb3ae;font-size:13px}
"""


def page(title, body):
    return ("<!doctype html><html><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title>"
            "<link rel=\"icon\" href=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🎓</text></svg>\">"
            "<style>%s</style></head><body><div class=wrap>"
            "<div class=top><h1>&#9650; wazuh-soc-training</h1>"
            "<span class=badge>SOC analyst drills</span>"
            "<span class='badge' style='margin-left:auto'>live Wazuh</span></div>"
            "%s</div></body></html>") % (html.escape(title), CSS, body)


def e(s):
    return html.escape(str(s))


# ---------------------------------------------------------------- views

_LEVEL_BLURB = {
    "beginner": "Single, clear attack. Good for learning the triage workflow.",
    "intermediate": "One attacker, several techniques — classify and scope it.",
    "advanced": "Multiple sources / stages. Correlate, prioritise, respond.",
}


def view_home():
    b = ["<form method=get action=/scenario>",
         "<div class=pan><label class=mut>Your name / callsign</label>"
         "<input type=text name=trainee placeholder='e.g. analyst-1' required "
         "style='margin-top:6px'></div>",
         "<h2>Start a drill</h2>",
         "<p class=mut>Pick a difficulty. You get a random, unlabelled incident at "
         "that level — the attack type is <b>not</b> revealed up front. A real, "
         "randomised attack is injected into the live Wazuh manager; triage it in "
         "the dashboard, then classify it below. Every run draws fresh source IPs "
         "and target hosts, so the answers change each time.</p>",
         "<div class=pan>"]
    for lvl in (LEVELS or ["beginner"]):
        b.append(
            "<button class=card style='width:100%%;text-align:left;cursor:pointer' "
            "name=difficulty value='%s'>"
            "<b style='text-transform:capitalize'>%s</b>"
            "<span class='diff %s'>%s</span><br>"
            "<span class=mut>%s</span></button>" % (
                e(lvl), e(lvl), e(lvl), e(lvl), e(_LEVEL_BLURB.get(lvl, ""))))
    if len(LEVELS) > 1:
        b.append(
            "<button class=card style='width:100%%;text-align:left;cursor:pointer' "
            "name=difficulty value='any'><b>Surprise me</b>"
            "<span class=diff style='background:#1b2b3a;color:var(--cy)'>any</span><br>"
            "<span class=mut>Random incident at any difficulty.</span></button>")
    b.append("</div></form>")
    lb = scoring.leaderboard(10)
    if lb:
        b.append("<h2>Leaderboard</h2><div class=pan><table>"
                 "<tr><th>Analyst</th><th>Drills</th><th>Avg</th><th>Best</th></tr>")
        for r in lb:
            b.append("<tr><td>%s</td><td>%s</td><td>%s%%</td><td>%s%%</td></tr>" % (
                e(r["trainee"]), r["attempts"], r["avg_pct"], r["best_pct"]))
        b.append("</table></div>")
    return page("wazuh-soc-training", "".join(b))


def _incident_code(run_id):
    # neutral, stable-looking case number derived from the run id (no attack hint)
    n = abs(hash(run_id)) % 9000 + 1000
    return "INC-%d" % n


def view_scenario(sc, trainee, run_id):
    dash = config.DASHBOARD_URL
    b = ["<p><a href=/>&larr; back</a></p>",
         "<h2>Live incident %s<span class='diff %s'>%s</span></h2>" % (
             e(_incident_code(run_id)), e(sc["difficulty"]), e(sc["difficulty"])),
         "<div class=warnbox>&#9889; Drill launched — randomised attack traffic is now "
         "being injected into the live Wazuh manager. The attack type is not given: "
         "triage it in the dashboard and classify it yourself. "
         "Run id: <span class=mono>%s</span></div>" % e(run_id),
         "<div class=pan><b>Briefing.</b> %s</div>" % e(sc.get("briefing", "")),
         "<div class=pan><b>Where to look.</b> %s<br><br>"
         "<a class=btn href='%s' target=_blank rel=noopener>Open Wazuh dashboard &#8599;</a>"
         "</div>" % (e(sc.get("dashboard_hint", "")), e(dash)),
         "<h3>Triage report</h3>",
         "<form method=post action=/submit>",
         "<input type=hidden name=trainee value='%s'>" % e(trainee),
         "<input type=hidden name=sid value='%s'>" % e(sc["id"]),
         "<input type=hidden name=run_id value='%s'>" % e(run_id)]
    for q in sc.get("questions", []):
        b.append("<div class=q><b>%s</b>" % e(q["prompt"]))
        qt = q["type"]
        qid = e(q["id"])
        if qt == "choice":
            for opt in q.get("options", []):
                b.append("<label class=opt><input type=radio name='q_%s' value='%s' required> %s</label>" % (
                    qid, e(opt), e(opt)))
        elif qt == "multi":
            for opt in q.get("options", []):
                b.append("<label class=opt><input type=checkbox name='q_%s' value='%s'> %s</label>" % (
                    qid, e(opt), e(opt)))
        elif qt in ("ipset", "text"):
            ph = "comma-separated IPs" if qt == "ipset" else "your answer"
            b.append("<input type=text name='q_%s' placeholder='%s'>" % (qid, ph))
        b.append("</div>")
    b.append("<button class='btn g' type=submit>Submit triage report</button></form>")
    # neutral page <title> too — never reveal the attack name in the blind view
    return page("Live incident %s" % _incident_code(run_id), "".join(b))


def _cls(frac):
    return "res-ok" if frac >= 0.999 else ("res-part" if frac > 0 else "res-bad")


def view_result(sc, trainee, graded):
    gt = sc.get("ground_truth", {})
    reveal = e(sc["title"])
    atk = gt.get("attack_type")
    if atk:
        reveal += " &middot; <span class=mut>%s</span>" % e(atk)
    b = ["<p><a href=/>&larr; back</a></p>",
         "<h2>Debrief</h2>",
         "<div class=pan><span class=mut>This incident was:</span> <b>%s</b></div>" % reveal,
         "<div class=pan><h1 style='margin:0'>%s%%</h1>"
         "<div class=bar><i style='width:%s%%'></i></div>"
         "<p class=mut>%s / %s points · analyst %s</p></div>" % (
             graded["pct"], graded["pct"], graded["score"], graded["max_score"], e(trainee))]
    for r in graded["results"]:
        frac = r["got"] / r["weight"] if r["weight"] else 0
        given = r["given"]
        given_disp = ", ".join(given) if isinstance(given, list) else (given or "(blank)")
        b.append(
            "<div class=q><b>%s</b> <span class='right %s'>%s / %s</span><br>"
            "<span class=mut>Your answer:</span> %s<br>"
            "<span class=mut>Correct:</span> <span class=res-ok>%s</span><br>"
            "<span class=mut>%s</span></div>" % (
                e(r["prompt"]), _cls(frac), r["got"], r["weight"],
                e(given_disp), e(r["correct"]), e(r["explain"])))
    b.append("<a class=btn href='/scenario?difficulty=%s&trainee=%s'>"
             "Another %s drill</a> "
             "<a href=/ style='margin-left:8px'>Change level</a>" % (
                 e(sc.get("difficulty", "any")), urllib.parse.quote(trainee),
                 e(sc.get("difficulty", ""))))
    return page("Debrief", "".join(b))


# ---------------------------------------------------------------- server

SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        if u.path == "/healthz":
            return self._send(200, '{"ok":true}', "application/json")
        if u.path == "/":
            return self._send(200, view_home())
        if u.path == "/scenario":
            trainee = (qs.get("trainee") or [""])[0].strip()[:40]
            if not trainee:
                return self._redirect("/")
            sid = (qs.get("id") or [""])[0]
            difficulty = (qs.get("difficulty") or [""])[0].strip().lower()
            # blind: normally pick a random scenario at the chosen level; an
            # explicit id is still honoured (instructor / direct link).
            template = SCENARIOS.get(sid) if sid else pick_scenario(difficulty)
            if not template:
                return self._redirect("/")
            sc = randomizer.materialize(template, config.AGENTS, config.AGENT_OS)
            run_id = injector.launch(sc, config.AGENTS)
            _store_run(run_id, sc)
            return self._send(200, view_scenario(sc, trainee, run_id))
        if u.path == "/run":
            rid = (qs.get("id") or [""])[0]
            return self._send(200, json.dumps(injector.run_state(rid)), "application/json")
        if u.path == "/api/scenarios":
            return self._send(200, json.dumps(list(SCENARIOS.keys())), "application/json")
        return self._redirect("/")

    def do_POST(self):
        if self.path != "/submit":
            return self._redirect("/")
        ln = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(ln).decode())
        sid = (form.get("sid") or [""])[0]
        trainee = (form.get("trainee") or [""])[0].strip()[:40]
        run_id = (form.get("run_id") or [""])[0]
        # grade against the exact randomised instance that was injected; fall
        # back to the static template if the run is unknown (e.g. after restart).
        sc = _get_run(run_id) or SCENARIOS.get(sid)
        if not sc or not trainee:
            return self._redirect("/")
        answers = {}
        for q in sc.get("questions", []):
            key = "q_" + q["id"]
            if q["type"] == "multi":
                answers[q["id"]] = form.get(key, [])
            else:
                answers[q["id"]] = (form.get(key) or [""])[0]
        graded = scoring.grade(sc, answers)
        scoring.record(trainee, sid, run_id, graded, json.dumps(graded["results"]))
        return self._send(200, view_result(sc, trainee, graded))

    def _redirect(self, to):
        self.send_response(303)
        self.send_header("Location", to)
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def log_message(self, *a):
        pass


def main():
    scoring.init_db()
    print("[wazuh-soc-training] %d scenarios loaded" % len(SCENARIOS))
    print("[wazuh-soc-training] queue socket: %s" % config.QUEUE_SOCKET)
    print("[wazuh-soc-training] http://%s:%d/" % (config.BIND, config.PORT))
    ThreadingHTTPServer((config.BIND, config.PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
