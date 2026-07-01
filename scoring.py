"""Answer grading + progress persistence (SQLite, stdlib).

Grading is deterministic and offline — trainee answers are compared to the
scenario's ground_truth. Question types:

  choice   exact match (case-insensitive)
  multi    set overlap: score = |correct ∩ given| / |correct| minus wrong picks
  ipset    set of source IPs; order-free; partial credit; penalize extras
  text     normalized substring / token match against accepted answers
"""
import sqlite3
import threading
import time
import re

import config

_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(config.DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock, _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS attempts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            trainee     TEXT NOT NULL,
            scenario    TEXT NOT NULL,
            run_id      TEXT,
            score       REAL NOT NULL,
            max_score   REAL NOT NULL,
            pct         REAL NOT NULL,
            detail_json TEXT,
            ts          REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_attempts_trainee ON attempts(trainee);
        CREATE INDEX IF NOT EXISTS idx_attempts_scenario ON attempts(scenario);
        """)


def _norm(s):
    return re.sub(r"[^a-z0-9.]+", " ", str(s).lower()).strip()


def _tokens(s):
    return set(t for t in _norm(s).split() if t)


def grade_question(q, given):
    """Return (score_0_1, correct_display, explanation)."""
    qtype = q["type"]
    correct = q.get("answer")
    if qtype == "choice":
        ok = _norm(given) == _norm(correct)
        return (1.0 if ok else 0.0, correct, q.get("explain", ""))
    if qtype == "multi":
        cset = set(_norm(x) for x in correct)
        gset = set(_norm(x) for x in (given or []))
        if not cset:
            return (0.0, ", ".join(correct), q.get("explain", ""))
        hit = len(cset & gset)
        wrong = len(gset - cset)
        raw = (hit - wrong) / len(cset)
        return (max(0.0, min(1.0, raw)), ", ".join(correct), q.get("explain", ""))
    if qtype == "ipset":
        cset = set(_norm(x) for x in correct)
        gset = set(_norm(x) for x in re.split(r"[\s,;]+", given or "") if x)
        if not cset:
            return (0.0, ", ".join(correct), q.get("explain", ""))
        hit = len(cset & gset)
        wrong = len(gset - cset)
        raw = (hit - wrong) / len(cset)
        return (max(0.0, min(1.0, raw)), ", ".join(correct), q.get("explain", ""))
    if qtype == "text":
        accepted = correct if isinstance(correct, list) else [correct]
        gt = _tokens(given)
        best = 0.0
        for a in accepted:
            at = _tokens(a)
            if at and at <= gt:
                best = 1.0
                break
            if at:
                best = max(best, len(at & gt) / len(at))
        return (best, " / ".join(accepted), q.get("explain", ""))
    return (0.0, str(correct), "")


def grade(scenario, answers):
    """answers: {question_id: given}. Returns dict with per-q + totals."""
    results = []
    score = 0.0
    maxs = 0.0
    for q in scenario.get("questions", []):
        w = float(q.get("weight", 1))
        given = answers.get(q["id"])
        s01, correct_disp, explain = grade_question(q, given)
        score += s01 * w
        maxs += w
        results.append({
            "id": q["id"], "prompt": q["prompt"], "given": given,
            "correct": correct_disp, "got": round(s01 * w, 2), "weight": w,
            "explain": explain,
        })
    pct = round(100.0 * score / maxs, 1) if maxs else 0.0
    return {"score": round(score, 2), "max_score": maxs, "pct": pct, "results": results}


def record(trainee, scenario_id, run_id, graded, detail_json=""):
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO attempts(trainee,scenario,run_id,score,max_score,pct,detail_json,ts)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (trainee, scenario_id, run_id, graded["score"], graded["max_score"],
             graded["pct"], detail_json, time.time()))


def leaderboard(limit=50):
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT trainee, COUNT(*) attempts, ROUND(AVG(pct),1) avg_pct,"
            " ROUND(MAX(pct),1) best_pct, MAX(ts) last_ts"
            " FROM attempts GROUP BY trainee ORDER BY avg_pct DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def history(trainee, limit=100):
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT scenario, pct, score, max_score, ts FROM attempts"
            " WHERE trainee=? ORDER BY ts DESC LIMIT ?", (trainee, limit)).fetchall()
        return [dict(r) for r in rows]
