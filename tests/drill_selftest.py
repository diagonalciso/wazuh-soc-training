#!/usr/bin/env python3
"""All-levels drill self-test (module-level).

Runs ON the Wazuh manager as root. For every scenario: materialise (per-run
randomised) -> fast-inject into the live manager queue socket -> grade the
materialised key with (a) fully-correct answers (expect 100%) and (b) one wrong
choice (expect a penalty) -> record to the live training.db. Verifies
randomizer + injector + scoring + persistence without going through HTTP.

Env:
  WSOC_INSTALL   repo/install dir to import from + read scenarios (default: the
                 parent of this tests/ dir; set to /opt/wazuh-soc-training to
                 exercise the deployed copy + its training.db).
Plus the usual service env (QUEUE_SOCKET, TRAIN_DB, TRAIN_AGENTS, ...) --
source /etc/wazuh-soc-training.env before running.
"""
import os, sys, json, glob, time, random

INSTALL = os.environ.get(
    "WSOC_INSTALL",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, INSTALL)
import config, randomizer, injector, scoring  # noqa: E402

scoring.init_db()
SC_DIR = os.path.join(INSTALL, "scenarios")


def load_scenarios():
    out = []
    for p in sorted(glob.glob(os.path.join(SC_DIR, "*.json"))):
        with open(p) as f:
            out.append((os.path.basename(p), json.load(f)))
    return out


def fast_inject(sc, agents):
    inj = injector.Injector()
    n = 0
    for st in sc.get("inject", {}).get("steps", []):
        agent_name = st.get("agent") or list(agents)[0]
        agent_id = agents.get(agent_name, "000")
        ips = [i for i in (st.get("srcips") or [st.get("srcip")]) if i]
        count = int(st.get("count", 1))
        for _ in range(count):
            ip = random.choice(ips) if ips else "10.10.0.9"
            location, raw = injector._line(st["template"], ip, st, agent_name)
            inj.send(agent_id, agent_name, location, raw)
            n += 1
    return n


def correct_answers(sc):
    ans = {}
    for q in sc["questions"]:
        a, t = q.get("answer"), q["type"]
        if t == "ipset":
            ans[q["id"]] = ", ".join(a)
        elif t == "multi":
            ans[q["id"]] = list(a)
        elif t == "text":
            ans[q["id"]] = a[0] if isinstance(a, list) else a
        else:
            ans[q["id"]] = a
    return ans


def wrong_answers(sc):
    ans = correct_answers(sc)
    for q in sc["questions"]:
        if q["type"] == "choice" and len(q.get("options", [])) > 1:
            for opt in q["options"]:
                if opt != q["answer"]:
                    ans[q["id"]] = opt
                    break
            break
    return ans


def main():
    scenarios = load_scenarios()
    order = {"beginner": 0, "intermediate": 1, "advanced": 2}
    scenarios.sort(key=lambda x: (order.get(x[1].get("difficulty"), 9), x[0]))
    fails, rows = [], []
    for fname, tmpl in scenarios:
        diff = tmpl.get("difficulty", "?")
        sc = randomizer.materialize(tmpl, config.AGENTS, config.AGENT_OS)
        leftover = "$" in json.dumps(sc)
        target = "?"
        for q in sc["questions"]:
            if q["id"] == "target":
                target = q["answer"]
        os_fam = config.AGENT_OS.get(target, "?")
        nsent = fast_inject(sc, config.AGENTS)
        run_id = "selftest-%s-%d" % (sc["id"], int(time.time() * 1000) % 100000)
        g_ok = scoring.grade(sc, correct_answers(sc))
        g_bad = scoring.grade(sc, wrong_answers(sc))
        scoring.record("selftest", sc["id"], run_id, g_ok, json.dumps(g_ok["results"]))
        scoring.record("selftest-partial", sc["id"], run_id + "-p", g_bad, "")
        ok = (g_ok["pct"] == 100.0) and (g_bad["pct"] < 100.0) and not leftover
        if not ok:
            fails.append(fname)
        rows.append(("PASS" if ok else "FAIL", diff, fname, target, os_fam,
                     nsent, g_ok["pct"], g_bad["pct"], leftover))
        time.sleep(0.3)
    print("\n%-4s %-12s %-34s %-8s %-15s %4s %6s %6s %s" %
          ("RES", "LEVEL", "SCENARIO", "TARGET", "OS", "EVT", "OK%", "BAD%", "LEFT$"))
    print("-" * 110)
    for r in rows:
        print("%-4s %-12s %-34s %-8s %-15s %4d %6.1f %6.1f %s" % r)
    print("-" * 110)
    print("scenarios=%d  PASS=%d  FAIL=%d" % (len(rows), len(rows) - len(fails), len(fails)))
    if fails:
        print("FAILED:", ", ".join(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
