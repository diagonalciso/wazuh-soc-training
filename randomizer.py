"""Per-run scenario randomizer.

Every drill start "materializes" a scenario template into a concrete instance:
source IPs, target hosts and event volumes are drawn fresh, and the graded
answers/options are rewritten to match — so two runs of the same scenario never
share the same answer key and a trainee cannot memorise last time's IPs/host.

A template declares what to randomise under a `randomize` block and references
the drawn values as `$TOKENS` anywhere in the scenario (inject steps, question
answers, explanations, briefing):

    "randomize": {
        "ips":     {"SRC1": "bruteforce", "SRC2": "bruteforce"},
        "targets": {"TARGET": {"question": "target"}}
    }

  * ips     -- token -> named IP pool; each token gets a distinct IP.
  * targets -- token -> {"question": <choice-question-id>}; each token gets a
               distinct host drawn from the live fleet. The named choice
               question's options are rebuilt as the drawn host + 3 random
               decoy hosts (shuffled), and its answer set to the drawn host.

Step `count` may be an int or an `[min, max]` range (drawn per run).

Grading constants (attack class, MITRE id, severity) are intentionally NOT
randomised — they are the learning objective and stay fixed per template.
"""
import copy
import random
import re

# Themed pools of plausible external source IPs. Kept deliberately varied so
# repeated runs look different; none are live targets — just realistic strings.
IP_POOLS = {
    "bruteforce": [
        "45.155.205.233", "193.32.162.40", "218.92.0.112", "61.177.173.50",
        "141.98.10.65", "185.220.101.42", "222.186.30.112", "89.248.165.74",
        "92.63.197.153", "195.178.120.14", "103.145.13.209", "80.94.95.115",
        "104.248.45.67", "159.203.201.98", "43.155.130.11", "170.64.148.30",
    ],
    "webattack": [
        "103.97.176.11", "185.191.171.35", "45.9.148.3", "162.243.145.2",
        "51.158.108.135", "193.106.191.20", "20.171.207.130", "134.209.82.19",
        "178.62.15.44", "68.183.44.21", "146.190.62.100", "84.17.35.180",
    ],
    "scanner": [
        "71.6.199.23", "198.20.69.74", "66.240.205.34", "184.105.247.195",
        "185.142.236.35", "162.142.125.12", "167.94.138.44", "206.168.34.9",
    ],
}

_TOKEN = re.compile(r"\$([A-Z][A-Z0-9_]*)")


def _sub(obj, mapping):
    """Recursively replace $TOKEN occurrences in every string of obj."""
    if isinstance(obj, str):
        return _TOKEN.sub(lambda m: mapping.get(m.group(1), m.group(0)), obj)
    if isinstance(obj, list):
        return [_sub(x, mapping) for x in obj]
    if isinstance(obj, dict):
        return {k: _sub(v, mapping) for k, v in obj.items()}
    return obj


def _pick_distinct(pool, n, exclude):
    choices = [x for x in pool if x not in exclude]
    random.shuffle(choices)
    if len(choices) < n:                       # pool too small; allow reuse
        choices = list(pool)
        random.shuffle(choices)
    return choices[:n]


def materialize(template, agents):
    """Return a concrete scenario dict for one run (template is left untouched).

    `agents` is the {name: id} fleet map used to draw target hosts + decoys.
    """
    sc = copy.deepcopy(template)
    rz = sc.get("randomize")
    if not rz:
        return sc

    mapping = {}
    used_ips = set()
    for token, pool_name in rz.get("ips", {}).items():
        pool = IP_POOLS.get(pool_name, IP_POOLS["bruteforce"])
        ip = _pick_distinct(pool, 1, used_ips)[0]
        used_ips.add(ip)
        mapping[token] = ip

    host_names = list(agents.keys()) or ["host01", "host02", "host03", "host04"]
    used_hosts = set()
    target_qs = {}                              # question_id -> chosen host
    for token, cfg in rz.get("targets", {}).items():
        host = _pick_distinct(host_names, 1, used_hosts)[0]
        used_hosts.add(host)
        mapping[token] = host
        qid = cfg.get("question")
        if qid:
            target_qs[qid] = host

    sc = _sub(sc, mapping)

    # resolve range counts on inject steps
    for st in sc.get("inject", {}).get("steps", []):
        c = st.get("count")
        if isinstance(c, list) and len(c) == 2:
            st["count"] = random.randint(int(c[0]), int(c[1]))

    # rebuild options for each target-bound choice question
    for q in sc.get("questions", []):
        if q.get("id") in target_qs:
            correct = target_qs[q["id"]]
            decoys = _pick_distinct([h for h in host_names if h != correct], 3, set())
            opts = [correct] + decoys
            random.shuffle(opts)
            q["options"] = opts
            q["answer"] = correct

    return sc
