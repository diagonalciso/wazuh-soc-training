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
    # External C2 / exfil endpoints for Sysmon network beacons.
    "c2": [
        "185.220.101.42", "45.9.148.3", "193.106.191.20", "5.188.206.18",
        "91.219.236.166", "23.106.223.44", "146.70.199.11",
        "194.165.16.9", "212.192.246.30", "179.43.187.100",
    ],
}

# Windows account pools for AD-flavoured scenarios (kerberoast targets, rogue
# admins, spray victims). Distinct per token like the IP pools.
USER_POOL = ["administrator", "jsmith", "adunn", "mwallace", "kperry",
             "operator", "helpdesk", "sqladmin", "backup_adm", "rsmith",
             "tgordon", "lchen", "pnovak", "svc_task", "hr_admin"]
SVC_POOL = ["svc_sql", "svc_web", "MSSQLSvc", "svc_backup", "svc_share",
            "svc_ldap", "svc_report", "http_svc", "svc_jenkins", "svc_vc"]

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


def _os_family(os_key):
    """Collapse windows-server/-10/-11 -> 'windows'; anything else -> 'linux'."""
    return "windows" if str(os_key).startswith("windows") else "linux"


def materialize(template, agents, agent_os=None):
    """Return a concrete scenario dict for one run (template is left untouched).

    `agents` is the {name: id} fleet map used to draw target hosts + decoys.
    `agent_os` is an optional {name: os_key} map; when a target token declares
    an "os" filter (e.g. "windows"), only matching hosts are drawn — so a
    Kerberoasting drill lands on a Windows DC, not a Linux web box. Decoys for
    that question are drawn from the same OS family so they stay plausible.
    """
    agent_os = agent_os or {}
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

    # Windows usernames: token -> distinct account from USER_POOL.
    used_users = set()
    for token in rz.get("users", {}):
        u = _pick_distinct(USER_POOL, 1, used_users)[0]
        used_users.add(u)
        mapping[token] = u

    # Kerberos/service accounts: token -> distinct service name.
    used_svcs = set()
    for token in rz.get("services", {}):
        s = _pick_distinct(SVC_POOL, 1, used_svcs)[0]
        used_svcs.add(s)
        mapping[token] = s

    all_hosts = list(agents.keys()) or ["host01", "host02", "host03", "host04"]
    used_hosts = set()
    target_qs = {}                              # question_id -> (chosen host, os filter)
    for token, cfg in rz.get("targets", {}).items():
        want_os = cfg.get("os")                 # "windows" / "linux" / None
        if want_os:
            pool = [h for h in all_hosts if _os_family(agent_os.get(h)) == want_os]
        else:
            pool = all_hosts
        if not pool:                            # requested OS absent -> fall back
            pool = all_hosts
        host = _pick_distinct(pool, 1, used_hosts)[0]
        used_hosts.add(host)
        mapping[token] = host
        qid = cfg.get("question")
        if qid:
            target_qs[qid] = (host, want_os)

    sc = _sub(sc, mapping)

    # resolve range counts on inject steps
    for st in sc.get("inject", {}).get("steps", []):
        c = st.get("count")
        if isinstance(c, list) and len(c) == 2:
            st["count"] = random.randint(int(c[0]), int(c[1]))

    # rebuild options for each target-bound choice question
    for q in sc.get("questions", []):
        if q.get("id") in target_qs:
            correct, want_os = target_qs[q["id"]]
            if want_os:                          # decoys from the same OS family
                cand = [h for h in all_hosts
                        if h != correct and _os_family(agent_os.get(h)) == want_os]
            else:
                cand = [h for h in all_hosts if h != correct]
            if len(cand) < 3:                    # top up with any other host
                cand += [h for h in all_hosts if h != correct and h not in cand]
            decoys = _pick_distinct(cand, 3, set())
            opts = [correct] + decoys
            random.shuffle(opts)
            q["options"] = opts
            q["answer"] = correct

    return sc
