# Asset Inventory

Lab environment: Wazuh 4.14.6 manager plus two monitored endpoints, all on the 192.168.64.0/24 lab network behind OPNsense. Criticality is assigned from the asset's role and exposure, not from the number of vulnerabilities found on it.

| Endpoint | IP | OS | Wazuh agent | Role in the business | Exposure | Criticality |
|---|---|---|---|---|---|---|
| linux-endpoint | 192.168.64.6 | Ubuntu 22.04.5 LTS (arm64), kernel 5.15.0-191 | 001 | Log collector and admin jump host. Headless server used to forward logs and for SSH administration of the environment. | Internal only. SSH reachable on the LAN, no user-driven activity (no browser, no email). | **Medium** |
| windows-endpoint | 192.168.64.7 | Windows 11 Pro 10.0.26200 (arm64) | 002 | Analyst workstation. Used daily by a person for email, browsing, downloads and admin tooling. | Internal, but user-driven: this is where phishing attachments, malicious links and untrusted installers arrive. | **High** |

## Why these ratings

- **windows-endpoint is High** because it is operated by a human. Most initial access in real incidents lands on a workstation through the user, so a vulnerable application there is reachable by an attacker without any network foothold.
- **linux-endpoint is Medium** because it is headless and LAN-only. A vulnerability on it needs an attacker who is already inside the network, or an exposed service, to be reachable. It is still important because it holds log data and has admin SSH access.
- Neither asset is internet-facing, so nothing here is rated Critical. In a production estate a domain controller or a public web server would sit above both of these.

## Baseline findings at scan time (Wazuh Vulnerability Detection, 17 Sep 2026)

| Endpoint | Total findings | Critical | High | Medium | Low | Unscored | In CISA KEV |
|---|---|---|---|---|---|---|---|
| linux-endpoint | 6,407 | 371 | 2,207 | 2,383 | 41 | 1,405 | 0 |
| windows-endpoint | 0 (fully patched, minimal software footprint) | 0 | 0 | 0 | 0 | 0 | 0 |

Note: 6,368 of the Linux findings sit in two kernel packages (`linux-image-5.15.0-187-generic`, installed but not running, and `linux-image-5.15.0-191-generic`, the running kernel). Outside the kernel, only two individual High findings remain: CVE-2026-15308 (python3.10) and CVE-2025-54289 (glibc).
