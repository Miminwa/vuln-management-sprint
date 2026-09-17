# Vulnerability Management Sprint

One-week SOC analyst project (compressed into two days) using Wazuh 4.14.6 Vulnerability Detection against the Project 1 homelab: an Ubuntu 22.04 server and a Windows 11 Pro workstation.

**Result:** 6,420 findings reduced to 3,182 (50%) with four remediations, 100% of P1 resolved, Windows endpoint at zero. Remaining findings sit in the running Ubuntu kernel, which has no available patch, and are documented as accepted risk.

## Deliverables

| File | What it is |
|---|---|
| `report/Remediation_Report.docx` | 2-page remediation report |
| `slides/Lightning_Presentation.pptx` | 5-minute lightning talk (6 slides, speaker notes included) |
| `data/prioritization_worksheet.xlsx` | CVSS + KEV + asset-criticality scoring, formula-driven P1/P2/P3 tiers |
| `data/asset_inventory.md` | Endpoint roles, exposure and criticality ratings |
| `data/ubuntu_export.csv`, `data/windows_export.csv` | Raw Wazuh inventory exports |
| `data/*_high_critical.csv`, `data/*_kev_matches.csv`, `data/*_summary.txt` | Script outputs |
| `scripts/kev_crossref.py` | Cross-references a Wazuh export against CISA KEV and enriches with NVD CVSS |
| `screenshots/` | Evidence, numbered in the order the work was done |

## Method

1. **Enable**: verified Vulnerability Detection is on by default in 4.14 (`enabled: yes`, `index-status: yes`, CTI feed, 60m updates). Confirmed syscollector package inventory on both agents; added `<hotfixes>yes</hotfixes>` explicitly on Windows.
2. **Discover**: exported the full inventory per endpoint from the dashboard. Windows was fully patched at baseline (0 findings), so Notepad++ 7.8.9 was installed deliberately to exercise the Windows detection path.
3. **Triage**: `kev_crossref.py` downloads the CISA KEV catalog, joins on CVE ID, groups kernel packages (one fix per package) and pulls CVSS v3.1 from NVD for the High/Critical shortlist.
4. **Prioritize**: P1 = in KEV on a High/Medium asset or CVSS 9+ on a High asset; P2 = CVSS 7+ on a non-Low asset; P3 = the rest.
5. **Remediate**: upgrade Notepad++ to 8.9.8 (P1), remove unused kernel 5.15.0-187, patch python3.10, remove unused LXD. Re-scan by restarting the agents.

## Reproduce the analysis

```bash
python3 scripts/kev_crossref.py data/ubuntu_export.csv
```

Edit `GROUPED_KERNELS` in the script to match `dpkg -l | grep linux-image` and `uname -r` on your host.

## Notes and limitations

- The running kernel (5.15.0-191) is already the newest build Ubuntu ships for 22.04, so its 1,284 High/Critical CVEs are either backported already or unfixed upstream. They are not actionable by patching.
- Wazuh's severity label and NVD's CVSS can disagree (CVE-2023-6401: Wazuh High, NVD 5.3). Tiering uses the NVD number.
- Agent-based detection only sees installed packages; it cannot find exposed services or configuration weaknesses. An active scanner (Greenbone/OpenVAS) is the natural complement.
