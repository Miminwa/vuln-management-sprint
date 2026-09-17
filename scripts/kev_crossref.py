#!/usr/bin/env python3
"""
kev_crossref.py
Cross-reference a Wazuh Vulnerability Detection CSV export against the
CISA Known Exploited Vulnerabilities (KEV) catalog, then enrich the
High/Critical shortlist with CVSS v3 base scores from NVD.

Usage:
    python3 kev_crossref.py wazuh_export.csv

Outputs (written next to the script):
    kev_matches.csv        every finding whose CVE is in CISA KEV
    high_critical.csv      every High/Critical finding, deduplicated per CVE,
                           with KEV flag and CVSS base score
    summary.txt            counts you can paste straight into the report
"""

import csv
import json
import sys
import time
import urllib.request
from collections import Counter, OrderedDict

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"

# Kernel packages are grouped rather than scored one CVE at a time, because
# every CVE in a kernel package shares a single fix (remove the package, or
# upgrade the kernel). Edit these to match your `dpkg -l | grep linux-image`
# and `uname -r` output.
GROUPED_KERNELS = {
    "linux-image-5.15.0-187-generic": "unused kernel (installed, not running): remove package",
    "linux-image-5.15.0-191-generic": "running kernel: upgrade via apt",
}


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "kev-crossref/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def load_kev():
    print("Downloading CISA KEV catalog ...")
    data = fetch_json(KEV_URL)
    kev = {}
    for v in data["vulnerabilities"]:
        kev[v["cveID"]] = {
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", ""),
        }
    print(f"  KEV catalog loaded: {len(kev)} CVEs")
    return kev


def nvd_cvss(cve_id):
    """Return (base_score, vector) from NVD, or ('', '') if unavailable."""
    try:
        data = fetch_json(NVD_URL.format(cve_id))
        items = data.get("vulnerabilities", [])
        if not items:
            return "", ""
        metrics = items[0]["cve"].get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
            if key in metrics:
                m = metrics[key][0]["cvssData"]
                return m.get("baseScore", ""), m.get("vectorString", "")
    except Exception as exc:  # network hiccup, rate limit, etc.
        print(f"  NVD lookup failed for {cve_id}: {exc}")
    return "", ""


def main(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    print(f"Loaded {len(rows)} findings from {path}")

    kev = load_kev()

    # 1. KEV matches (all severities)
    kev_rows = []
    for r in rows:
        cve = r["vulnerability.id"]
        if cve in kev:
            out = OrderedDict(r)
            out.update({f"kev_{k}": v for k, v in kev[cve].items()})
            kev_rows.append(out)
    with open("kev_matches.csv", "w", newline="", encoding="utf-8") as fh:
        if kev_rows:
            w = csv.DictWriter(fh, fieldnames=list(kev_rows[0].keys()))
            w.writeheader()
            w.writerows(kev_rows)
        else:
            fh.write("no KEV matches\n")
    print(f"KEV matches: {len(kev_rows)} findings, "
          f"{len({r['vulnerability.id'] for r in kev_rows})} unique CVEs")

    # 2. High/Critical shortlist, one row per CVE (packages merged)
    shortlist = OrderedDict()
    grouped_kernel = Counter()
    for r in rows:
        if r["vulnerability.severity"] not in ("High", "Critical"):
            continue
        pkg = r["package.name"]
        if pkg in GROUPED_KERNELS:
            grouped_kernel[pkg] += 1
            continue
        cve = r["vulnerability.id"]
        if cve not in shortlist:
            shortlist[cve] = {
                "cve": cve,
                "severity": r["vulnerability.severity"],
                "agent": r["agent.name"],
                "packages": set(),
                "version": r["package.version"],
                "description": r["vulnerability.description"][:160],
                "in_kev": "YES" if cve in kev else "no",
            }
        shortlist[cve]["packages"].add(pkg)

    print(f"High/Critical shortlist: {len(shortlist)} unique CVEs "
          f"(excluding {sum(grouped_kernel.values())} grouped kernel findings)")

    # 3. CVSS enrichment from NVD for the shortlist only.
    #    NVD allows ~5 requests per 30 s without an API key, so we pause.
    print("Fetching CVSS scores from NVD (this takes a few minutes) ...")
    for i, (cve, item) in enumerate(shortlist.items(), 1):
        score, vector = nvd_cvss(cve)
        item["cvss_base"] = score
        item["cvss_vector"] = vector
        print(f"  [{i}/{len(shortlist)}] {cve} -> {score}")
        time.sleep(6.5)

    fields = ["cve", "severity", "cvss_base", "in_kev", "agent", "packages",
              "version", "cvss_vector", "description",
              "asset_criticality", "priority_tier", "justification"]
    with open("high_critical.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for item in shortlist.values():
            row = dict(item)
            row["packages"] = "; ".join(sorted(item["packages"]))
            row["asset_criticality"] = ""
            row["priority_tier"] = ""
            row["justification"] = ""
            w.writerow(row)
        # one grouped row per kernel package
        for pkg, n in grouped_kernel.items():
            kev_hits = sum(1 for r in rows if r["package.name"] == pkg
                           and r["vulnerability.id"] in kev)
            w.writerow({
                "cve": f"GROUP: {n} High/Critical CVEs",
                "severity": "Critical",
                "cvss_base": "up to 10.0",
                "in_kev": "YES" if kev_hits else "no",
                "agent": rows[0]["agent.name"],
                "packages": pkg,
                "version": next(r["package.version"] for r in rows
                                if r["package.name"] == pkg),
                "cvss_vector": "",
                "description": GROUPED_KERNELS[pkg],
                "asset_criticality": "",
                "priority_tier": "",
                "justification": "",
            })

    # 4. Summary for the report
    sev = Counter(r["vulnerability.severity"] for r in rows)
    pkgs = Counter(r["package.name"] for r in rows).most_common(5)
    with open("summary.txt", "w", encoding="utf-8") as fh:
        fh.write(f"Source file: {path}\n")
        fh.write(f"Total findings: {len(rows)}\n")
        fh.write(f"Unique CVEs: {len({r['vulnerability.id'] for r in rows})}\n")
        fh.write("By severity:\n")
        for k in ("Critical", "High", "Medium", "Low", "-"):
            fh.write(f"  {k:9s} {sev.get(k, 0)}\n")
        fh.write("Top packages:\n")
        for p, n in pkgs:
            fh.write(f"  {p}: {n}\n")
        fh.write(f"KEV matches: {len(kev_rows)} findings\n")
        fh.write(f"High/Critical unique CVEs outside unused kernels: {len(shortlist)}\n")
        for p, n in grouped_kernel.items():
            fh.write(f"High/Critical grouped on {p}: {n} ({GROUPED_KERNELS[p]})\n")
    print("Done. Wrote kev_matches.csv, high_critical.csv, summary.txt")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
