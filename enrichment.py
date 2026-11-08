import os
import re
import csv
import json
import time
import ipaddress
import requests

API_KEY = os.getenv("VT_API_KEY")
results = []

if not API_KEY:
    print("VT_API_KEY belum diatur.")
    exit()

with open("iocs.txt") as f:
    iocs = set(line.strip() for line in f if line.strip())

for ioc in iocs:
    # Validasi tipe IOC
    try:
        ipaddress.IPv4Address(ioc)
        ioc_type = "ip_addresses"
    except ValueError:
        if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
            ioc_type = "files"
        elif re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
            ioc_type = "files"
        elif re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
            ioc_type = "files"
        elif re.fullmatch(
            r"(?=.{1,253}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}", ioc
        ):
            ioc_type = "domains"
        else:
            print("IOC tidak valid:", ioc)
            continue

    url = f"https://www.virustotal.com/api/v3/{ioc_type}/{ioc}"

    try:
        response = requests.get(
            url,
            headers={"x-apikey": API_KEY},
            timeout=15
        )

        if response.status_code == 429:
            print("Rate limit. Coba lagi nanti:", ioc)
            continue

        if response.status_code == 404:
            results.append({
                "ioc": ioc,
                "type": ioc_type,
                "score": None,
                "verdict": "unknown"
            })
            continue

        response.raise_for_status()

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        score = round(malicious / total * 100, 2) if total else None

        if malicious:
            verdict = "malicious"
        elif suspicious:
            verdict = "suspicious"
        else:
            verdict = "clean"

        results.append({
            "ioc": ioc,
            "type": ioc_type,
            "score": score,
            "verdict": verdict
        })

    except requests.RequestException as e:
        print("API error:", e)
        results.append({
            "ioc": ioc,
            "type": ioc_type,
            "score": None,
            "verdict": "unknown"
        })

    time.sleep(16)

with open("results.json", "w") as f:
    json.dump(results, f, indent=4)

with open("results.csv", "w", newline="") as f:
    writer = csv.DictWriter(
        f, fieldnames=["ioc", "type", "score", "verdict"]
    )
    writer.writeheader()
    writer.writerows(results)

print("Enrichment selesai.")