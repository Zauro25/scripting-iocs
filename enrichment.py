import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import time

import requests

FIELDS = ["ioc", "type", "score", "verdict"]


def detect_type(value):
    try:
        ipaddress.IPv4Address(value)
        return "ip_addresses"
    except ValueError:
        pass

    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        return "files"

    normalized = value.lower()
    if len(normalized) <= 253 and not normalized.endswith("."):
        labels = normalized.split(".")
        if len(labels) >= 2 and all(
            label and len(label) <= 63 and label[0].isalnum()
            and label[-1].isalnum() and re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels
        ) and len(labels[-1]) >= 2:
            return "domains"

    return None


def mock_result(ioc, ioc_type):
    digest = hashlib.sha256(ioc.encode()).digest()
    malicious = digest[0] % 5 == 0
    suspicious = not malicious and digest[1] % 7 == 0
    return {
        "ioc": ioc,
        "type": ioc_type,
        "score": 100 if malicious else (25 if suspicious else 0),
        "verdict": "malicious" if malicious else ("suspicious" if suspicious else "clean"),
    }


def enrich(ioc, ioc_type, api_key, retries=2):
    if not api_key:
        return mock_result(ioc, ioc_type)

    url = f"https://www.virustotal.com/api/v3/{ioc_type}/{ioc}"
    headers = {"x-apikey": api_key}
    for attempt in range(retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 404:
                return {"ioc": ioc, "type": ioc_type, "score": None, "verdict": "unknown"}
            if response.status_code == 429 and attempt < retries:
                retry_after = response.headers.get("Retry-After", "2")
                time.sleep(min(float(retry_after), 30))
                continue
            response.raise_for_status()
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            return {
                "ioc": ioc,
                "type": ioc_type,
                "score": round(malicious / total * 100, 2) if total else None,
                "verdict": "malicious" if malicious else ("suspicious" if suspicious else "clean"),
            }
        except (requests.RequestException, ValueError, KeyError) as error:
            if attempt == retries:
                print(f"API error untuk {ioc}: {error}")
                return {"ioc": ioc, "type": ioc_type, "score": None, "verdict": "unknown"}
            time.sleep(2 ** attempt)


def main():
    parser = argparse.ArgumentParser(description="Enrich IP, domain, and file hash IOCs with VirusTotal.")
    parser.add_argument("--input", default="iocs.txt")
    parser.add_argument("--json", default="results.json")
    parser.add_argument("--csv", dest="csv_path", default="results.csv")
    parser.add_argument("--mock", action="store_true", help="Use deterministic local results without an API call.")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as input_file:
        iocs = list(dict.fromkeys(line.strip() for line in input_file if line.strip()))

    results = []
    api_key = os.getenv("VT_API_KEY")
    if not args.mock and not api_key:
        parser.error("VT_API_KEY belum diatur. Set API key atau gunakan --mock.")
    if args.mock:
        api_key = None
    for ioc in iocs:
        ioc_type = detect_type(ioc)
        if not ioc_type:
            print("IOC tidak valid:", ioc)
            continue
        results.append(enrich(ioc, ioc_type, api_key))

    with open(args.json, "w", encoding="utf-8") as output_file:
        json.dump(results, output_file, indent=2)
    with open(args.csv_path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(results)
    print(f"Enrichment selesai: {len(results)} IOC valid.")


if __name__ == "__main__":
    main()