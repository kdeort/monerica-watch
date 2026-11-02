#!/usr/bin/env python3
"""
monerica-watch v0.1
Tracks status, KYC policy, and scam warning changes across Monerica.com's data.json API.
Zero external dependencies (Python 3 standard library only).
"""

import datetime
import html
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

DATA_URL = "https://monerica.com/data.json"
DATA_DIR = Path("data")
SNAPSHOT_FILE = DATA_DIR / "snapshot.json"
CHANGELOG_FILE = DATA_DIR / "changelog.json"
SUMMARY_FILE = DATA_DIR / "status_summary.json"
RSS_FILE = DATA_DIR / "feed.xml"
MAX_EVENTS = 200


def fetch_monerica_data() -> dict:
    req = urllib.request.Request(
        DATA_URL,
        headers={"User-Agent": "monerica-watch/0.1 (+https://github.com/)"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def has_tor(item: dict) -> bool:
    for link in item.get("otherLinks", []) or []:
        if link.get("label", "").lower() == "tor" or ".onion" in link.get("url", ""):
            return True
    return False


def build_summary(listings: list, generated_at: str) -> dict:
    summary = {
        "generated": generated_at,
        "total": len(listings),
        "verified": 0,
        "admitted": 0,
        "questionable": 0,
        "scam": 0,
        "no_kyc": 0,
        "tor_enabled": 0,
        "active_warnings": [],
    }
    for item in listings:
        status = item.get("status", "")
        if status == "Verified":
            summary["verified"] += 1
        elif status == "Admitted":
            summary["admitted"] += 1
        elif status == "Questionable":
            summary["questionable"] += 1
        elif status == "Scam":
            summary["scam"] += 1

        if item.get("kycPolicy") == "Guaranteed No KYC":
            summary["no_kyc"] += 1
        if has_tor(item):
            summary["tor_enabled"] += 1

        if status in ("Scam", "Questionable") or item.get("warning"):
            summary["active_warnings"].append({
                "name": item.get("name", "Unknown"),
                "slug": item.get("slug", ""),
                "profileUrl": item.get("profileUrl", "https://monerica.com"),
                "category": f"{item.get('category', '')} › {item.get('subcategory', '')}",
                "status": status,
                "kycPolicy": item.get("kycPolicy", "Not Stated"),
                "warning": item.get("warning", f"Marked as {status}"),
                "updated": item.get("updated", ""),
            })

    summary["active_warnings"].sort(key=lambda x: x.get("updated", ""), reverse=True)
    summary["active_warnings"] = summary["active_warnings"][:50]
    return summary


def diff_listings(old_map: dict, new_map: dict, now_iso: str) -> list:
    events = []
    for slug, curr in new_map.items():
        name = curr.get("name", slug)
        cat = f"{curr.get('category', '')} › {curr.get('subcategory', '')}"
        url = curr.get("profileUrl", "https://monerica.com")

        if slug not in old_map:
            events.append({
                "timestamp": now_iso,
                "type": "NEW_LISTING",
                "severity": "info" if curr.get("status") != "Scam" else "high",
                "name": name,
                "slug": slug,
                "category": cat,
                "profileUrl": url,
                "detail": f"Added to directory (Status: {curr.get('status', 'N/A')}, KYC: {curr.get('kycPolicy', 'Not Stated')})",
            })
            continue

        prev = old_map[slug]
        old_status = prev.get("status", "")
        new_status = curr.get("status", "")
        if old_status != new_status:
            sev = "high" if new_status in ("Scam", "Questionable") else "info"
            events.append({
                "timestamp": now_iso,
                "type": "STATUS_CHANGE",
                "severity": sev,
                "name": name,
                "slug": slug,
                "category": cat,
                "profileUrl": url,
                "detail": f"Status changed: {old_status or 'None'} → {new_status or 'None'}",
            })

        old_kyc = prev.get("kycPolicy", "Not Stated")
        new_kyc = curr.get("kycPolicy", "Not Stated")
        if old_kyc != new_kyc:
            sev = "high" if old_kyc == "Guaranteed No KYC" else "medium"
            events.append({
                "timestamp": now_iso,
                "type": "KYC_CHANGE",
                "severity": sev,
                "name": name,
                "slug": slug,
                "category": cat,
                "profileUrl": url,
                "detail": f"KYC policy changed: {old_kyc} → {new_kyc}",
            })

        old_warn = prev.get("warning", "")
        new_warn = curr.get("warning", "")
        if old_warn != new_warn and new_warn:
            events.append({
                "timestamp": now_iso,
                "type": "WARNING_ADDED",
                "severity": "high",
                "name": name,
                "slug": slug,
                "category": cat,
                "profileUrl": url,
                "detail": f"Warning added: {new_warn}",
            })

    for slug, prev in old_map.items():
        if slug not in new_map:
            events.append({
                "timestamp": now_iso,
                "type": "REMOVED_LISTING",
                "severity": "medium",
                "name": prev.get("name", slug),
                "slug": slug,
                "category": f"{prev.get('category', '')} › {prev.get('subcategory', '')}",
                "profileUrl": prev.get("profileUrl", "https://monerica.com"),
                "detail": f"Removed from directory (was {prev.get('status', 'N/A')})",
            })

    return events


def seed_initial_events(listings: list) -> list:
    sorted_items = sorted(
        listings,
        key=lambda x: (x.get("updated", ""), x.get("added", "")),
        reverse=True
    )[:30]
    events = []
    for item in sorted_items:
        status = item.get("status", "Admitted")
        sev = "high" if status in ("Scam", "Questionable") else "info"
        events.append({
            "timestamp": item.get("updated") or item.get("added") or "2026-11-01",
            "type": "INITIAL_SNAPSHOT",
            "severity": sev,
            "name": item.get("name", "Unknown"),
            "slug": item.get("slug", ""),
            "category": f"{item.get('category', '')} › {item.get('subcategory', '')}",
            "profileUrl": item.get("profileUrl", "https://monerica.com"),
            "detail": f"Status: {status} | KYC: {item.get('kycPolicy', 'Not Stated')}"
                      + (f" | Warning: {item['warning']}" if item.get("warning") else ""),
        })
    return events


def write_rss_feed(events: list, now_rfc2822: str):
    items_xml = []
    for ev in events[:40]:
        title = html.escape(f"[{ev['type']}] {ev['name']} — {ev['detail']}")
        link = html.escape(ev.get("profileUrl", "https://monerica.com"))
        desc = html.escape(f"Category: {ev.get('category', '')} | {ev.get('detail', '')}")
        guid = html.escape(f"{ev.get('slug', '')}-{ev.get('type', '')}-{ev.get('timestamp', '')}")
        items_xml.append(
            f"    <item>\n"
            f"      <title>{title}</title>\n"
            f"      <link>{link}</link>\n"
            f"      <description>{desc}</description>\n"
            f"      <guid isPermaLink=\"false\">{guid}</guid>\n"
            f"    </item>"
        )

    rss_content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n'
        '  <channel>\n'
        '    <title>Monerica Watch — KYC &amp; Scam Alert Feed</title>\n'
        '    <link>https://monerica.com</link>\n'
        '    <description>Automated alerts for status, KYC policy, and scam changes on Monerica.com</description>\n'
        f'    <lastBuildDate>{now_rfc2822}</lastBuildDate>\n'
        + "\n".join(items_xml) + "\n"
        '  </channel>\n'
        '</rss>\n'
    )
    RSS_FILE.write_text(rss_content, encoding="utf-8")


def send_telegram_alerts(new_events: list):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id or not new_events:
        return

    for ev in new_events[:10]:
        msg = f"[{ev['type']}] {ev['name']}\n{ev['detail']}\n{ev['profileUrl']}"
        payload = urllib.parse.urlencode({"chat_id": chat_id, "text": msg}).encode("utf-8")
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            urllib.request.urlopen(urllib.request.Request(url, data=payload), timeout=10)
        except Exception as exc:
            print(f"Telegram alert error: {exc}")


def main():
    DATA_DIR.mkdir(exist_ok=True)
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    now_rfc2822 = now_dt.strftime("%a, %d %b %Y %H:%M:%S +0000")

    raw_data = fetch_monerica_data()
    listings = raw_data.get("listings", [])
    current_map = {item["slug"]: item for item in listings if "slug" in item}

    summary = build_summary(listings, raw_data.get("generated", now_iso))
    SUMMARY_FILE.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    existing_changelog = []
    if CHANGELOG_FILE.exists():
        existing_changelog = json.loads(CHANGELOG_FILE.read_text(encoding="utf-8"))

    if SNAPSHOT_FILE.exists():
        old_map = json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))
        new_events = diff_listings(old_map, current_map, now_iso)
        if new_events:
            send_telegram_alerts(new_events)
        combined_events = (new_events + existing_changelog)[:MAX_EVENTS]
    else:
        combined_events = seed_initial_events(listings)

    CHANGELOG_FILE.write_text(json.dumps(combined_events, indent=2), encoding="utf-8")
    SNAPSHOT_FILE.write_text(json.dumps(current_map, indent=2), encoding="utf-8")
    write_rss_feed(combined_events, now_rfc2822)
    print(f"Sync complete. Tracked {len(current_map)} listings. Total events logged: {len(combined_events)}.")


if __name__ == "__main__":
    main()