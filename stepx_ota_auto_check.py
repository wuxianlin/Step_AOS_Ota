#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
StepOS OTA Auto Check - periodic OTA watcher driven by a CSV device list.

Reads known devices/channels from a CSV file, queries the OTA server for each
device+channel group (reusing stepx_ota.py signing/parsing logic), and APPENDS
a new row when a new android version is detected. The CSV is append-only and
acts as version history: the latest row of each group holds the current
baseline, whose version doubles as the sysVer of the next query.
Designed to run from cron/systemd timers.

CSV columns:
    device_type,android,channel,version,url,digest_md5,digest_sha256

 Behaviour per device+channel group (latest row = most recent in file order):
    - version differs from the latest row  -> append a new row with the new
      version (old rows are kept as history)
    - version identical                    -> nothing appended
    - version empty                        -> group skipped (no baseline)
    - request error                        -> nothing appended

Exit codes: 0 = no change, 2 = change detected, 1 = all groups failed.
"""

import argparse
import csv
import os
import sys
import time
from datetime import datetime, timezone

from stepx_ota import (  # noqa: E402  (same directory)
    CHECK_ENDPOINT,
    SWITCH_ENDPOINT,
    DeviceConfig,
    parse_update_response,
    send_ota_request,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CSV = os.path.join(SCRIPT_DIR, "stepx_ota_devices.csv")

FIELDNAMES = [
    "device", "android", "channel",
    "version", "url", "digest_md5", "digest_sha256",
]


# ============================================================
# CSV Handling
# ============================================================


def load_rows(csv_path: str) -> list:
    """Load all rows from CSV (file order = chronological order)."""
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_rows(csv_path: str, all_rows: list) -> None:
    """Write all rows (history + appended) atomically to avoid corruption."""
    tmp_path = csv_path + ".tmp"
    with open(tmp_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_rows)
    os.replace(tmp_path, csv_path)


def group_key(row: dict) -> tuple:
    """Identity of a monitored target: model + android ver + channel."""
    return (row.get("device", "").strip(),
            row.get("android", "16").strip() or "16",
            row.get("channel", "stable").strip().lower() or "stable")


def utc_now() -> str:
    """Current UTC time as an ISO string (console output only)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ============================================================
# Checking Logic
# ============================================================


def latest_per_group(rows: list) -> list:
    """
    Collapse rows into groups keyed by group_key(), keeping only the LAST
    (newest) row of each group for checking. File order is preserved.
    """
    latest = {}
    order = []
    for row in rows:
        key = group_key(row)
        if key not in latest:
            order.append(key)
        latest[key] = row
    return [latest[k] for k in order]


def make_row(ref: dict, info) -> dict:
    """Build a new history row from a reference row and parsed update info."""
    return {
        "device": ref.get("device", "").strip(),
        "android": ref.get("android", "16").strip() or "16",
        "channel": ref.get("channel", "stable").strip().lower() or "stable",
        "version": (info.version or "").strip(),
        "url": info.download_url or "",
        "digest_md5": info.digest_md5 or "",
        "digest_sha256": info.digest_sha256 or "",
    }


def check_group(ref: dict) -> tuple:
    """
    Query OTA for one device+channel group. The latest row's version
    serves both as the change-detection baseline AND as the reported sysVer
    of this query (i.e. "is there anything newer than what I already have").

    Never mutates existing rows; the caller appends on change.

    Returns:
        (change: bool, new_row: dict or None)
        Raises on request failure / unusable reply.
    """
    version = (ref.get("version") or "").strip()
    if not version:
        raise ValueError("version is empty, no baseline to check against")

    config = DeviceConfig(
        device=ref.get("device", "").strip(),
        sys_ver=version,   # baseline doubles as the query sysVer
        android=ref.get("android", "16").strip() or "16",
    )
    channel = group_key(ref)[2]
    endpoint = CHECK_ENDPOINT if channel == "stable" else SWITCH_ENDPOINT
    target = None if channel == "stable" else channel

    response = send_ota_request(config, endpoint, target)
    info = parse_update_response(response)
    latest = (info.version or "").strip()
    if not latest:
        raise ValueError(f"no version in reply (code="
                         f"{response.get('reply', response).get('code')})")

    if latest != version:
        print(f"  [CHANGE] {version}\n           -> {latest}")
        if info.download_url:
            print(f"           url: {info.download_url}")
        return True, make_row(ref, info)

    return False, None


# ============================================================
# Main
# ============================================================


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Periodic StepOS OTA watcher driven by a CSV device list "
                    "(append-only version history)")
    parser.add_argument("--csv", default=DEFAULT_CSV,
                        help=f"device CSV path (default: {DEFAULT_CSV})")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between group checks (default: 2)")
    parser.add_argument("--dry-run", action="store_true",
                        help="check only, never write the CSV")
    args = parser.parse_args()

    if not os.path.exists(args.csv):
        print(f"[!] CSV not found: {args.csv}")
        return 1

    rows = load_rows(args.csv)
    groups = latest_per_group(rows)
    print(f"[{utc_now()}] checking {len(groups)} target(s) "
          f"({len(rows)} history rows) from {args.csv}")

    appended, failed = [], 0
    for i, ref in enumerate(groups, 1):
        label = f"{ref.get('device_type', '?')}/{ref.get('channel', '?')}"
        print(f"[{i}/{len(groups)}] {label}")
        try:
            change, new_row = check_group(ref)
        except Exception as e:
            # Nothing appended: the last known row simply remains the baseline
            print(f"  [!] failed, kept previous baseline: {e}")
            failed += 1
        else:
            if change:
                appended.append(new_row)
        if i < len(groups):
            time.sleep(args.interval)

    if appended:
        rows.extend(appended)

    if args.dry_run:
        print("[dry-run] CSV not modified")
    else:
        save_rows(args.csv, rows)
        print(f"CSV saved: {args.csv} ({len(rows)} rows, +{len(appended)} appended)")

    print(f"done: {len(groups)} target(s), {len(appended)} appended, {failed} failed")
    if appended:
        return 2  # useful signal for cron-driven notifications
    return 0 if failed < len(groups) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
