#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
StepOS OTA Tracker - Query OTA firmware update info for StepOS devices.

Pure Python (stdlib only) implementation of the OTA check protocol of
com.stepos.update (MzUpdate.apk), reverse engineered via jadx + IDA Pro:

  POST https://upush.<domain>/v4/firmware/check     channel = current
  POST https://upush.<domain>/v4/firmware/switchover  target channel (daily/beta)

Signing (OAuth-like, keys extracted from lib/arm64-v8a/libupgrade.so):
  base  = [sys, oauth_consumer_key, oauth_timestamp, oauth_version,
           oauth_signature_method]
  msg   = "POST|urlenc(url)|k1=v1&k2=v2&...|SECRET|"
          ("|" separators after method/url/first-param/tail, "&" between params)
  oauth_signature = base64(HMAC-SHA256(msg, SECRET))
Verified against real device captures (sign accepted by server, HTTP 200).
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ============================================================
# Constants
# ============================================================

DOMAIN = "stepaos.com"                       # net_env: prod; dev->d-stepaos.com, stg->s-stepaos.com, test->t-stepaos.com
BASE_URL = f"https://upush.{DOMAIN}"         # ro.stepos.international=true -> https://u.in.{DOMAIN}
CHECK_ENDPOINT = "/v4/firmware/check"        # current-channel check
SWITCH_ENDPOINT = "/v4/firmware/switchover"  # target-channel check (daily/beta)

# JNI keys from com.stepos.update.jni.UpgradeNdkMain (libupgrade.so)
OAUTH_CONSUMER_KEY = "kB0GuUVISDjfGnzR2uSU"  # getOauthConsumerKey()
OAUTH_SECRET = "pSo9LOJlVYqBmYsYQfXWxIdgt5et2Q"  # getOauthSecret()

# AbstractC3218e.m5533m(): packageName + "/" + versionName
USER_AGENT = "com.stepos.update/1.0.44_20260927_163307"
CHANNELS = ("stable", "daily", "beta")

# ============================================================
# Dataclasses
# ============================================================


@dataclass
class DeviceConfig:
    """Device configuration for OTA query.

    Field comments document how the original app (com.stepos.update)
    obtains each value on a real device (jadx references included).
    """

    # AbstractC3218e.m5528h(): "ro.stepos.product.model" (fallback Build.MODEL;
    # MzProduct builds try "ro.vendor.stepos.product.model" / BuildExt MZ_MODEL first)
    device: str = "PZ261A"
    # AbstractC3218e.m5537q(): "ro.build.mask.id" -> "ro.build.aios_version"
    # -> "ro.build.aios_version_suffix" -> Build.DISPLAY
    sys_ver: str = "Step AOS 1.0.0.2.26001_stable_user_20261004_131555"
    # AbstractC3218e.m5524d(): Build.VERSION.RELEASE ("Q"->"10", "R"->"11")
    android: str = "16"
    # DeviceUtilsWrap.m4429E() -> OAID provider via AbstractC2843j2.m4729r();
    # optional server-side, random uuid works
    oaid: str = field(default_factory=lambda: uuid.uuid4().hex)
    # DeviceUtilsWrap.m4493v(): query content://com.stepos.secureservice.open.DataProvider
    # (selection arg "5", column "value"); REQUIRED non-empty by the server,
    # but a random uuid is accepted
    dsid: str = field(default_factory=lambda: uuid.uuid4().hex)
    # DeviceUtilsWrap.m4430F(): query content://com.stepos.secureservice.open.NormalDataProvider
    # (falls back to com.stepos.safe.open.NormalDataProvider), selection "1", column "value";
    # never sent on switchover, and not validated by the server at all
    ppid: str = field(default_factory=lambda: uuid.uuid4().hex)
    verbose: bool = False


@dataclass
class UpdateInfo:
    """Parsed OTA update information."""

    exists_update: Optional[bool] = None
    version: Optional[str] = None
    system_version: Optional[str] = None
    ver_type: Optional[str] = None
    release_date: Optional[str] = None
    size: Optional[str] = None
    size_bytes: Optional[int] = None
    download_url: Optional[str] = None
    digest_md5: Optional[str] = None
    digest_sha256: Optional[str] = None
    mandatory: Optional[bool] = None
    release_note: Optional[str] = None
    raw_response: Optional[str] = None


# ============================================================
# Signing Functions
# ============================================================


def _java_urlencode(s: str) -> str:
    """Replicate java.net.URLEncoder.encode (space->+, keep .-*_)."""
    q = urllib.parse.quote(str(s), safe=".-*_")
    return q.replace("~", "%7E")


def _param_encode(s: str) -> str:
    """Replicate RequestManager.paramEncode: + -> %20, * -> %2A."""
    return s.replace("+", "%20").replace("*", "%2A")


def sign_oauth(params: List[tuple], url: str, secret: str = OAUTH_SECRET,
               method: str = "POST") -> str:
    """
    Build the oauth_signature for /v4/firmware/* requests.

    Message layout (jadx: RequestManager.oauthCheckSignature):
        method | urlencode(url) | p1=v1 & p2=v2 ... | secret |
    - params sorted by name; first param joined with "|", rest with "&"
    - values: urlencode then paramEncode
    """
    pairs = sorted(params, key=lambda p: p[0])
    msg = f"{method}|{_java_urlencode(url)}"
    for i, (name, value) in enumerate(pairs):
        sep = "|" if i == 0 else "&"
        msg += f"{sep}{name}={_param_encode(_java_urlencode(value))}"
    msg += f"|{secret}|"
    digest = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


# ============================================================
# Request Building
# ============================================================


def build_sys_json(config: DeviceConfig, target_type: Optional[str] = None) -> str:
    """
    Build the `sys` parameter (jadx: RequestManager.generateNewSysParam).

    switchover carries targetFirmwareType and no ppid (3rd arg false).
    """
    obj: Dict = {
        "isCheckCdnBandwidth": False,
        "retryCheckCounts": 0,
        "unitType": "0",
        "oaid": config.oaid,
        "dsid": config.dsid,
        "deviceType": config.device,
        "firmware": config.android,
        "root": 0,
        "sysVer": config.sys_ver,
        "version": config.sys_ver,
    }
    if target_type:
        obj["targetFirmwareType"] = target_type
    else:
        obj["ppid"] = config.ppid
    return json.dumps(obj, separators=(",", ":"))


def build_request_params(config: DeviceConfig, url: str,
                         target_type: Optional[str] = None) -> Dict[str, str]:
    """Assemble signed form fields for an OTA check request."""
    base = [
        ("sys", build_sys_json(config, target_type)),
        ("oauth_consumer_key", OAUTH_CONSUMER_KEY),
        ("oauth_timestamp", str(int(time.time()))),  # seconds
        ("oauth_version", "1.0"),
        ("oauth_signature_method", "HMAC-SHA256"),
    ]
    fields = dict(base)
    fields["oauth_signature"] = sign_oauth(base, url)
    return fields


# ============================================================
# HTTP Functions
# ============================================================


def http_post_form(url: str, fields: Dict[str, str], headers: Dict[str, str] = None,
                   timeout: int = 30, max_retries: int = 3) -> str:
    """POST form-urlencoded body with retry/backoff. Returns response text."""
    data = urllib.parse.urlencode(fields).encode()
    last_error: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("User-Agent", USER_AGENT)
            req.add_header("Content-Type",
                           "application/x-www-form-urlencoded; charset=UTF-8")
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError:
            raise  # HTTP-level errors (404/500) are meaningful, do not retry
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_error = e
            if attempt < max_retries - 1:
                wait = 2 * (attempt + 1)
                print(f"  [!] Connection error, retrying in {wait}s "
                      f"({attempt + 1}/{max_retries})")
                time.sleep(wait)
    raise last_error


def send_ota_request(config: DeviceConfig, endpoint: str,
                     target_type: Optional[str] = None) -> dict:
    """Send a signed OTA check/switchover request, return parsed JSON."""
    url = BASE_URL + endpoint
    fields = build_request_params(config, url, target_type)
    # OtaUpdateCheckRequest.getHeaders()
    headers = {"retryCheckCounts": "0", "isCheckCdnBandWidth": "false"}
    text = http_post_form(url, fields, headers)
    return json.loads(text)


# ============================================================
# Response Parsing
# ============================================================


def _parse_firmware(fw: dict) -> dict:
    """Flatten an UpdateFirmware-like object (cur/new) into key fields."""
    return {
        "existsUpdate": fw.get("existsUpdate"),
        "latestVersion": fw.get("latestVersion"),
        "systemVersion": fw.get("systemVersion"),
        "verType": fw.get("verType"),
        "releaseDate": fw.get("releaseDate"),
        "fileSize": fw.get("fileSize"),
        "size": fw.get("size"),
        "updateUrl": fw.get("updateUrl"),
        "digest": fw.get("digest"),
        "digestV2": fw.get("digestV2"),
        "mandatoryUpgrade": fw.get("mandatoryUpgrade"),
        "markDownText": fw.get("markDownText"),
    }


def parse_update_response(response: dict) -> UpdateInfo:
    """Parse the reply envelope {code, message, value:{new, cur, plan}}."""
    info = UpdateInfo(raw_response=json.dumps(response, ensure_ascii=False))
    reply = response.get("reply", response)
    code = reply.get("code")

    if code != 200:
        info.exists_update = False
        info.release_note = f"code={code} message={reply.get('message', '')}"
        return info

    value = reply.get("value") or {}
    # switchover responses put the payload in "new" when a target build exists
    fw = value.get("new") or value.get("cur") or {}
    info.exists_update = bool(fw.get("existsUpdate"))
    info.version = fw.get("latestVersion")
    info.system_version = fw.get("systemVersion")
    info.ver_type = fw.get("verType")
    info.release_date = fw.get("releaseDate")
    info.size = fw.get("fileSize")
    info.size_bytes = fw.get("size")
    info.download_url = fw.get("updateUrl")
    info.digest_md5 = fw.get("digest")
    info.digest_sha256 = fw.get("digestV2")
    info.mandatory = fw.get("mandatoryUpgrade") == 1
    info.release_note = fw.get("markDownText")
    return info


# ============================================================
# Display Functions
# ============================================================


def print_update_info(info: UpdateInfo, endpoint: str) -> None:
    """Print update information in formatted output."""
    print("\n=== Update Information ===")
    print(f"  Endpoint    : {endpoint}")

    if info.exists_update is False and info.version is None:
        print(f"  Result      : no update / rejected ({info.release_note})")
        return

    print(f"  ExistsUpdate: {info.exists_update}")
    for label, v in [
        ("Version", info.version),
        ("SystemVer", info.system_version),
        ("VerType", info.ver_type),
        ("ReleaseDate", info.release_date),
        ("Size", info.size),
        ("Mandatory", info.mandatory),
        ("Download URL", info.download_url),
        ("MD5", info.digest_md5),
        ("SHA256", info.digest_sha256),
    ]:
        if v not in (None, ""):
            print(f"  {label:12s}: {v}")
    if info.release_note:
        note = info.release_note.strip().replace("\n", " ")
        print(f"  Note        : {note[:120]}{'...' if len(note) > 120 else ''}")


# ============================================================
# Main Query Function
# ============================================================


def query_ota_update(config: DeviceConfig, target_type: str = "stable",
                     raw_json: bool = False) -> Optional[UpdateInfo]:
    """
    Query OTA update for a device channel.

    Args:
        config: Device configuration
        target_type: stable -> /v4/firmware/check, daily/beta -> switchover
        raw_json: print the raw response JSON

    Returns:
        UpdateInfo if successful, None otherwise
    """
    endpoint = CHECK_ENDPOINT if target_type == "stable" else SWITCH_ENDPOINT
    print(f"  Device : {config.device} | {config.sys_ver}")
    print(f"  Channel: {target_type}  ->  POST {endpoint}")

    try:
        response = send_ota_request(config, endpoint,
                                    None if target_type == "stable" else target_type)
    except Exception as e:
        print(f"  [!] Request failed: {e}")
        return None

    if config.verbose or raw_json:
        print(json.dumps(response, ensure_ascii=False, indent=2))

    info = parse_update_response(response)
    if not raw_json:
        print_update_info(info, endpoint)
    return info


# ============================================================
# CLI Entry Point
# ============================================================


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="StepOS OTA Tracker - query firmware updates for StepOS devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Current channel (stable) check
  %(prog)s

  # Check beta channel via switchover
  %(prog)s -t beta

  # Custom device, raw JSON output
  %(prog)s -d PZ261A --sysver "Step AOS 1.0.0.2.26001_stable_user_20261004_131555" --json
        """)

    parser.add_argument("-d", "--device", default="PZ261A",
                        help="ro.stepos.product.model (default: PZ261A)")
    parser.add_argument("--sysver", default=DeviceConfig.sys_ver,
                        help="ro.build.mask.id (sysVer)")
    parser.add_argument("-a", "--android", default="16",
                        help="Android major version, Build.VERSION.RELEASE (default: 16)")
    parser.add_argument("-t", "--target", default="stable", choices=CHANNELS,
                        help="check channel: stable=check, daily/beta=switchover")
    # Original app sources: oaid <- OAID provider; dsid <- secureservice DataProvider
    # (must be non-empty); ppid <- NormalDataProvider ContentProvider (not validated)
    parser.add_argument("--oaid", default=None,
                        help="oaid; original: OAID provider (default: random)")
    parser.add_argument("--dsid", default=None,
                        help="dsid; original: secureservice DataProvider (default: random)")
    parser.add_argument("--ppid", default=None,
                        help="ppid; original: NormalDataProvider, optional "
                             "(default: random)")
    parser.add_argument("--json", action="store_true",
                        help="print raw response JSON only")
    parser.add_argument("--verbose", action="store_true",
                        help="print raw response JSON alongside parsed output")
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()
    config = DeviceConfig(
        device=args.device,
        sys_ver=args.sysver,
        android=args.android,
        oaid=args.oaid or uuid.uuid4().hex,
        dsid=args.dsid or uuid.uuid4().hex,
        ppid=args.ppid or uuid.uuid4().hex,
        verbose=args.verbose,
    )
    info = query_ota_update(config, target_type=args.target, raw_json=args.json)
    return 0 if info is not None else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n  [!] Interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n  [!] Fatal error: {e}")
        sys.exit(1)
