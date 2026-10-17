# Step AOS OTA Tracker

Step AOS OTA Tracker is an open-source tool for querying official OTA firmware and system-app updates for Step AOS devices (`com.stepos.update` / MzUpdate.apk) directly from your computer. The request protocol was fully reverse engineered from the APK and verified against real device captures.

---

**Core Features:**
* 📦 **Firmware Fetching**: Construct device parameters on your PC to query official OTA servers and extract firmware download links, digests, and changelogs.
* 🔐 **Full Signing Support**: Reproduces all signature schemes of the updater — HMAC-SHA256 (appupgrade), OAuth-style HMAC (firmware v4), and double-HMAC headers (UMAP).
* 📱 **Multi-Device Support**: Custom device model, system version, and update channel (`stable` / `daily` / `beta`).
* 🕐 **Scheduled Monitoring**: CSV-driven watcher with append-only version history, ready for cron/systemd timers.

---

### 📁 Files

| File | Description |
|------|-------------|
| `stepx_ota.py` | Single-shot OTA query CLI (stdlib only, no dependencies) |
| `stepx_ota_auto_check.py` | Periodic watcher driven by the CSV device list |
| `stepx_ota_devices.csv` | Device list + append-only version history |
| `stepx_update_api.py` | Extended toolkit: APK update check, UMAP platform, CDN check (reference/legacy) |

---

### 🛠️ Environment Prerequisites

#### Python Version
* **Python 3.8 or higher**
* `stepx_ota.py` / `stepx_ota_auto_check.py`: **no third-party dependencies** (stdlib only)
* `stepx_update_api.py` (optional): `pycryptodome` for the credential decryption demo
  ```bash
  pip install pycryptodome
  ```

---

### 🚀 Quick Start

#### Single Query
```bash
# Current channel (stable) check
python stepx_ota.py

# Check beta channel via /v4/firmware/switchover
python stepx_ota.py -t beta

# Custom device + raw JSON output
python stepx_ota.py -m PZ261A --sysver "Step AOS 1.0.0.2.26001_stable_user_20261004_131555" --json
```

#### Scheduled Monitoring
```bash
# One-shot watcher run (reads CSV, appends on change)
python stepx_ota_auto_check.py

# Dry run: check but never write the CSV
python stepx_ota_auto_check.py --dry-run

# crontab: every 2 hours
0 */2 * * * cd /path/to/stepx && python3 stepx_ota_auto_check.py >> stepx_ota_cron.log 2>&1
```

Exit codes of the watcher: `0` = no change, `2` = new version appended, `1` = all targets failed.

---

### ⚙️ CLI Arguments (`stepx_ota.py`)

| Argument | Description | Original app source | Default |
|----------|-------------|---------------------|---------|
| `-d`, `--device` | Device model | `ro.stepos.product.model` | `PZ261A` |
| `--sysver` | System version (maskId) | `ro.build.mask.id` | current stable build |
| `-a`, `--android` | Android major version | `Build.VERSION.RELEASE` | `16` |
| `-t`, `--target` | Channel: `stable`, `daily`, `beta` | firmware switch subscription | `stable` |
| `--oaid` | Advertising ID | OAID provider | random |
| `--dsid` | Device ID (**must be non-empty** server-side) | `secureservice` DataProvider | random |
| `--ppid` | Secondary device ID (not validated) | `NormalDataProvider` | random |
| `--json` | Print raw response JSON only | - | off |
| `--verbose` | Raw JSON + parsed output | - | off |

Device IDs are randomized per run by default (accepted by the server), which avoids device-profile correlation. Only `dsid` must be non-empty.

---

### 📋 CSV Format (`stepx_ota_devices.csv`)

```csv
device,android,channel,version,url,digest_md5,digest_sha256
```

The CSV is **append-only version history**:

* Rows are grouped by `device` + `android` + `channel`; the **last row** of each group is the current baseline used for the next check.
* On a new version, a new row is **appended** (previous rows are kept as history); `version` of the new row become the new baseline.
* Identical version / request error -> nothing is appended.

---

### 🔬 How It Works

| Endpoint | Purpose | Signing |
|----------|---------|---------|
| `POST /v4/firmware/check` | OTA firmware check (current channel) | OAuth-style: `POST\|url\|p=v&p=v\|SECRET\|` -> base64 HMAC-SHA256 |
| `POST /v4/firmware/switchover` | OTA check for target channel (`daily`/`beta`) | same as above, `targetFirmwareType` in `sys` |

Keys were extracted from `lib/arm64-v8a/libupgrade.so` (JNI `UpgradeNdkMain`):

| JNI Function | Value | Usage |
|--------------|-------|-------|
| `getOauthConsumerKey()` | `kB0GuUVISDjfGnzR2uSU` | v4 OAuth consumer key |
| `getOauthSecret()` | `pSo9LOJlVYqBmYsYQfXWxIdgt5et2Q` | v4 HMAC secret |

All signatures were byte-for-byte verified against Reqable captures of the real app.

---

### 🆘 FAQ & Troubleshooting

#### ❌ `code=120001 当前版本和目标版本不能一致` (switchover)
* **Cause**: you requested `--target stable` style consistency — the reported `sysVer` already belongs to that channel.
* **Solution**: check a different channel (`daily` / `beta`), or adjust `--sysver`.

#### ❌ `daily` / `beta` return the same package as `stable`
* **Cause**: no dedicated daily/beta builds are currently published for your model; the server falls back to the stable package (`verType` is empty).
* **Solution**: none — this is server-side rollout state, not a client bug.

#### ❌ `code=110001 Parameter sys's subitem must not null`
* **Cause**: `dsid` is missing or empty in the `sys` JSON.
* **Solution**: keep any non-empty `dsid` (random is fine).

#### ❌ `/appupgrade/checkCdn` returns 404
* **Cause**: the CDN rollout-gate endpoint has been taken down server-side. The client treats this as "download immediately". Ignore it.

---

### 📜 Disclaimer
This project is for technical learning and communication purposes only. Do not use it for any illegal or commercial purposes. The user bears all consequences for any problems caused by improper use.
