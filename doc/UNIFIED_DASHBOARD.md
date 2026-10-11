# Unified dashboard 1.0

## Everyday use

Flash the complete firmware bundle onto an ESP32 DevKit V1 / ESP32-WROOM-32
with 4 MB flash. Connect Android Chrome to `ManagementAP` (default password
`mgmtadmin`) and open `http://192.168.4.1`. Everyday use needs no computer,
Termux, internet connection or external website.

1. In **Networks**, refresh the scan and select your network. WPA modes and
   PMF are advertised capabilities; Unknown PMF does not mean disabled PMF.
2. In **Capture / Controller**, select one network for a handshake capture.
   Start with **Passive capture only** and reconnect your own client during
   the timed window. Up to eight networks can be selected for the supplied
   controller test. The board accepts one radio operation at a time.
3. Completed handshake PCAPs transfer automatically into browser memory.
   In **Offline Audit**, select a usable client exchange, check the exact
   SSID, choose known-password verification, SSID patterns or a local wordlist,
   and start. Plain UTF-8 and gzip wordlists stream through the worker.
4. **Capture & audit** remembers the chosen mode and local password/wordlist
   and starts it after the capture arrives. Configure those fields first.
   If another audit is running, the requested audit waits for it to finish.
5. **Cancel audit** immediately terminates the worker and clears queued
   automatic audits. It does not stop the ESP32. Select the saved capture
   again to restart. **Stop device** stops only the radio operation.
6. Use **Save selected capture**, **Save PCAP**, or the legacy HCCAPX link to
   retain results. PMKID results can be inspected and saved as text; password
   testing of PMKIDs is outside this release.

The ESP32 has one 2.4 GHz radio. Channel changes may interrupt its management
connection. The dashboard retries automatically and the device keeps its own
deadline. If Android switches networks, reconnect to ManagementAP, keep the
same page open, and wait for contact to return. A local audit can continue
through this interruption. The board does not cover 5 or 6 GHz.

Each worker uses its own capture snapshot. Starting another radio job does
not alter a running audit. Files, candidates and passwords stay on the phone;
only device configuration and target indices are submitted to the ESP32.
The page must remain open. Android suspension is not guaranteed to preserve
execution. Reloading or closing it discards its in-memory files and results.
The device retains only its latest result; save it before leaving the page.

## Supported offline inputs

- Classic little-endian PCAP version 2.4 with linktype 105 (raw 802.11).
  Firmware PCAP files use this format. Imports are limited to 32 MiB.
- WPA2 RSN EAPOL-Key descriptor version 2, HMAC-SHA1 MIC, M1/M2 or M2/M3
  pairs. Messages are grouped by AP and client and matched by replay counter
  and nonce, rather than adjacency. Identical retransmissions are deduplicated.
- Select one exchange when a capture contains several. A match confirms that
  exchange; it does not imply all clients in the capture use the same password.
- SSID bytes from firmware metadata are preserved, including meaningful
  spaces and embedded NULs. Editing the field replaces them with UTF-8 bytes.
  Imported captures require the correct SSID to be supplied by the user.
- Password candidates are 8–63 UTF-8 bytes. The default limit is 100,000 tested
  unique candidates, configurable up to 1,000,000. Invalid/duplicate lines do
  not count as attempts. Wordlist spaces are significant; only CRLF endings
  are removed. UTF-8 decoding replaces malformed byte sequences.

PCAPNG, radiotap, big-endian PCAP, WPA/TKIP, WPA3 SAE, enterprise authentication,
descriptor version 3, raw 64-hex PSKs, fragmented/protected data and aggregated
MSDUs are outside the browser audit support. Unsupported PCAP formats and
descriptor versions are reported. Missing or unusable exchanges are reported
as such. A no-match result does not prove password strength. The inherited
pattern generators are preserved; this release adds no router bypass technique.

`companion/wifiaudit.py` retains the Python implementation as an optional
standalone/reference tool with matching replay checks and exchange selection.
Run `python companion/wifiaudit.py --help` for its arguments. It is not needed
for browser operation. The supplied Python code is user-provided; no additional
third-party license grant is inferred for that source.

## Device interfaces

All JSON replies identify `schema_version: 1`. Job IDs are scoped to a random
16-hex-character `boot_id`. Target indices refer to a particular
`scan_generation`. Stale identities fail instead of returning another run.

| Route | Function |
| --- | --- |
| `GET /api/v1/device` | Firmware, chip/band, management SSID, maximum targets, boot ID |
| `GET /api/v1/networks` | Cached scan generation and networks with exact `ssid_hex`, BSSID, channel, RSSI, security and PMF |
| `POST /api/v1/scan` | Reserve and start a passive scan; returns 202 and its job |
| `POST /api/v1/jobs` | Reserve a timed operation; returns 202 and its job |
| `GET /api/v1/job` | Current state, identity, target metadata, elapsed time, controller counters, completion reason and available files |
| `POST /api/v1/stop` | Stop the matching boot/job identity |
| `GET /api/v1/capture?boot_id=...&id=...` | Result metadata for a matching capture |
| `GET /api/v1/capture.pcap?boot_id=...&id=...` | Completed PCAP |
| `GET /api/v1/capture.hccapx?boot_id=...&id=...` | Completed legacy HCCAPX, when available |

Job submission example:

```json
{"boot_id":"0123456789abcdef","scan_generation":1,"targets":[0],"type":1,"method":2,"timeout":60}
```

Types are 1 handshake, 2 PMKID, 3 existing single-target controller methods,
and 4 supplied multi-target controller. Type 1 methods are 0 rogue AP,
1 broadcast deauthentication, 2 passive. Type 3 methods are 0 rogue AP,
1 broadcast, 2 combined. Types 2 and 4 require method 0. Timeouts are 1–255
seconds. Only type 4 accepts multiple targets. Transmission counters describe
the supplied type 4 controller and count SDK successes/errors, not proof that
a client received or acted on a frame.

Stop example: `{"boot_id":"0123456789abcdef","id":2}`.
400 means invalid input, 404 stale/missing identity, 409 busy/stale selection,
503 a queue/setup request could not be accepted. Job states are idle, scanning,
running, stopping, complete or error. Reasons include complete, deadline,
cancelled, scan_complete and setup_failed/SDK error. Completion of a deadline
can still leave a usable capture. Metadata contains `pcap`/`hccapx` availability
flags and PMKID text entries when present. A scan is finite but cannot be stopped
partway through the synchronous SDK scan; other radio commands are rejected.

The previous `/ap-list`, `/security-report`, `/run-attack`, `/status`, `/reset`,
`/capture.pcap` and `/capture.hccapx` routes remain compatibility adapters.
They use the same radio manager; legacy downloads have no identity protection.

## Optional USB serial

USB serial at 115200 baud shares the browser's manager:
`scan`, `list`, `all`, `0,2,5`, `start`, `stop`, `status`, `limit 30`, `cancel`,
and `help`. Wait for the asynchronous scan to finish, then use `list`.
`all` selects the eight strongest cached networks. Explicit selections reject
malformed tokens and preserve the previous selection on error. Duplicate
indices are deduplicated. A new scan makes an older selection stale.
`cancel` stops a running non-scan job and clears the serial selection.
The default serial limit is 30 seconds; limits must be 1–255, rather than an
unlimited test. USB serial is optional for everyday browser use.

## Build and verification

Use Node 22 or later, `npm ci`, and ESP-IDF **v5.5.5** for target **esp32**.
Dependencies are pinned by `package-lock.json`; hash-wasm is exactly **4.12.0**.
`npm run build` creates the dashboard and self-contained WASM worker.
The firmware build compresses and embeds all runtime scripts, CSS and licenses
into flash. No CDN or runtime downloads are used. Build dependencies need
internet access only when initially installed.

```shell
npm ci
idf.py -B build-modern -DIDF_TARGET=esp32 build
# Native host regression suite, including the actual browser worker:
npx playwright install chromium
python tests/run_tests.py
# Linux with compiler memory/undefined-behavior instrumentation:
python tests/run_tests.py --sanitize
```

Windows uses installed Edge by default for browser tests. Set
`BROWSER_EXECUTABLE` to another compatible browser path if needed; set `CC`
for a GCC compiler outside PATH. `PYTHON` is supplied to the parity tests by
the test runner. CI installs Chromium and performs host sanitizer tests and
the pinned firmware build. CI has been configured but not run remotely.

Passed locally: independent PBKDF2/HMAC vectors; Python/browser synthetic
capture parity; interleaved clients, retransmissions, M2/M3, mismatched replay,
wrong passwords, SSID spaces, unsupported descriptors and truncated packets;
plain/gzip streams and candidate limits; browser worker termination, stale
messages, concurrent device/audit progress, reconnects and automatic transfer;
native C lifecycle, strict HTTP, browser/serial conflicts, target snapshots,
failed starts, timeouts and capture identity mismatches. Native radio/OS tests
use mocks. Desktop Chromium tests do not establish Android behavior.

## Required DevKit V1 acceptance checks — pending

1. Confirm classic ESP32 and 4 MB flash, then flash all three matched files.
2. Load the dashboard without internet and check all panels on Android Chrome.
3. Compare the advertised security/PMF report to your own router settings.
4. Capture your own WPA2 reconnect passively; verify the expected password
   locally and compare the downloaded PCAP with Wireshark.
5. Run a saved-capture audit while another capture runs. Confirm both progress
   indicators, immutable results and that the two Stop buttons are independent.
6. Repeat channel changes, phone reconnection, early Stop, timeout and captures
   with no frames. Confirm ManagementAP's channel/MAC/settings return and
   stale results are not reused. Collect serial logs and heap/reset behavior.
7. Check the existing active methods on your own setup. They remain unverified
   until these hardware tests pass: ESP-IDF's private raw-frame behavior may
   reject transmissions even though the firmware compiles successfully.

No board has been flashed or physically tested in this workspace.
