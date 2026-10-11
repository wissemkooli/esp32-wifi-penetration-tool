> The follow-on unified release is documented in [UNIFIED_DASHBOARD.md](UNIFIED_DASHBOARD.md).
> Its browser worker and shared controller supersede the earlier UI discussed here.

# Audit and modernization

Target: ESP32 DevKit V1 with ESP32-WROOM-32, 4 MB flash.
Upstream baseline: `e346e28ed9c93e98ab686c30eb8c4bc549313ba3`.
SDK: ESP-IDF **v5.5.5**, commit `b774170ff46c393eeb5e495ea37936038d3f4f4f`.

## Findings and fixes

| Finding in upstream | Change | Verification |
| --- | --- | --- |
| Wildcard event unregister did not match registered handlers; stop/reset could abort | Unregister exact event base, ID and handler; make cleanup repeatable | Real start/stop/reset code exercised with event-loop mocks |
| Radio and EAPOL parsing trusted unverified lengths | Check MAC, LLC, EAPOL body, key data and each element before reading | Every truncation of a synthetic frame, malformed nested lengths, Windows guard pages |
| PMKID element traversal skipped bytes and could read outside a packet | Advance by element length plus its two-byte header; reject malformed/encrypted key data; free lists | Consecutive elements and short/malformed data tests |
| PMKID export assumed the receiver was always the ESP32's own station | Carry the actual receiver MAC from the observed AP key message into the result | Complete PMKID event-to-result test with a different receiver MAC |
| Handshake serializer retained stale state and misclassified messages | Reset all state; use explicit wire byte order; match client/AP, nonces, versions and replay counters | Repeated runs, M1/M2 and M2/M3, missing M1 and replay mismatch |
| Short HTTP bodies, invalid indices and method values were accepted | Require four bytes, receive partial reads, validate inputs, reserve run before reply | HTTP and concurrent-start reservation tests |
| Timeout callback could wait on a full event queue | Nonblocking timeout post with retry; serialize start/stop on event loop | Full-queue timeout recovery test |
| Queued frames could contaminate a later run | Tag copied events with capture generation and reject stale generations | Old-generation frame rejection test |
| UI used unsafe network-name rendering and reversed PMKID MAC labels | Render names as text, send SSID bytes as hex, correct MAC order; retry failed polling | Tests execute the actual UI script, including a markup-like SSID |
| Capture allocations grew without a bound; downloads could use missing or changing data | Bound PCAP to 64 KiB and status to 65,535 bytes; lock results and require completed capture | Buffer cap, cleanup, active/missing download tests |
| Runtime setup/connection and raw-transmit failures could restart the device | Return setup errors to run cleanup; log raw-transmit rejection | Failed sniffer, connection and method start tests; firmware build |
| SDK 4.1 build assumptions were obsolete | Explicit component dependencies, current Wi-Fi types, pinned SDK and generated web header | Native Windows firmware build with v5.5.5 |

The original code had real correctness and reliability problems. These fixes
make it easier to maintain, but do not demonstrate that every original radio
method works on current routers.

## Approved additions

### Router security report

The web UI and `/security-report` show SSID, BSSID, RSSI, channel, advertised
authentication mode and PMF status. Authentication mode comes from IDF scan
records; PMF comes from validated RSN elements in observed beacon/probe
response frames during a passive scan.

| PMF label | Meaning |
| --- | --- |
| Required | Both MFPC and MFPR are advertised |
| Supported, optional | MFPC is advertised, MFPR is not |
| Not advertised | A valid complete advertisement has no PMF capability |
| Inconsistent advertisement | MFPR is set without MFPC |
| Unknown | No valid advertisement was observed for that BSSID |

A scan is an observation of advertised capabilities. It does not verify the
router's actual enforcement or the negotiated security of a client connection.
Missing or malformed observations produce Unknown rather than a guessed value.
The observations are reset on each scan and stored in a bounded 64-entry table.

### SDK migration and automated checks

The build uses ESP-IDF v5.5.5 and targets `esp32`. It automatically generates
the embedded HTML with normalized text and a fixed gzip timestamp. Host tests
use the actual parser, serializers, lifecycle and HTTP code with mocked OS and
radio calls. UI tests execute the actual inline JavaScript against a minimal
DOM. CI adds ASan/UBSan on Linux and a firmware build in the versioned Espressif
container. CI configuration is included; remote CI has not been executed here.

## Why a current router may give no result

- The ESP32-WROOM-32 radio supports **2.4 GHz 802.11 b/g/n**. It cannot observe
  a client's connection on 5 GHz or 6 GHz. See the
  [Espressif module datasheet](https://documentation.espressif.com/esp32-wroom-32_datasheet_en.html).
- PMF protects robust management frames, including deauthentication and
  disassociation. WPA3 uses newer authentication and requires PMF; the original
  WPA/WPA2 capture methods do not establish WPA3 support. See
  [Espressif's Wi-Fi security guide](https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32/api-guides/wifi-security.html).
- A router need not send a PMKID in the exchange observed by this implementation.
  A missing PMKID is not sufficient evidence of a parser bug.
- Passive capture needs an actual client authentication exchange on the same
  2.4 GHz channel during the capture window. An already-connected idle client
  may produce no handshake.
- A router configured for WPA2/WPA3 transition mode can have clients using
  different negotiated security. The advertisement alone does not identify it.

No new router bypass or attack technique was added. The approved modernization
adds inspection of current advertised security and a current build environment.

## Remaining limits

- **No physical ESP32 or router tests have been performed.** Promiscuous
  observations during scan, channel changes, management AP reconnection,
  station connection behavior and active methods need hardware verification.
- The original `wsl_bypasser` overrides a private Wi-Fi symbol and permits
  duplicate linker symbols. Its presence in a successful build does not prove
  that the new closed Wi-Fi library uses that override or accepts a frame.
  Rejected raw transmissions now log an error instead of aborting the board.
- HCCAPX and the displayed PMKID export remain legacy formats. There is no
  hc22000 exporter in this scope. HCCAPX handles one supported WPA/WPA2
  client/AP message pair per run; mixed clients, fragmented, protected and
  aggregated MSDUs are not parsed as handshakes.
- Capture buffers stop growing at their limits. Under memory or event-queue
  pressure frames can be dropped. PCAP timestamps are radio-local microsecond
  timestamps, not wall-clock time, and may wrap.
- The existing terminal states have no separate setup-error state. A setup
  failure ends the run through TIMEOUT; its exact cause is in the serial log.
- Startup initialization and event-handler registration still treat failures
  as fatal. The tests mock radio/OS behavior and cannot establish timing,
  free-heap margins or every allocation failure on real hardware.

## Verification on your board

1. Flash the new `build-modern` output using the README instructions and keep
   the serial log at 115200 baud. Confirm the reported chip and flash size.
2. Connect to `ManagementAP` with password `mgmtadmin`, then open
   `http://192.168.4.1`. Check that the security table loads and Refresh works.
3. Compare your own router's WPA2/WPA3 and PMF settings with the report. If PMF
   is Unknown, repeat the scan and retain the log; do not infer PMF is disabled.
4. For a basic capture check, select your own 2.4 GHz WPA2 network and use
   **Passive capture only**. Reconnect your own client during the capture
   window. Check the PCAP in Wireshark. HCCAPX may be absent if no supported
   complete message pair was observed.
5. Reset and repeat several times. Confirm the board does not reboot and that
   a run without new frames does not return the previous run's handshake.
6. Keep the mode, router model/settings and serial log for any failure. This is
   the evidence needed to distinguish capture timing, SDK radio behavior and
   a remaining code defect.

## Local verification result

Native Windows ESP-IDF v5.5.5 firmware build: passed.
Native GCC core regression suite: passed (warnings treated as errors).
Real browser worker/dashboard and Python parity regression suites: passed.
Embedded-page consistency check: passed.
Linux sanitizer run and GitHub CI: configured, not executed locally.
Physical board tests: pending.
