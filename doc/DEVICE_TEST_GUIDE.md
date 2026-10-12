# ESP32 evidence collection with a Windows PC and a phone

This guide is for a short, single-target test on your own network with your own
client. It works without USB access to the ESP32 or a monitor-mode adapter.
It separates firmware errors, capture results, client connectivity and evidence
that is unavailable with this equipment. It does not require changing router
security settings.

## What your equipment can prove

| Source | Useful evidence | Cannot establish by itself |
| --- | --- | --- |
| ESP32 Save device log | Boot/job identity, selected network, setup failure stage/code, controller submission/completion counters, terminal state | Whether a client received or obeyed a frame |
| Windows as Wi-Fi client | Association, BSSID/channel where exposed, disconnect/reconnect events, driver reason text, local reachability | A complete raw 802.11 capture or identification of the sender of a spoofed frame |
| Windows mobile hotspot | Client list, hotspot availability, driver-dependent diagnostic events | A guaranteed log of every deauthentication frame received or transmitted |
| Android/iPhone as client | Wi-Fi connection state, network details where exposed, screen recording, optional Android bug report | A universal frame log; many drivers drop frames without reporting them |
| Phone hotspot | Connected-device count/list where exposed, hotspot uptime | Per-frame logs or proof of who caused a disconnect |
| ESP32 handshake PCAP | EAPOL frames the capture pipeline delivered | All frames on the channel; this capture is filtered, not a deauthentication monitor |

**A Windows hotspot does not create monitor-mode support.** Normal Wireshark,
Npcap or Windows packet tracing often sees Ethernet/IP traffic, not the raw
Wi-Fi management frames. A disconnection reason can support an explanation but
does not authenticate the source of a frame. If no receiver exposes raw frames,
record `peer_frame_receipt: unknown`. No script can recover frames the driver
never exposes.

## 1. Prepare a clean evidence folder

1. On Windows create `Desktop\WiFiEvidence`. Download
   [Collect-WifiEvidence.ps1](../tools/Collect-WifiEvidence.ps1) from this branch.
   Use Windows PowerShell 5.1 or PowerShell on Windows. The collector needs no
   Python, Wireshark or extra adapter.
2. Synchronize automatic time on PC and phone. Write down their time difference
   if they disagree. Use UTC timestamps or include the timezone in every note.
3. Record Windows version, phone model/OS, ESP32 board, power source, firmware
   image filename and source commit if known. Keep power and locations unchanged
   for the comparisons. A firmware version label alone does not identify every
   build; the older diagnostics image had a stale `unified-1.0.2` label.
4. Prefer a test client/network you can interrupt briefly. Keep the network's
   existing security settings, and record WPA2/WPA3 and PMF as advertised. PMF
   advertised by an AP is not proof of what a particular connection negotiated.
5. Ensure the target is **2.4 GHz**. Classic ESP32 cannot observe a 5 GHz client
   just because its SSID matches a 2.4 GHz network. Record the exact target
   BSSID/channel, not only the SSID. Rescan after restarting a hotspot: its BSSID
   and channel may change. Do not assume channel 10 for a new scenario.
6. On the phone, disable cellular data / automatic mobile-data fallback for the
   observation period, where practical. Keep the screen awake. On the PC, avoid
   VPN or other routes masking the test client's local Wi-Fi path. Record any
   setting you changed and restore it afterward.

## 2. Your setup: phone controls ESP32; PC hosts the target hotspot

### C0. Keep the phone on ManagementAP and the PC hotspot running

This is your primary setup. The phone stays on the ESP32's management Wi-Fi;
the PC runs the Windows hotspot throughout. You do not need the PC to connect
to ManagementAP. The ESP32 scans/tests the PC hotspot over its own radio.

```text
Phone -- management Wi-Fi --> ESP32 -- test radio activity --> PC hotspot
Phone saves dashboard logs.                                 PC saves Windows logs.
                                                            No separate client yet.
```

1. On Windows open Settings → Network & Internet → Mobile hotspot. Configure a
   unique SSID, select 2.4 GHz if offered, and enable it. Keep the settings page
   open. Disable automatic shutdown when no clients are connected if offered;
   otherwise watch for shutdown and record it as a separate event.
2. Start `Collect-WifiEvidence.ps1 -Scenario C0-scan-01 -Seconds 180` on the PC.
   Omit `-Gateway`: the PC is the hotspot host, not a client whose link we are
   testing. Optionally start the Windows WLAN trace described below.
3. On the phone join the ESP32 management network, open the dashboard and keep
   that tab. Refresh scan. Match your unique hotspot SSID and record its BSSID,
   channel, security and PMF. Windows' upstream interface BSSID is a different
   network; do not select it by mistake.
4. Save screenshots of the Windows hotspot settings/client list and ESP32 scan.
   Run S0, then S1 (passive capture), using the common procedure below. If there
   are no hotspot clients reconnecting, an empty handshake capture is expected
   and cannot establish a broken receiver.
5. For another mode, use a new scenario folder and a short 15-second job. Keep
   the phone on ManagementAP; it may lose contact while the ESP32 uses its radio.
   Reconnect after the deadline and save the terminal log. On Windows record
   whether the hotspot remained enabled and any client/driver events.
6. PMKID mode involves an ESP32 connection attempt, so host-side events may
   appear even without a separate client. A Windows hotspot may provide no
   usable PMKID; that absence alone is inconclusive.
7. For deauthentication modes, record setup and transmission diagnostics, but
   write **client-disconnection result: not testable, no target client** when
   the hotspot has no connected client. The PC is the AP, not the client these
   frames are intended to disconnect. A hotspot remaining on is not failure.

This setup is useful for firmware setup errors, deadline/cleanup behavior,
hotspot compatibility and management-network restoration. The PC being the
target AP does not make it a monitor-mode receiver. It may neither receive nor
expose the relevant over-the-air frames in its Windows logs.

For actual client observations, keep this setup and add another owned client if
one becomes available. With only your existing phone and PC, use C below: after
launching a timed job, move the phone to the hotspot and later return it to the
dashboard. Alternatively A keeps the PC as a client of your existing router and
the phone as the dedicated ESP32 controller throughout.

### A. Alternative: existing router, PC as client, phone as ESP32 dashboard

1. Connect the PC to your router's 2.4 GHz network.
2. Run `netsh wlan show interfaces` and `ipconfig` in PowerShell. Record the
   connected BSSID, channel, interface and that interface's default gateway.
   If Windows hides Wi-Fi information, check its Location permission prompt;
   record unavailable fields instead of guessing. Multiple interfaces require
   selecting the Wi-Fi interface, not an Ethernet/VPN gateway.
3. Connect the phone to the ESP32 management network and open the dashboard.
   Stay connected despite the phone's "no Internet" warning. Keep the tab open.
4. Scan in the dashboard and match the PC's BSSID exactly. This topology lets
   the PC remain a client throughout the test while the phone controls the ESP32.
5. Use the Windows collector below and the common run procedure in section 4.

### B. Phone hotspot, PC as client — useful second AP

1. Enable a 2.4 GHz hotspot on the phone. Android menus vary; select 2.4 GHz if
   offered. On supported iPhones, enable Maximize Compatibility, then verify the
   actual band/channel on Windows. Keep the hotspot settings page visible and
   disable automatic hotspot shutdown if that setting exists.
2. Connect the PC to the phone hotspot. Record BSSID/channel and gateway.
3. Start the Windows collector while connected to the hotspot and record a
   30-second baseline. Screen-record the phone's hotspot client count/list if
   available. Some phones show only a count; save that limitation in notes.
4. To launch an ESP32 job with these two devices, the PC normally must leave
   the hotspot and join the ESP32 management network. Keep its collector running.
   Record that switch as **manual**, scan/select the phone hotspot, and start
   the job. Keep the dashboard tab open.
5. Rejoin the phone hotspot during the job. For this topology, a 30-second
   bounded job leaves time to switch. Record the return time. Observe whether
   the PC can join/stay joined and whether the phone's client count changes.
6. After the deadline, return the PC to the management network and save the
   terminal device log. These manual switches are not evidence of deauthentication.
   This topology is better at testing association/recovery than proving an
   already-connected client was disconnected at the start of a job.

### C. Optional extension of C0: temporarily use the phone as hotspot client

1. Settings → Network & Internet → Mobile hotspot. Give it a recognizable test
   name and choose 2.4 GHz if available. Turn off automatic hotspot shutdown for
   the test if offered. Enable the hotspot and connect the phone.
2. Save a screenshot of the Windows connected-device list and phone Wi-Fi
   details. The hotspot may use a virtual adapter; `netsh wlan show interfaces`
   often describes the PC's upstream client connection, **not** the hotspot.
   Obtain the target hotspot BSSID/channel from the ESP32 scan and identify it
   using the unique test SSID. Do not substitute the upstream router's BSSID.
3. Leave the PC hosting the hotspot and start its collector, normally without
   `-Gateway`. A ping from the host to itself is not a client-connectivity test.
4. With one phone and one PC Wi-Fi adapter, the phone normally must leave the
   hotspot to control the ESP32. Record that deliberate departure. Join the
   management network, select the hotspot and launch a 30-second bounded job.
5. Keep the dashboard tab, switch the phone back to the PC hotspot, and screen-
   record connection attempts/state. Record the join time and whether it remains
   connected. Observe the PC's client list in parallel. The list may lag events.
6. After the deadline reconnect the phone to the management network, reopen the
   same tab and export the final device log. The phone's initial deliberate
   departure is not a test result.

A single adapter generally cannot keep two separate Wi-Fi client associations.
Do not switch the PC away from its upstream network if doing so stops its
hotspot. Do not assume a phone can host its hotspot and join ManagementAP at the
same time. Hardware that supports concurrent modes may differ; document that.

## 3. Capture Windows evidence

Open PowerShell in the folder containing the downloaded collector. For topology
A, replace the example gateway with the one shown by your PC's `ipconfig`:

```powershell
powershell.exe -NoProfile -File .\Collect-WifiEvidence.ps1 -Scenario A-passive-01 -Seconds 180 -Gateway 192.168.1.1
```

For a Windows hotspot host:

```powershell
powershell.exe -NoProfile -File .\Collect-WifiEvidence.ps1 -Scenario C-hotspot-01 -Seconds 180
```

If downloaded scripts are blocked, inspect this script and use the Windows file
Properties → Unblock option if available. Follow any organization execution
policy; the manual commands below are an alternative. The script does not
change execution policy or Wi-Fi settings.

The collector writes a new timestamped folder, with `manifest.json`, `notes.txt`,
driver/IP details, timestamped `samples.jsonl`, and WLAN events where available.
It samples roughly every 2–3 seconds plus command latency; brief disconnects can
fall between samples. Event logs may catch them. Keep the full event message/XML,
not just a numeric event ID. Empty events are not proof nothing happened.
The collector can run without admin; event access or Wi-Fi details may be denied
by local policy and are recorded as unavailable.

Optional richer Windows trace, in **Administrator PowerShell**, before one run:

```powershell
New-Item -ItemType Directory -Force C:\WiFiDebug | Out-Null
netsh trace show scenarios
netsh trace start scenario=WLAN capture=no persistent=no maxsize=256 tracefile=C:\WiFiDebug\A-passive-01.etl
```

Check that trace start succeeds. If another trace already exists, do not stop
someone else's session. If `WLAN` is unavailable on this Windows installation,
keep the regular collector instead. After the test, stop only the trace you
started and generate the PC's station report:

```powershell
netsh trace stop
netsh wlan show wlanreport
netsh trace convert input=C:\WiFiDebug\A-passive-01.etl output=C:\WiFiDebug\A-passive-01.txt dump=TXT report=no
```

Keep the ETL even if conversion fails or produces little readable information.
Copy the report from the location printed by `show wlanreport`, normally
`C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html`.
Use a different ETL filename for each run. A WLAN report covers earlier history
too; identify the exact run time window. It mainly describes the PC as a client,
not a comprehensive list of its hotspot clients. `capture=no` intentionally
collects diagnostic events; changing it to `yes` does not promise raw management
frames on an unsupported adapter.

Manual alternative to the collector:

```powershell
netsh wlan show drivers > drivers.txt
ipconfig /all > ipconfig.txt
1..90 | ForEach-Object {
    [DateTime]::UtcNow.ToString('o')
    netsh wlan show interfaces
    Start-Sleep -Seconds 2
} | Out-File -Encoding utf8 interfaces-timeline.txt
```

## 4. Common procedure for EVERY radio run

1. Create a new scenario name, e.g. `A-passive-01`. Fill in the collector's
   manifest and notes. Save a screenshot of the selected dashboard row, operation,
   method and duration. Select one BSSID only during initial diagnosis.
2. Start the Windows collector and phone screen recording. Observe 30 seconds
   without an ESP32 job. Record whether baseline local ping works. A router or
   hotspot can block ICMP, so a baseline ping failure makes later ping loss
   uninformative. Internet/video buffering is not a reliable association test.
3. Note the UTC start time. For topology A use a 15-second active test, or a
   60-second passive capture. For B/C use 30 seconds if switching is needed.
   Press **Start capture / test**. Initially avoid **Capture & audit**, so capture
   and browser-analysis failures are distinguishable.
4. Observe the client without manually reconnecting unless the scenario calls
   for it. Record association state, BSSID, local ping and automatic reconnection
   separately. Record every manual action explicitly.
5. ManagementAP can disappear while the ESP32 uses its one radio. A dashboard
   disconnect is not proof the target client disconnected. Keep the tab open.
   Without USB, the Stop button may be unreachable during a job: use short device
   deadlines. If you must power-cycle to stop, record it; volatile evidence is lost.
6. After the duration, reconnect to ManagementAP and wait for the terminal
   `complete` or `error` state. Save **device log**, screenshot the result, and
   download **Save PCAP** / **Save PMKID text** if present. Rename artifacts with
   the scenario, boot ID and job ID. Save before starting another job or scan.
7. If the final state is still unavailable after a reasonable recovery interval,
   save what you have and record `inconclusive / terminal status missing`. Do not
   infer a crash from a browser timeout. A different `boot_id` proves a reboot,
   but not whether it was power loss, watchdog, panic or manual reset.
8. Observe client recovery for 30 seconds. Then verify the ESP32 can scan again.
   Repeat useful comparisons up to three times with recovery between runs.
   Stop repeated active tests when a consistent setup error already provides the
   evidence; longer bursts add little diagnostic value.

The browser export retains the last 200 observed status changes. It is not a
full device trace and cannot reconstruct updates while disconnected. Setup
error fields persist in the current job until replacement/reboot; save them
promptly. This branch does not implement a persistent per-SDK-call trace.

## 5. Scenarios and what counts as a result

| ID | Dashboard selection / activity | Expected evidence and interpretation |
| --- | --- | --- |
| S0 | Refresh scan, repeat once | Your 2.4 GHz BSSID/channel appears; scan finishes; dashboard recovers. Missing network may be RF/band/scan visibility, not an attack failure. |
| S1 | Handshake capture → Passive capture only, 60 s | Use topology A. After capture has started, deliberately disconnect/reconnect the PC once to its existing saved network; note both times. Download PCAP and inspect the exchange. This tests reception/parser paths without relying on deauthentication. |
| S2 | Handshake capture → Broadcast deauthentication, 15 s | Keep PC associated; do not manually toggle it in the first run. Compare Windows events with ESP32 log and captured EAPOL. A valid exchange is capture evidence; no exchange alone does not identify a bug or prove no transmission. |
| S3 | Handshake capture → Rogue AP, 15 s | Record setup stage/error, PC association and any capture. A matching visible SSID alone is not proof the ESP32 created it, because the real AP has the same identity. Do not change the client's saved credentials to force a connection. This method is not expected to provide normal Internet service. |
| S4 | PMKID capture → Not applicable, 15 s | Record terminal error/stage or saved PMKID text. A returned PMKID is a capture result, not password recovery. A deadline with no PMKID is inconclusive: APs do not all provide one. PC disconnects are not the success criterion for this mode. |
| S5 | Deauthentication controller → Broadcast deauthentication, 15 s | Keep PC associated on topology A. Record accepted submissions, driver completion results, Windows association events and local ping. Client disconnect observed is an outcome; raw frame receipt remains unknown with this equipment. No disconnect can reflect protection, client behavior or radio issues. |
| S6 | Legacy controller method → Broadcast deauthentication, 15 s | Save setup/terminal state and client observations. Known legacy target-channel and TX-error reporting limitations remain; zero counters or a deadline cannot validate radio success. Keep this separate from S5. |
| S7 | Legacy controller method → Rogue AP, 15 s | Save setup error and subsequent management-network restoration. Existing MAC-change SDK-precondition concerns remain. No disruptive outcome is required to demonstrate a setup failure. |
| S8 | Legacy controller method → Combined, 15 s | Run only after individual methods. Save the first failure stage: `rogue_ap_start` versus `broadcast_start`. A combined result cannot identify which component caused a client outcome without independent evidence. |
| S9 | Offline Audit → Verify a known password | Import your S1 PCAP; enter its exact SSID and your known password locally. Save the parser/exchange and result text, excluding the password. A supported valid pair should verify. One intentionally wrong password should not verify. Unsupported exchange is not a radio failure. |
| S10 | Offline Audit → My wordlist / SSID patterns | For a disposable test hotspot only: use a tiny local list with one deliberately wrong entry and the known test password. Record attempts/result and cancellation behavior. SSID patterns are heuristic: no match is not a bug. Do not upload credentials or use large searches for this functional check. |

For S1, reconnecting the client is deliberate stimulus. For S2/S5, a spontaneous
client disconnect is an observation. Do not combine those two interpretations.
The dashboard's offline verifier supports specific WPA2 HMAC-SHA1 exchange
pairs, not every WPA3/PMF/security variant. The ESP32 handshake PCAP is filtered
for EAPOL; looking for deauthentication frames in that file is not a valid test
of whether they were transmitted.

For your C0 setup, use the matrix to collect software/setup evidence first;
client-dependent success criteria require A, B, C or another connected client.
To compare AP behavior, repeat **S0, S1 and the relevant failing mode** on another
owned AP when practical. Record B/C as an association-during-job test when you had
to leave the target to launch the job. Do not run the entire matrix repeatedly
unless the earlier results justify it.

## 6. Lifecycle / regression comparisons

These often identify bugs more reliably than trying to measure disruption:

1. Passive capture → finish → export → scan → passive capture again.
2. Passive capture → Stop device while reachable → export → start again.
3. Failed mode → export error → scan → passive capture. Does reception recover?
4. Controller → wait for deadline → export → scan → passive capture. Does radio
   ownership/management-network restoration recover?
5. Keep the dashboard tab open, leave/rejoin ManagementAP, and verify the same
   boot/job identity returns. Repeat once with a page reload, after saving any
   existing evidence; lost browser history on reload is expected.
6. Compare a reproducible failure immediately after boot against the same mode
   after another mode. Only reboot after saving the earlier terminal result.

Change one factor at a time. Record firmware, target BSSID/channel, security,
client role, mode/method and preceding operation. Do not weaken PMF/security to
make a test produce a disconnect; protected clients may correctly remain online.

## 7. More evidence from the phone

**Android as client:** screen-record Wi-Fi details before/during/after. Some
phones expose BSSID, frequency and link speed; others do not. If available, turn
on Developer options → Wi-Fi verbose logging, reproduce once, then use Take bug
report and save it promptly. Manufacturer menus and included driver details vary.
Bug reports may be large and contain unrelated personal/system data; keep them
private and extract the Wi-Fi time window for sharing. Disable verbose logging
afterward if you enabled it. This does not require USB, root or ADB.

**Android as hotspot:** record client list/count and any automatic shutdown;
take a bug report if the device offers it. Client lists are not packet captures.

**iPhone:** screen-record Wi-Fi state or Personal Hotspot connection indicators
where visible. Stock iOS does not offer a user-facing complete Wi-Fi frame log.
Record observations honestly; a third-party app cannot necessarily access the
missing driver events. Cellular fallback and cached webpages can hide Wi-Fi loss.

**Phone as ESP32 controller:** save the dashboard log and screenshots to Files /
Downloads. Keep the same tab when returning after a job. The phone disconnecting
from ManagementAP is an expected control-path effect in some modes, not evidence
about the PC's connection to the target AP.

## 8. Save a bundle the next AI agent can use

Put these in each collector folder, then zip the folder:

```text
A-passive-01-<UTC>/
  manifest.json                 # roles, versions, BSSID/channel, boot/job IDs
  notes.txt                     # exact manual actions and observed outcomes
  samples.jsonl                 # Windows association + optional local ping
  wlan-events.jsonl             # when available; keep complete messages/XML
  drivers.txt, ipconfig.txt, collector-status.txt, ended-utc.txt
  esp32-device-log-<boot>-<job>.txt
  scan.png, final-state.png
  capture.pcap                  # handshake runs, if available
  pmkids.txt                    # PMKID run, if available
  phone-screen-recording.mp4    # or timestamped screenshots
  optional-trace.etl, optional-trace.txt, wlan-report-latest.html
  offline-result.txt           # parser/status only; no passwords
```

Add a short summary, using explicit unknowns:

```text
Scenario: A-S5-01
Firmware source commit / image filename:
Topology: router AP; Windows client; phone ESP32 dashboard
Target BSSID / channel / security / advertised PMF:
ESP32 boot_id / job_id / type / method / duration:
UTC baseline start / job start / deadline / recovery:
Manual actions (including network switches):
ESP32 terminal state / reason / error code / error stage:
SDK accepted / driver OK / driver failed / callback registered:
Windows Wi-Fi disconnect observed: yes / no / unknown
Windows event reason and timestamp:
Local ping baseline / during / after:
Peer frame receipt: unknown (no raw receiver capture)
PCAP exchange or PMKID result:
Management network restored / subsequent scan succeeded:
Previous operation and repetitions:
Missing evidence and why:
```

Suggested prompt for an AI agent:

> Correlate this bundle by UTC and ESP32 boot_id/job_id. Separate setup failure,
> packet capture, SDK submission, driver completion, Wi-Fi association and IP
> reachability. Exclude deliberate network switches from attack outcomes. Do not
> infer peer frame receipt from driver counters or ping loss. Identify confirmed
> bugs versus hypotheses and propose the smallest next distinguishing test.

Keep raw originals privately. PCAP/PMKID, ETL, bug reports, SSIDs/MACs and Windows
reports can contain sensitive network/system information. Do not commit test
captures, passwords, wordlists or personal device logs to this public repository.
If redacting identifiers, preserve consistent mappings across all artifacts.

## 9. What changed, and what still needs hardware evidence

The base branch already derives version strings from the running image and
retains handshake setup failures. This change adds equivalent failure code/stage
retention for PMKID and legacy methods, and handles PMKID event-registration
failure without aborting the device. Native regression tests exercise those
paths, exported errors, cleanup and a subsequent healthy run.

It does not fix the known legacy channel-selection/TX-reporting limitations or
the rogue-AP radio-precondition concern, and it does not change raw frame sending.
It does not add a persistent firmware trace or establish the cause of the
original type-4 run with driver completions. Host tests cannot validate the real
ESP32 Wi-Fi driver, antenna, frame delivery or client response.

Pushing source does not update your ESP32. If you cannot flash it, you can use
this guide with the current image, but newly added error fields will only be
useful after installing a firmware build containing these changes. Preserve the
image filename/source SHA and build logs for whoever performs that update.

References: [ESP-IDF Wi-Fi API](https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32/api-reference/network/esp_wifi.html),
[Wireshark WLAN capture limits](https://wiki.wireshark.org/CaptureSetup/WLAN),
[Windows tracing](https://learn.microsoft.com/en-us/windows/win32/ndf/using-netsh-to-manage-traces).
