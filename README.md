# ESP32 Wi-Fi Penetration Tool

## Unified local fork

One ESP32-hosted website now contains **Networks**, **Capture / Controller**
and **Offline Audit**. The ESP32 handles discovery and timed radio operations;
your phone runs the offline WPA2 audit in a background worker. Passwords and
wordlists stay on the phone. Everyday use requires no computer, Termux or internet.

This fork targets **ESP32 DevKit V1 / ESP32-WROOM-32 with 4 MB flash** and pins
**ESP-IDF v5.5.5**. The build and automated native/browser checks pass.
**Physical board and Android/router tests are still pending.** Existing active
radio methods remain unverified with the new SDK.

Read [the unified workflow, APIs and hardware checklist](doc/UNIFIED_DASHBOARD.md)
and [the original audit and reliability fixes](doc/MODERNIZATION.md).
The upstream feature descriptions and demo below describe the original project.

<p align="center">
    <img src="doc/images/logo.png" alt="Logo">
</p>

## Features
- **PMKID capture**
- **WPA/WPA2 handshake capture** and parsing
- **Deauthentication attacks** using various methods
- **Denial of Service attacks**
- Formatting captured traffic into **PCAP format**
- Parsing captured handshakes into **HCCAPX file** ready to be cracked by Hashcat
- Passive handshake sniffing
- Easily extensible framework for new attacks implementations
- Management AP for easy configuration on the go using smartphone for example
- And more...

### Demo video
[![Demonstration Youtube video](https://img.youtube.com/vi/9I3BxRu86GE/0.jpg)](https://www.youtube.com/watch?v=9I3BxRu86GE)


## Usage
1. [Build](#Build) and [flash](#Flash) project onto ESP32 (DevKit or module)
1. Power ESP32
1. Management AP is started automatically after boot
1. Connect to this AP\
By default: 
*SSID:* `ManagementAP` and *password:* `mgmtadmin`
1. In browser open `192.168.4.1` and you should see a web client to configure and control tool like this:

    Use the three panels described in [the dashboard guide](doc/UNIFIED_DASHBOARD.md).

## Build
Install [ESP-IDF v5.5.5](https://github.com/espressif/esp-idf/releases/tag/v5.5.5)
with its ESP32 tools, then open the ESP-IDF terminal. The build rejects other
SDK versions and chip targets. Install Node 22 or later and run `npm ci`
in this repository first. On Windows, enable Git long paths before
installing SDK submodules: `git config --global core.longpaths true`.

```shell
idf.py -B build-modern -DIDF_TARGET=esp32 build
```

For a clean Linux SDK installation:

```shell
git clone --branch v5.5.5 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32
. ./export.sh
cd /path/to/esp32-wifi-penetration-tool
idf.py -B build-modern -DIDF_TARGET=esp32 build
```

Do not reuse an ESP-IDF 4.1 `sdkconfig` or build directory. Start from this
fork's `sdkconfig.defaults`. Configure management AP credentials under
**Wi-Fi Controller â†’ Management AP** in `idf.py -B build-modern menuconfig`.
The dashboard, worker, bundled WASM and CSS are compressed and embedded
automatically during builds. Daily operation makes no external asset requests.

Host regression checks require Python, GCC and Node.js, independently of IDF.
Install the pinned packages with `npm ci`; on Linux run
`npx playwright install --with-deps chromium`. Windows tests use installed Edge:

```shell
python tests/run_tests.py
# Linux: also enable memory and undefined-behavior checks
python tests/run_tests.py --sanitize
```

The GitHub workflow builds the pinned firmware and runs the sanitized host
checks when pushed. It has not been run remotely for this local fork.

## Flash
In the ESP-IDF terminal, replace `COM5` with your board's serial port:

```shell
idf.py -B build-modern -p COM5 flash monitor
```

On Linux use a port such as `/dev/ttyUSB0`. Leave the serial monitor with
Ctrl+]. Flashing has not been performed automatically.

**The committed binaries in `build/` are upstream's old firmware.** They do
not contain these changes. Use the new `build-modern` output or the prepared
firmware bundle. Its `flash_args` specifies the bootloader at `0x1000`, the
partition table at `0x8000`, and the application at `0x10000` (DIO, 40 MHz,
4 MB). Confirm your module has 4 MB flash before using this layout.

## Documentation
### Wi-Fi attacks
Attacks implementations in this project are described in [main component README](main/). Theory behind these attacks is located in [doc/ATTACKS_THEORY.md](doc/ATTACKS_THEORY.md)
### API reference
This project uses Doxygen notation for documenting components API and implementation. Doxyfile is included so if you want to generate API reference, just run `doxygen` from root directory. It will generate HTML API reference into `doc/api/html`.

### Components
This project consists of multiple components, that can be reused in other projects. Each component has it's own README with detailed description. Here comes brief description of components:

- [**Main**](main) component is entry point for this project. All neccessary initialisation steps are done here. Management AP is started and the control is handed to webserver.
- [**Wifi Controller**](components/wifi_controller) component wraps all Wi-Fi related operations. It's used to start AP, connect as STA, scan nearby APs etc. 
- [**Webserver**](components/webserver) component provides web UI to configure attacks. It expects that AP is started and no additional security features like SSL encryption are enabled.
- [**Wi-Fi Stack Libraries Bypasser**](components/wsl_bypasser) component bypasses Wi-Fi Stack Libraries restriction to send some types of arbitrary 802.11 frames.
- [**Frame Analyzer**](components/frame_analyzer) component processes captured frames and provides parsing functionality to other components.
- [**PCAP Serializer**](components/pcap_serializer) component serializes captured frames into PCAP binary format and provides it to other components (mostly for webserver/UI)
- [**HCCAPX Serializer**](components/hccapx_serializer) component serializes captured frames into HCCAPX binary format and provides it to other components (mostly for webserver/UI)

### Further reading
* [Academic paper about this project (PDF)](https://excel.fit.vutbr.cz/submissions/2021/048/48.pdf)

## Hardware 
This project was mostly build and tested on **ESP32-DEVKITC-32E**
but there should not be any differences for any **ESP32-WROOM-32** modules.

<p align="center">
    <img src="doc/images/soucastky_8b.png" alt="Hw components" width="400">
</p>

On the following pictures you can see a battery (Li-Pol accumulator) powered ESP32 DevKitC using following hardware:
- **ESP32-DEVKITC-32E** (cost 213 CZK/8.2 EUR/9.6 USD)
- 220mAh Li-Pol 3.7V accumulator (weights Â±5g, cost 77 CZK/3 EUR/3.5 USD)
- MCP1702-3302ET step-down 3.3V voltage regulator (cost 11 CZK/0.42 EUR/0.50 USD)
- Czech 5-koruna coin for scale (weights 4.8g, diameter 23 mm, cost 0.19 EUR/0.23 USD)
<p align="center">
    <img src="doc/images/mini.jpg" alt="Hw components" width="300">
    <img src="doc/images/mini2.jpg" alt="Hw components" width="300">
</p>

Altogether (without coin) this setup weights around 17g. This can be further downsized by using smaller Li-Pol accumulator and using ESP32-WROOM-32 modul directly instead of whole dev board.

This setup cost me around 300 CZK (Â± 11.50 EUR/13.50 USD). Using the modul directly that costs around 80 CZK (Â± 3 EUR/3.5 USD) we can get to price of 160 CZK (Â± 6.5 EUR/7.5 USD) which makes this tool really cheap and available to almost everybody.

### Power consumption
Based on experimental measurements, ESP32 consumes around 100mA during attack executions. 

## Similar projects
* [GANESH-ICMC/esp32-deauther](https://github.com/GANESH-ICMC/esp32-deauther)
* [SpacehuhnTech/esp8266_deauther](https://github.com/SpacehuhnTech/esp8266_deauther)
* [justcallmekoko/ESP32Marauder](https://github.com/justcallmekoko/ESP32Marauder)
* [EParisot/esp32-network-toolbox](https://www.tindie.com/products/klhnikov/esp32-network-toolbox/)
* [Jeija/esp32free80211](https://github.com/Jeija/esp32free80211)

## Contributing
Feel free to contribute. Don't hestitate to refactor current code base. Please stick to Doxygen notation when commenting new functions and files. This project is mainly build for educational and demonstration purposes, so verbose documentation is welcome.

## Disclaimer
This project demonstrates vulnerabilities of Wi-Fi networks and its underlaying 802.11 standard and how ESP32 platform can be utilised to attack on those vulnerable spots. Use responsibly against networks you have permission to attack on.

## License
Even though this project is licensed under MIT license (see [LICENSE](LICENSE) file for details), don't be shy or greedy and share your work.
