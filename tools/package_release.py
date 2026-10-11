"""Package a verified local unified source/firmware release; never flash or publish."""
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build-modern'
OUTPUT = ROOT.parent / 'deliverables'
OUTPUT.mkdir(exist_ok=True)
sha = lambda data: hashlib.sha256(data).hexdigest()

test_log = (ROOT / 'build-tests/unified-tests.log').read_text(encoding='utf-8')
build_log = (BUILD / 'unified-build.log').read_text(encoding='utf-8')
if any(marker not in test_log for marker in ['All core regression tests passed.', 'PASS: actual controller', 'PASS: real browser worker', 'PASS: independent crypto vectors']):
    raise SystemExit('Run the complete regression suite and retain build-tests/unified-tests.log first')
if 'Project build complete.' not in build_log:
    raise SystemExit('Complete the firmware build and retain build-modern/unified-build.log first')

names = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],cwd=ROOT,text=True).splitlines()
names += [p.relative_to(ROOT).as_posix() for p in (ROOT/'web/dist').glob('*') if p.is_file()]
names = sorted({name for name in names if not name.startswith('build/') and (ROOT/name).is_file()})
contents = {name:(ROOT/name).read_bytes() for name in names}
source_checksums = ''.join(f'{sha(data)}  {name}\n' for name,data in contents.items())
source_zip = OUTPUT/'esp32-unified-source.zip'
with zipfile.ZipFile(source_zip,'w',zipfile.ZIP_DEFLATED) as archive:
    for name,data in contents.items(): archive.writestr('esp32-wifi-penetration-tool/'+name,data)
    archive.writestr('esp32-wifi-penetration-tool/SOURCE_SHA256SUMS.txt',source_checksums)

files = ['esp32-wifi-penetration-tool.bin','bootloader/bootloader.bin','partition_table/partition-table.bin','flash_args','flasher_args.json']
payloads = {name:(BUILD/name).read_bytes() for name in files}
for source,target in [('LICENSE','licenses/PROJECT-LICENSE'),('web/vendor/HASH-WASM-LICENSE','licenses/HASH-WASM-LICENSE'),('tests/support/cJSON-LICENSE','licenses/CJSON-LICENSE')]:
    payloads[target]=(ROOT/source).read_bytes()
for file in (ROOT/'licenses').glob('*'): payloads['licenses/'+file.name]=file.read_bytes()
for name in ['UNIFIED_DASHBOARD.md','MODERNIZATION.md']:
    payloads['doc/'+name]=(ROOT/'doc'/name).read_bytes()
payloads['verification/host-tests.txt']=test_log.encode()
payloads['verification/firmware-build.log']=build_log.encode()
tree = hashlib.sha256()
for name,data in contents.items(): tree.update(name.encode()+b'\0'+data+b'\0')
manifest = {
    'release':'unified-1.0.1','target':'esp32','board':'ESP32-WROOM-32 / DevKit V1','flash_mb':4,
    'idf_version':'v5.5.5','idf_commit':'b774170ff46c393eeb5e495ea37936038d3f4f4f',
    'local_sdk_note':'OpenThread submodule has a Windows checkout change; this Wi-Fi firmware does not build OpenThread.',
    'hash_wasm':'4.12.0','upstream_commit':'e346e28ed9c93e98ab686c30eb8c4bc549313ba3','local_changes':True,
    'source_tree_sha256':tree.hexdigest(),'source_archive_sha256':sha(source_zip.read_bytes()),
    'application_bytes':len(payloads[files[0]]),'application_partition_bytes':0x177000,
    'verification':{'firmware_build':'passed','native_c_tests':'passed','python_browser_parity':'passed',
        'real_browser_workflow':'passed on desktop Edge/Chromium','physical_devkit_v1':'pending',
        'android_chrome':'pending','active_radio_methods':'unverified','remote_ci':'not run','linux_sanitizers':'not run locally'}}
payloads['README.md']=b'''# Unified ESP32 Wi-Fi Audit firmware 1.0.1 (diagnostics)

For classic ESP32-WROOM-32 / DevKit V1 with 4 MB flash, ESP-IDF v5.5.5.
Software build/tests passed; physical ESP32, Android and router tests are pending.
Existing active radio methods remain unverified. See doc/UNIFIED_DASHBOARD.md.
The 1.0 preview has reported zero accepted transmissions on a user's board.
This update records the actual SDK error and stops on the first failure;
it does not establish deauthentication compatibility with ESP-IDF 5.5.5.

## Flash

Extract the ZIP, open a terminal in it, confirm 4 MB flash and replace COM5
with your board's port. Install Python and the pinned flash tool if needed:

```shell
python -m pip install esptool==4.12.0
python -m esptool --chip esp32 -p COM5 -b 115200 --before default_reset --after hard_reset write_flash "@flash_args"
```

If connecting fails, hold BOOT during connection, release when writing begins.
Linux uses a port such as /dev/ttyUSB0. All three matched files are required:
bootloader at 0x1000, partition table at 0x8000, application at 0x10000.
Flash settings: DIO / 40 MHz / 4 MB. The application alone is not a first-flash bundle.
Flashing has not been performed automatically.

## Use

Connect Android Chrome to ManagementAP (password mgmtadmin), open
http://192.168.4.1 and keep the page open. No Termux, computer or internet is
needed for daily operation. Start with passive capture on your own WPA2 network.
Completed PCAPs transfer automatically. Choose an exchange, exact SSID and local
password/wordlist; Capture & audit can start the configured audit automatically.
Passwords and wordlists stay on the phone. Gzip wordlists are supported.

Channel changes can interrupt contact. Reconnect to ManagementAP if the phone
switches networks; the device keeps its deadline and the page retries.
Cancel audit stops only the local worker. Stop device stops only the radio.
Save files before reloading: captures and results are held in browser memory.

SHA256SUMS.txt verifies every packaged payload. manifest.json links the matching
source bundle and records verification limits. Licenses are included.
'''
manifest['files_sha256']={name:sha(data) for name,data in payloads.items()}
payloads['manifest.json']=(json.dumps(manifest,indent=2)+'\n').encode()
payloads['SHA256SUMS.txt']=''.join(f'{sha(data)}  {name}\n' for name,data in payloads.items()).encode()
firmware_zip=OUTPUT/'esp32-wroom32-unified-firmware.zip'
with zipfile.ZipFile(firmware_zip,'w',zipfile.ZIP_DEFLATED) as archive:
    for name,data in payloads.items(): archive.writestr(name,data)
for file in [source_zip,firmware_zip]:
    with zipfile.ZipFile(file) as archive:
        assert archive.testzip() is None
        if file==firmware_zip:
            for name,checksum in manifest['files_sha256'].items(): assert sha(archive.read(name))==checksum
    print(f'{file.name}: {file.stat().st_size} bytes; SHA256 {sha(file.read_bytes())}; verified')
(OUTPUT/'UNIFIED_SHA256SUMS.txt').write_text(''.join(f'{sha(file.read_bytes())}  {file.name}\n' for file in [source_zip,firmware_zip]),encoding='utf-8')
