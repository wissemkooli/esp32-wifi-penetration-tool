"""Build and run the real C parsers/lifecycle with mocked ESP-IDF radio and OS APIs."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sanitize', action='store_true', help='Enable GCC/Clang ASan + UBSan (Linux)')
args = parser.parse_args()
build = ROOT / 'build-tests'
build.mkdir(exist_ok=True)
os.environ['PYTHON'] = sys.executable
subprocess.run(['npm.cmd' if os.name == 'nt' else 'npm', 'run', 'build'], cwd=ROOT, check=True)
subprocess.run([sys.executable, 'tools/embed_assets.py', '--output', str(build / 'web_assets.h')], cwd=ROOT, check=True)
includes = ['tests/stubs', 'tests/support', 'build-tests', 'main', 'components/frame_analyzer/interface',
            'components/hccapx_serializer/interface', 'components/pcap_serializer/interface',
            'components/webserver/interface', 'components/webserver/pages', 'components/wifi_controller']
sources = ['tests/test_core.c', 'tests/support/cJSON.c', 'main/serial_console.c', 'main/attack.c', 'main/attack_handshake.c', 'main/attack_pmkid.c',
           'main/attack_dos.c', 'components/frame_analyzer/frame_analyzer.c',
           'components/frame_analyzer/frame_analyzer_parser.c',
           'components/hccapx_serializer/hccapx_serializer.c',
           'components/pcap_serializer/pcap_serializer.c', 'components/wifi_controller/security_report.c']
exe = build / ('test_core.exe' if os.name == 'nt' else 'test_core')
command = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
           '-Wno-unused-parameter']
if args.sanitize:
    command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
command += [f'-I{path}' for path in includes] + sources + ['-lm', '-o', str(exe)]
subprocess.run(command, cwd=ROOT, check=True)
subprocess.run([str(exe)], cwd=ROOT, check=True)
subprocess.run([sys.executable, 'tools/embed_page.py', '--check'], cwd=ROOT, check=True)
subprocess.run(['node', 'tests/test_audit.mjs'], cwd=ROOT, check=True)
subprocess.run(['node', 'tests/test_dashboard.mjs'], cwd=ROOT, check=True)
