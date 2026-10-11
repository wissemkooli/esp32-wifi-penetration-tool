#!/usr/bin/env python3
"""WiFiAudit 3.0 - menu-driven offline WPA2-Personal audit for authorized networks.

Designed for Termux (no root / Debian / third-party Python dependencies).
Only operates on existing 802.11 PCAP files; never associates with access points.
Supported MIC: WPA2 EAPOL-Key descriptor version 2 HMAC-SHA1, M1/M2 and M2/M3 pairs.

Run `wifiaudit` for an interactive choice of SSID-derived or wordlist testing.
Use `wifiaudit --mode ssid` or `wifiaudit --mode wordlist -w file.txt` to skip the mode menu.
"""
import argparse
import gzip
import getpass
import hashlib
import hmac
import json
import re
import struct
import sys
import time
import unicodedata
from pathlib import Path

VERSION = '3.0.0'
SETTINGS_FILE = Path.home() / '.config' / 'wifiaudit' / 'settings.json'
LLC_EAPOL = bytes.fromhex('aaaa03000000888e')
DEFAULT_MAX_TRIES = 100000


def frames_from_capture(path):
    """Parse EAPOL-Key frames in a classic PCAP, linktype 105 (802.11)."""
    raw = Path(path).read_bytes()
    if len(raw) < 24 or raw[:4] != bytes.fromhex('d4c3b2a1') or struct.unpack_from('<I', raw, 20)[0] != 105:
        raise ValueError('Expected a classic little-endian 802.11 PCAP (linktype 105)')
    frames = []
    pos = 24
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError('Capture exceeds the 32 MiB import limit')
    while pos < len(raw):
        if len(raw) - pos < 16:
            raise ValueError('Truncated PCAP record header')
        _, _, captured_len, original_len = struct.unpack_from('<IIII', raw, pos)
        start = pos + 16
        end = start + captured_len
        if end > len(raw) or captured_len == 0 or captured_len > original_len:
            raise ValueError('Malformed or truncated PCAP record')
        frame = raw[start:end]
        pos = end
        if len(frame) < 24:
            continue
        fc = int.from_bytes(frame[:2], 'little')
        if (frame[0] & 15) != 8 or (frame[0] & 64) or (frame[1] & 68) or (frame[22] & 15):
            continue
        ds = frame[1] & 3
        if ds not in (1, 2):
            continue
        header_len = 24
        if fc & 0x0080:
            if len(frame) < 26 or frame[24] & 128:
                continue
            header_len += 2 + (4 if frame[1] & 128 else 0)
        if len(frame) < header_len + 8 + 99:
            continue
        if frame[header_len:header_len+8] != LLC_EAPOL:
            continue
        eapol = frame[header_len+8:]
        eapol_len = 4 + int.from_bytes(eapol[2:4], 'big')
        if not (99 <= eapol_len <= len(eapol)):
            continue
        eapol = eapol[:eapol_len]
        if eapol[1] != 3 or eapol[4] != 2 or int.from_bytes(eapol[97:99], 'big') > eapol_len - 99:
            continue
        key_info = int.from_bytes(eapol[5:7], 'big')
        if not key_info & 8 or key_info & 0x0c00 or bool(key_info & 128) != (ds == 2):
            continue
        msg = (3 if key_info & 256 else 1) if ds == 2 else (2 if key_info & 256 and not key_info & 512 else 4)
        if msg == 4 or not any(eapol[17:49]):
            continue
        frames.append({'msg':msg, 'src':frame[10:16], 'dst':frame[4:10],
                       'version':key_info & 7, 'replay':int.from_bytes(eapol[9:17], 'big'),
                       'nonce':eapol[17:49], 'mic':eapol[81:97], 'eapol':eapol})
    return frames


def collect_pairs(path):
    frames = frames_from_capture(path)
    pairs, seen, groups = [], set(), {}
    for frame in frames:
        if frame['version'] != 2:
            continue
        ap, sta = (frame['src'], frame['dst']) if frame['msg'] in (1,3) else (frame['dst'],frame['src'])
        groups.setdefault((ap,sta),[]).append(frame)
    for messages in groups.values():
        ap_keys = {}
        for a in messages:
            if a['msg'] in (1,3):
                ap_keys.setdefault((a['msg'],a['replay']),[]).append(a)
        for b in messages:
            if b['msg'] != 2:
                continue
            for lookup in ((1,b['replay']),(3,b['replay']+1)):
                for a in ap_keys.get(lookup,[]):
                    key = (a['src'],b['src'],a['nonce'],b['nonce'],b['eapol'])
                    if key not in seen:
                        seen.add(key)
                        pairs.append((a,b))
    return frames, pairs


def mic_matches(password, ssid, m1, m2):
    pmk = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)
    a, b = m1['src'], m2['src']
    n1, n2 = m1['nonce'], m2['nonce']
    blob = min(a,b) + max(a,b) + min(n1,n2) + max(n1,n2)
    kck = hmac.new(pmk, b'Pairwise key expansion\0' + blob + b'\0', hashlib.sha1).digest()[:16]
    packet = bytearray(m2['eapol'])
    packet[81:97] = b'\0' * 16
    computed = hmac.new(kck, packet, hashlib.sha1).digest()[:16]
    return hmac.compare_digest(computed, m2['mic'])


def load_settings():
    try:
        content = json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
        return content if isinstance(content,dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(**changes):
    settings = load_settings()
    settings.update(changes)
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings,indent=2)+'\n', encoding='utf-8')


def candidate_captures():
    directories = [Path.home()/'storage'/'downloads',Path('/sdcard/Download'),Path.cwd(),Path.home()/'Downloads']
    matches = {}
    for directory in directories:
        if directory.is_dir():
            try:
                for path in directory.iterdir():
                    if path.is_file() and path.suffix.lower() in ('.pcap','.cap'):
                        matches[str(path.resolve())] = path
            except OSError:
                continue
    return sorted(matches.values(),key=lambda p:p.stat().st_mtime, reverse=True)


def latest_usable_capture():
    for path in candidate_captures():
        try:
            _, pairs = collect_pairs(path)
            if pairs:
                return path
        except (OSError,ValueError):
            pass
    return None


def wordlist_paths(explicit=None):
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f'Wordlist not found: {path}')
        return [path]
    # Auto-discover previously downloaded password dictionaries; don't load arbitrary text files.
    rx = re.compile(r'wpa|password|wordlist|rockyou|seclist|weakpass|probable|common', re.I)
    matches = {}
    for directory in (Path.home()/'storage'/'downloads',Path('/sdcard/Download'),Path.cwd()):
        if not directory.is_dir():
            continue
        try:
            for path in directory.iterdir():
                if (path.is_file() and rx.search(path.name) and
                        path.name.lower().endswith(('.txt','.lst','.dic','.txt.gz','.lst.gz','.dic.gz'))):
                    matches[str(path.resolve())] = path
        except OSError:
            continue
    return sorted(matches.values(), key=lambda p:p.stat().st_size)


def load_words(path):
    opener = gzip.open if path.name.lower().endswith('.gz') else open
    with opener(path,'rt',encoding='utf-8',errors='replace') as f:
        for line in f:
            yield line.rstrip('\r\n')


def valid_candidate(word):
    return isinstance(word,str) and 8 <= len(word.encode('utf-8')) <= 63


def remove_accents(word):
    return ''.join(ch for ch in unicodedata.normalize('NFKD',word) if not unicodedata.combining(ch))


def ssid_stems(ssid):
    """Derive only from user's supplied lab SSID, without web profiling."""
    raw = ssid.strip()
    if not raw:
        return []
    # Split spaces/punctuation and CamelCase.
    parts = []
    for part in re.split(r'[\s_.\-]+', raw):
        parts.extend(re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+', part) or [part])
    parts = [x for x in parts if x]
    bases = [raw,remove_accents(raw),re.sub(r'[\W_]+','',raw),re.sub(r'[\W_]+','',remove_accents(raw))]
    if parts:
        bases += [''.join(parts),'-'.join(parts),'_'.join(parts),' '.join(parts),
                  ''.join(p.capitalize() for p in parts)]
        bases += [p for p in parts if len(p) >= 4]
        if len(parts) >= 2:
            bases += [parts[-1]+parts[0]]
    seen = set()
    for b in bases:
        for variant in (b,b.lower(),b.upper(),b.title()):
            if variant and variant not in seen:
                seen.add(variant)
                yield variant


def mild_leet(word):
    swaps = [('a','@'),('o','0'),('i','1'),('e','3'),('s','$')]
    for original,replacement in swaps:
        for i,ch in enumerate(word):
            if ch.lower() == original:
                yield word[:i] + replacement + word[i+1:]
                break  # one substitution per stem, avoid combinatorial explosion


def stage_ssid(ssid):
    """Stream simple capitalization/number/symbol patterns, in likelihood order."""
    stems = list(ssid_stems(ssid))
    suffixes = ['', '123','1234','12345','123456','12345678','@','!','@123','123@',
                '2026','2025','2024','2023','2022','2027','2020','2021',
                '2026!','2025!','2024!','@2026','@2025','123!','!123',
                '_2026','_2025','-2026','-2025', '0000','1111','123123','321']
    # First base variants, then predictable appended suffixes.
    for stem in stems:
        for suffix in suffixes:
            yield stem + suffix
    # Single-character substitutions, variants with prefixes.
    for stem in stems:
        for transformed in mild_leet(stem):
            yield transformed
            for suffix in ('123','1234','@','2026','2025','!'):
                yield transformed + suffix
    for stem in stems:
        for prefix in ('123','2026','2025','wifi','Wifi','WIFI'):
            yield prefix + stem
        for suffix in ('wifi','WiFi','WIFI','guest','Guest'):
            yield stem + suffix
    # A narrow set of two-sided append combinations.
    for stem in stems:
        for tail in ('123','1234','2026','2025'):
            for punct in ('@','!','#'):
                yield stem + tail + punct
                yield stem + punct + tail


def stage_common():
    """Small generic common-password fallback. A sample, not a comprehensive list."""
    basics = ['00000000','12345678','1234554321','123456789','1234567890',
              '987654321','87654321','11111111','22222222','33333333','44444444',
              '55555555','66666666','77777777','88888888','99999999',
              'password','password123','password1','12341234','qwertyuiop',
              'qwerty123','admin123','administrator','internet','wifi1234',
              'welcome123','iloveyou','abcdefgh','abcd1234','passw0rd']
    for candidate in basics:
        yield candidate
    for base in ('wifi','WiFi','WIFI','internet','password','Password',
                 'admin','Admin','welcome','Welcome','hotspot','guest','Guest',
                 'tunis','tunisie','Tunisie'):
        for suffix in ('123','1234','12345','123456','2026','2025','2024','@123','!123'):
            yield base+suffix
    for n in range(10):
        yield str(n)*8
    for n in range(10):
        yield str(n)*10
    for n in range(10000):
        v=str(n).zfill(4)
        yield v+v
        yield v+v[::-1]  # synthetic mirrored number-pattern tests


def choose_mode():
    """Prompt only for a real user choice. Don't silently mix two modes."""
    print('\n' + '=' * 45)
    print('         WiFiAudit | Offline WPA2')
    print('=' * 45)
    print('  1) SSID-based patterns (+ common patterns)')
    print('  2) Existing wordlist (.txt, .lst, .gz)')
    print('  q) Quit')
    while True:
        try:
            choice = input('\nChoose mode [1/2]: ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            print('\nCancelled.')
            return None
        if choice in ('1', 'ssid'):
            return 'ssid'
        if choice in ('2', 'wordlist', 'w'):
            return 'wordlist'
        if choice in ('q', 'quit', 'exit'):
            return None
        print('Enter 1 or 2 (or q to quit).')


def choose_wordlist(explicit=None):
    """Prompt for exactly one file, not silently scan every installed dictionary."""
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f'Wordlist not found: {path}')
        return path
    paths = wordlist_paths()
    print('\nChoose a wordlist:')
    for n, path in enumerate(paths, 1):
        print(f'  {n}) {path.name} ({path.stat().st_size:,} bytes)')
    print('  p) Enter an exact path')
    print('  q) Cancel')
    while True:
        try:
            choice = input('Wordlist [number/p]: ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\nCancelled.')
            return None
        if choice.lower() in ('q', 'quit'):
            return None
        if choice.lower() == 'p':
            try:
                name = input('File path: ').strip()
            except (EOFError, KeyboardInterrupt):
                print('\nCancelled.')
                return None
            path = Path(name).expanduser()
            if path.is_file():
                return path
            print(f'File not found: {path}')
            continue
        if choice.isdigit() and 1 <= int(choice) <= len(paths):
            return paths[int(choice) - 1]
        print('Choose one of the listed numbers, p for a file path, or q.')


def run_audit(capture, ssid, mode, dictionary=None, max_tries=DEFAULT_MAX_TRIES, verify=None, pair_index=0):
    try:
        frames, pairs = collect_pairs(capture)
    except (OSError,ValueError) as exc:
        print(f'Cannot read capture: {exc}',file=sys.stderr)
        return 2
    print(f'\nCapture: {capture}\nSSID: {ssid}\nEAPOL packets: {len(frames)} | usable WPA2 pairs: {len(pairs)}')
    if not pairs or not 0 <= pair_index < len(pairs):
        print('No usable handshake found. Capture again after a client joins your test network.')
        return 2
    if not (1 <= len(ssid.encode('utf-8')) <= 32):
        print('SSID must be between 1 and 32 bytes.',file=sys.stderr)
        return 2
    if verify is not None:
        found = valid_candidate(verify) and mic_matches(verify,ssid,*pairs[pair_index])
        print('Known password verification: '+('MATCH' if found else 'NO MATCH'))
        return 0 if found else 1
    if mode == 'ssid':
        streams = [('SSID variants',stage_ssid(ssid)), ('common patterns',stage_common())]
        print(f'Mode: SSID-based generation | maximum {max_tries:,} guesses')
    elif mode == 'wordlist' and dictionary is not None:
        streams = [(f'Wordlist: {dictionary.name}',load_words(dictionary))]
        print(f'Mode: Wordlist ({dictionary}) | maximum {max_tries:,} guesses')
    else:
        print('Choose a valid mode and wordlist.', file=sys.stderr)
        return 2
    print('Offline-only. Ctrl+C to stop.\n')
    start = time.monotonic()
    tested = 0
    seen = set()
    try:
        for label, stream in streams:
            print(f'[{label}]',flush=True)
            for pwd in stream:
                if not valid_candidate(pwd) or pwd in seen:
                    continue
                if tested >= max_tries:
                    print('Reached configured candidate limit.')
                    print(f'No match after {tested:,} guesses ({time.monotonic()-start:.1f}s).')
                    return 1
                seen.add(pwd)
                tested += 1
                if mic_matches(pwd,ssid,*pairs[pair_index]):
                    print(f'\nMATCH FOUND: {pwd}')
                    print(f'Tested: {tested:,} | Time: {time.monotonic()-start:.1f}s')
                    print(f'Valid MIC for selected pair: {pair_index}')
                    return 0
                if tested % 1000 == 0:
                    elapsed = time.monotonic()-start
                    print(f'  {tested:,} tested | {tested / max(elapsed,.01):.0f} guesses/s | {elapsed:.0f}s',flush=True)
    except KeyboardInterrupt:
        print(f'\nStopped after {tested:,} guesses.')
        return 130
    except (OSError,UnicodeError) as exc:
        print(f'Wordlist read error: {exc}',file=sys.stderr)
        return 2
    print(f'No match after {tested:,} candidates ({time.monotonic()-start:.1f}s).')
    print('No wordlist guarantees recovery. Use a new capture if the password changed.')
    return 1


def main(argv=None):
    p = argparse.ArgumentParser(description='Menu-driven offline WPA2 audit on Termux (no root or Debian).')
    p.add_argument('-c','--capture',help='PCAP (newest usable capture in Downloads by default)')
    p.add_argument('-s','--ssid',help='Exact network SSID, including capitalization and spaces')
    p.add_argument('-m','--mode',choices=('ssid','wordlist'),help='Skip the interactive menu')
    p.add_argument('-w','--wordlist',help='Specific wordlist; automatically sets mode to wordlist')
    p.add_argument('--max-tries',type=int,default=DEFAULT_MAX_TRIES,help=f'Offline guess budget (default: {DEFAULT_MAX_TRIES:,})')
    p.add_argument('--verify',action='store_true',help='Verify one known password, entered privately')
    p.add_argument('--pair',type=int,default=0,help='Select a zero-based handshake pair (default: 0)')
    p.add_argument('--list-captures',action='store_true',help='List PCAP captures found in Downloads')
    p.add_argument('--reset',action='store_true',help='Reset saved SSID')
    p.add_argument('--version',action='version',version=f'wifiaudit {VERSION}')
    args=p.parse_args(argv)
    if args.reset:
        SETTINGS_FILE.unlink(missing_ok=True)
        print('Saved SSID cleared.')
        return 0
    if args.list_captures:
        for path in candidate_captures():
            print(path)
        return 0
    if args.max_tries < 1:
        p.error('--max-tries must be positive')
    if args.mode == 'ssid' and args.wordlist:
        p.error('--wordlist cannot be combined with --mode ssid')

    # Always prompt for mode in the interactive CLI, unless a mode was passed explicitly.
    mode = 'wordlist' if args.wordlist else args.mode
    if not args.verify and mode is None:
        mode = choose_mode()
        if mode is None:
            return 0

    dictionary = None
    if mode == 'wordlist' and not args.verify:
        try:
            dictionary = choose_wordlist(args.wordlist)
        except (OSError,ValueError) as exc:
            print(exc, file=sys.stderr)
            return 2
        if dictionary is None:
            return 0

    remembered=load_settings()
    capture=Path(args.capture).expanduser() if args.capture else latest_usable_capture()
    if capture is None:
        print('No usable WPA2 handshake capture found in Downloads. Supply -c /path/to/file.pcap.',file=sys.stderr)
        return 2
    prior_capture = remembered.get('capture')
    same_capture = prior_capture == str(capture.resolve())
    ssid=args.ssid or (remembered.get('ssid') if same_capture else None)
    if not ssid:
        try:
            ssid=input('Exact SSID of your test router: ')
        except (EOFError,KeyboardInterrupt):
            print('\nCancelled.')
            return 130
    if not ssid:
        print('SSID required.',file=sys.stderr)
        return 2
    save_settings(ssid=ssid, capture=str(capture.resolve()))
    password=getpass.getpass('Known test password (not saved): ') if args.verify else None
    return run_audit(capture, ssid, mode, dictionary, args.max_tries, password, args.pair)


if __name__ == '__main__':
    sys.exit(main())
