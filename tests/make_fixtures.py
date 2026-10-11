"""Independent stdlib WPA2 fixtures and Python/browser parity oracle."""
import hashlib
import hmac
import importlib.util
import itertools
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('wifiaudit', ROOT / 'companion/wifiaudit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
SSID = ' LabNetwork '
PASSWORD = 'lab-test-pass123'
AP = bytes.fromhex('021122334455')
STA = bytes.fromhex('0466778899aa')

def frame(message, station=STA, replay=7, password=PASSWORD, version=2, qos=False):
    from_ap = message in (1,3)
    mac = bytearray(24)
    mac[0] = 0x88 if qos else 8
    mac[1] = 2 if from_ap else 1
    mac[4:10] = station if from_ap else AP
    mac[10:16] = AP if from_ap else station
    mac[16:22] = AP
    nonce_ap, nonce_sta = bytes(range(1,33)), bytes(range(101,133))
    eapol = bytearray(99)
    eapol[0:5] = bytes([2,3,0,95,2])
    info = {1:0x0088,2:0x0108,3:0x13c8,4:0x0308}[message] | version
    eapol[5:7] = info.to_bytes(2,'big')
    eapol[9:17] = replay.to_bytes(8,'big')
    eapol[17:49] = nonce_ap if from_ap else nonce_sta if message==2 else bytes(32)
    if message==2:
        pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), SSID.encode(),4096,32)
        blob = min(AP,station)+max(AP,station)+min(nonce_ap,nonce_sta)+max(nonce_ap,nonce_sta)
        kck = hmac.new(pmk,b'Pairwise key expansion\0'+blob+b'\0',hashlib.sha1).digest()[:16]
        eapol[81:97] = hmac.new(kck,eapol,hashlib.sha1).digest()[:16]
    return bytes(mac)+(bytes(2) if qos else b'')+bytes.fromhex('aaaa03000000888e')+eapol+bytes(4)

def pcap(frames):
    result=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,105)
    for i,data in enumerate(frames):
        result += struct.pack('<IIII',0,i,len(data),len(data))+data
    return result

def main():
    output=ROOT/'build-tests'; output.mkdir(exist_ok=True)
    other=bytes.fromhex('0466778899bb')
    cases={
        'm1m2': [frame(1),frame(2)],
        'interleaved': [frame(1),frame(1,other),frame(2,other,password='another-pass123'),frame(2)],
        'retransmission': [frame(1),frame(1),frame(2),frame(2)],
        'missing_m1': [frame(2),frame(3,replay=8)],
        'mismatch': [frame(1,replay=5),frame(2)],
        'unsupported': [frame(1,version=3),frame(2,version=3)],
        'qos': [frame(1,qos=True),frame(2,qos=True)],
        'wrong_password': [frame(1),frame(2,password='different-pass')]
    }
    result={}
    for name,frames in cases.items():
        data=pcap(frames); path=output/f'{name}.pcap'; path.write_bytes(data)
        _,pairs=audit.collect_pairs(path)
        result[name]={'pcap':data.hex(),'pairs':len(pairs),'matches':[audit.mic_matches(PASSWORD,SSID,*p) for p in pairs]}
    print(json.dumps({'ssid':SSID,'password':PASSWORD,'cases':result,
        'ssid_candidates':list(audit.stage_ssid('LabNetwork')),
        'pattern_cases':{ssid:list(audit.stage_ssid(ssid)) for ssid in ['Home123Router','Café Wi-Fi','SSID_2026',' Straße ']},
        'common_candidates':list(itertools.islice(audit.stage_common(),400))}))
if __name__=='__main__': main()
