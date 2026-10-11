import {createSHA1, createHMAC, pbkdf2} from 'hash-wasm';

export const MAX_CAPTURE = 32 * 1024 * 1024;
export const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export function unhex(text) {
  if (!/^(?:[0-9a-f]{2})*$/i.test(text)) throw Error('Invalid hexadecimal bytes');
  return Uint8Array.from(text.match(/../g) || [], b => parseInt(b, 16));
}
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const be16 = (b, i) => b[i] * 256 + b[i + 1];
const nonzero = b => b.some(v => v !== 0);
const llc = unhex('aaaa03000000888e');

export function keyFrame(frame) {
  if (frame.length < 24 || (frame[0] & 15) !== 8 || (frame[0] & 64) ||
      (frame[1] & 68) || (frame[22] & 15)) return null;
  const ds = frame[1] & 3;
  if (ds !== 1 && ds !== 2) return null;
  let offset = 24;
  if (frame[0] & 128) {
    if (frame.length < 26 || (frame[24] & 128)) return null;
    offset += 2 + ((frame[1] & 128) ? 4 : 0);
  }
  if (frame.length < offset + 107 || !equal(frame.subarray(offset, offset + 8), llc)) return null;
  offset += 8;
  const size = 4 + be16(frame, offset + 2);
  if (size < 99 || offset + size > frame.length) return null;
  const eapol = frame.slice(offset, offset + size);
  if (eapol[1] !== 3 || eapol[4] !== 2 || be16(eapol, 97) > size - 99) return null;
  const info = be16(eapol, 5), version = info & 7;
  if (!(info & 8) || (info & 0x0c00)) return null;
  const ack = !!(info & 128), mic = !!(info & 256), fromAP = ds === 2;
  if (ack !== fromAP) return null;
  const nonce = eapol.slice(17, 49);
  const msg = fromAP ? (mic ? 3 : 1) : (mic && !(info & 512) ? 2 : 4);
  if (!nonzero(nonce) || msg === 4) return null;
  return {msg, version, ap: hex(frame.subarray(fromAP ? 10 : 4, fromAP ? 16 : 10)),
    sta: hex(frame.subarray(fromAP ? 4 : 10, fromAP ? 10 : 16)),
    replay: BigInt('0x' + hex(eapol.subarray(9, 17))), nonce, mic: eapol.slice(81, 97), eapol};
}

export function inspectCapture(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length > MAX_CAPTURE) throw Error('Capture exceeds the 32 MiB import limit');
  if (bytes.length < 24 || hex(bytes.subarray(0, 4)) !== 'd4c3b2a1')
    throw Error('Use a classic little-endian PCAP; PCAPNG is not supported');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(4, true) !== 2 || view.getUint16(6, true) !== 4 || view.getUint32(20, true) !== 105)
    throw Error('Use an 802.11 PCAP with linktype 105 (without radiotap)');
  const frames = [], groups = new Map(); let pos = 24, records = 0;
  while (pos < bytes.length) {
    if (bytes.length - pos < 16) throw Error('Truncated PCAP record header');
    const size = view.getUint32(pos + 8, true), original = view.getUint32(pos + 12, true);
    pos += 16;
    if (!size || size > original || size > bytes.length - pos) throw Error('Malformed or truncated PCAP record');
    const key = keyFrame(bytes.subarray(pos, pos + size)); pos += size; records++;
    if (key) {
      frames.push(key);
      const id = `${key.ap}/${key.sta}`;
      if (!groups.has(id)) groups.set(id, []);
      groups.get(id).push(key);
    }
  }
  const pairs = [], seen = new Set();
  for (const messages of groups.values()) {
    const apKeys = new Map();
    for (const key of messages) if (key.version === 2 && (key.msg === 1 || key.msg === 3)) {
      const lookup = `${key.msg}/${key.replay}`;
      if (!apKeys.has(lookup)) apKeys.set(lookup, []);
      const list = apKeys.get(lookup);
      if (!list.some(old => equal(old.nonce, key.nonce))) list.push(key);
    }
    for (const m2 of messages) if (m2.msg === 2 && m2.version === 2) {
      for (const lookup of [`1/${m2.replay}`, `3/${m2.replay + 1n}`]) {
        for (const ap of apKeys.get(lookup) || []) {
          const id = `${ap.ap}/${ap.sta}/${hex(ap.nonce)}/${hex(m2.nonce)}/${hex(m2.eapol)}`;
          if (!seen.has(id)) { seen.add(id); pairs.push({id: String(pairs.length), ap, m2}); }
        }
      }
    }
  }
  return {records, frames: frames.length, unsupported: frames.filter(f => f.version !== 2).length, pairs};
}
export function pairSummary(pair) {
  return {id: pair.id, bssid: pair.ap.ap, station: pair.ap.sta,
    messages: `M${pair.ap.msg}/M2`, replay: pair.m2.replay.toString()};
}

export async function verifyPassword(password, ssid, pair) {
  const pwd = new TextEncoder().encode(password);
  if (pwd.length < 8 || pwd.length > 63 || ssid.length < 1 || ssid.length > 32) return false;
  const pmk = await pbkdf2({password: pwd, salt: ssid, iterations: 4096,
    hashLength: 32, hashFunction: createSHA1(), outputType: 'binary'});
  const a = unhex(pair.ap.ap), b = unhex(pair.m2.sta), n1 = pair.ap.nonce, n2 = pair.m2.nonce;
  const order = (x, y) => hex(x) < hex(y) ? [x, y] : [y, x];
  const blob = new Uint8Array([...order(a, b).flatMap(x => Array.from(x)),
    ...order(n1, n2).flatMap(x => Array.from(x))]);
  const prf = await createHMAC(createSHA1(), pmk);
  const kck = prf.update(new Uint8Array([...new TextEncoder().encode('Pairwise key expansion'), 0, ...blob, 0])).digest('binary').slice(0, 16);
  const packet = pair.m2.eapol.slice(); packet.fill(0, 81, 97);
  const mic = (await createHMAC(createSHA1(), kck)).update(packet).digest('binary').slice(0, 16);
  const matches = equal(mic, pair.m2.mic);
  pmk.fill(0); kck.fill(0); return matches;
}

export function* ssidStems(ssid) {
  const raw = ssid.trim(); if (!raw) return;
  const noAccent = value => value.normalize('NFKD').replace(/\p{M}/gu, '');
  const parts = raw.split(/[\s_.-]+/).flatMap(p => p.match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+/g) || [p]).filter(Boolean);
  const clean = value => value.replace(/[^\p{L}\p{N}]/gu, '');
  const title = value => value.toLowerCase().replace(/(^|[^\p{Cased}])\p{Cased}/gu,
    c => { const chars=Array.from(c), last=chars.pop().toUpperCase(); return chars.join('') + last[0] + last.slice(1).toLowerCase(); });
  const bases = [raw, noAccent(raw), clean(raw), clean(noAccent(raw))];
  if (parts.length) bases.push(parts.join(''), parts.join('-'), parts.join('_'), parts.join(' '),
    parts.map(p => p[0].toUpperCase() + p.slice(1).toLowerCase()).join(''), ...parts.filter(p => p.length >= 4));
  if (parts.length >= 2) bases.push(parts.at(-1) + parts[0]);
  const seen = new Set();
  for (const base of bases) for (const value of [base, base.toLowerCase(), base.toUpperCase(), title(base)])
    if (value && !seen.has(value)) { seen.add(value); yield value; }
}
function* mildLeet(word) {
  for (const [from, to] of [['a','@'],['o','0'],['i','1'],['e','3'],['s','$']]) {
    const i = word.toLowerCase().indexOf(from); if (i >= 0) yield word.slice(0,i) + to + word.slice(i+1);
  }
}
export function* ssidCandidates(ssid) {
  const stems = Array.from(ssidStems(ssid));
  const suffixes = ['', '123','1234','12345','123456','12345678','@','!','@123','123@',
    '2026','2025','2024','2023','2022','2027','2020','2021','2026!','2025!','2024!','@2026','@2025',
    '123!','!123','_2026','_2025','-2026','-2025','0000','1111','123123','321'];
  for (const stem of stems) for (const suffix of suffixes) yield stem + suffix;
  for (const stem of stems) for (const changed of mildLeet(stem)) {
    yield changed; for (const suffix of ['123','1234','@','2026','2025','!']) yield changed + suffix;
  }
  for (const stem of stems) {
    for (const prefix of ['123','2026','2025','wifi','Wifi','WIFI']) yield prefix + stem;
    for (const suffix of ['wifi','WiFi','WIFI','guest','Guest']) yield stem + suffix;
  }
  for (const stem of stems) for (const tail of ['123','1234','2026','2025']) for (const p of ['@','!','#']) {
    yield stem + tail + p; yield stem + p + tail;
  }
}
export function* commonCandidates() {
  yield* ['00000000','12345678','1234554321','123456789','1234567890','987654321','87654321',
    '11111111','22222222','33333333','44444444','55555555','66666666','77777777','88888888','99999999',
    'password','password123','password1','12341234','qwertyuiop','qwerty123','admin123','administrator',
    'internet','wifi1234','welcome123','iloveyou','abcdefgh','abcd1234','passw0rd'];
  for (const base of ['wifi','WiFi','WIFI','internet','password','Password','admin','Admin','welcome','Welcome',
    'hotspot','guest','Guest','tunis','tunisie','Tunisie'])
    for (const suffix of ['123','1234','12345','123456','2026','2025','2024','@123','!123']) yield base + suffix;
  for (let n=0; n<10; n++) yield String(n).repeat(8);
  for (let n=0; n<10; n++) yield String(n).repeat(10);
  for (let n=0; n<10000; n++) { const v = String(n).padStart(4,'0'); yield v+v; yield v+Array.from(v).reverse().join(''); }
}

export async function* wordlistLines(file) {
  let stream = file.stream();
  if (/\.gz$/i.test(file.name || '')) {
    if (typeof DecompressionStream === 'undefined') throw Error('This browser cannot read gzip. Select an uncompressed wordlist.');
    stream = stream.pipeThrough(new DecompressionStream('gzip'));
  }
  const reader = stream.pipeThrough(new TextDecoderStream()).getReader();
  let pending = '', discard = false;
  try {
    while (true) {
      const {value, done} = await reader.read(); if (done) break;
      pending += value;
      let pos;
      while ((pos = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0,pos).replace(/\r$/, '');
        if (!discard && line.length <= 256) yield line;
        discard = false; pending = pending.slice(pos+1);
      }
      if (pending.length > 256) { pending = ''; discard = true; }
    }
    if (pending && !discard) yield pending.replace(/\r$/, '');
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
export async function runAudit({pair, ssid, mode, password, wordlist, maxTries=100000}, progress = () => {}) {
  if (!ssid.length || ssid.length > 32) throw Error('Supply the exact SSID (1–32 bytes)');
  if (!Number.isInteger(maxTries) || maxTries < 1 || maxTries > 1000000) throw Error('Attempt limit must be 1–1,000,000');
  if (!['verify','ssid','wordlist'].includes(mode)) throw Error('Unknown audit mode');
  if (mode === 'wordlist' && !wordlist) throw Error('Select a wordlist file on your phone');
  const seen = new Set(), start = performance.now(); let tested = 0, last = 0;
  async function* candidates() {
    if (mode === 'verify') yield password || '';
    else if (mode === 'wordlist') yield* wordlistLines(wordlist);
    else { yield* ssidCandidates(new TextDecoder().decode(ssid)); yield* commonCandidates(); }
  }
  for await (const candidate of candidates()) {
    const size = new TextEncoder().encode(candidate).length;
    if (size < 8 || size > 63 || seen.has(candidate)) continue;
    if (tested >= maxTries) break;
    seen.add(candidate); tested++;
    const matches = await verifyPassword(candidate, ssid, pair);
    const elapsed = (performance.now()-start)/1000;
    if (matches) return {state: 'match', password: candidate, tested, elapsed};
    if (performance.now()-last >= 250) { progress({tested, elapsed}); last = performance.now(); await new Promise(r => setTimeout(r,0)); }
  }
  return {state: 'no_match', tested, elapsed: (performance.now()-start)/1000};
}
