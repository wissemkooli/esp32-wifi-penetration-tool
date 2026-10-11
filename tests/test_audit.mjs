import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {gzipSync} from 'node:zlib';
import {createSHA1,createHMAC,pbkdf2} from 'hash-wasm';
import {inspectCapture,verifyPassword,unhex,hex,runAudit,wordlistLines,ssidCandidates,commonCandidates} from '../web/audit-core.js';
const oracle=JSON.parse(execFileSync(process.env.PYTHON || 'python',['tests/make_fixtures.py'],{encoding:'utf8'}));
const vector=await pbkdf2({password:'password',salt:'IEEE',iterations:4096,hashLength:32,hashFunction:createSHA1(),outputType:'hex'});
assert.equal(vector,'f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e');
assert.equal((await createHMAC(createSHA1(),new Uint8Array(20).fill(11))).update('Hi There').digest('hex'),'b617318655057264e28bc0b6fb378c8ef146be00');
for(const [name,fixture] of Object.entries(oracle.cases)) {
  const inspection=inspectCapture(unhex(fixture.pcap));
  assert.equal(inspection.pairs.length,fixture.pairs,name);
  const matches=[];
  for(const pair of inspection.pairs) matches.push(await verifyPassword(oracle.password,new TextEncoder().encode(oracle.ssid),pair));
  assert.deepEqual(matches,fixture.matches,name);
}
assert.deepEqual(Array.from(ssidCandidates('LabNetwork')),oracle.ssid_candidates);
for(const [ssid,candidates] of Object.entries(oracle.pattern_cases))assert.deepEqual(Array.from(ssidCandidates(ssid)),candidates,ssid);
assert.deepEqual(Array.from(commonCandidates()).slice(0,400),oracle.common_candidates);
const data=unhex(oracle.cases.m1m2.pcap), pair=inspectCapture(data).pairs[0], ssid=new TextEncoder().encode(oracle.ssid);
assert.equal(await verifyPassword('wrong-pass',ssid,pair),false);
assert.equal(await verifyPassword(oracle.password,new TextEncoder().encode(oracle.ssid.trim()),pair),false);
for(let length=0;length<data.length;length++) {
  try { const info=inspectCapture(data.slice(0,length)); assert.equal(info.pairs.length,0); }
  catch(error) { assert.match(error.message,/PCAP|truncated|capture/i); }
}
const malformed=data.slice(); new DataView(malformed.buffer).setUint32(32,0xffffffff,true);
assert.throws(()=>inspectCapture(malformed),/Malformed/);
const file=(parts,name)=>{const blob=new Blob(parts);Object.defineProperty(blob,'name',{value:name});return blob;};
const text=`short\r\nwrong-pass\r\n${oracle.password}\n`;
const plain=file([text],'list.txt'), zipped=file([gzipSync(text)],'list.txt.gz');
for(const wordlist of [plain,zipped]) {
  const result=await runAudit({pair,ssid,mode:'wordlist',wordlist,maxTries:10});
  assert.equal(result.state,'match');assert.equal(result.tested,2);assert.equal(result.password,oracle.password);
}
assert.equal((await runAudit({pair,ssid,mode:'wordlist',wordlist:plain,maxTries:1})).state,'no_match');
const overlong=file(['a'.repeat(200000)+'\n'+oracle.password],'large.txt');
const lines=[];for await(const line of wordlistLines(overlong))lines.push(line);
assert.deepEqual(lines,[oracle.password]);
const broken=file([new Uint8Array([1,2,3])],'bad.gz');
await assert.rejects(async()=>{for await(const _ of wordlistLines(broken)){};});
console.log('PASS: independent crypto vectors, Python/browser parity, interleaved/retransmitted pairs, M2/M3, replay mismatch, SSID bytes, malformed captures, streamed gzip and attempt limits');
