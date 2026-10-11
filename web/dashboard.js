const $ = id => document.getElementById(id);
const text = (id, value) => { $(id).textContent = value; };
const decode = hex => new TextDecoder().decode(Uint8Array.from(hex.match(/../g) || [], b => parseInt(b,16)));
const encode = value => Array.from(new TextEncoder().encode(value), b => b.toString(16).padStart(2,'0')).join('');
let device, job, scanGeneration = 0, lastScan = -1, networkRows = [], pollTimer, offline = false;
let worker, workerEpoch = 0, requestSequence = 0, workerRequest = '', auditing = false, inspecting = false;
let captureSequence = 0, activeCapture, auditSsidHex = '', ssidDisplay = '', autoOptions;
const captures = new Map(), fetched = new Set(), pendingAudit = new Map(), auditQueue = [];
const deviceLog = [];
let lastDeviceLog = '';
function recordDeviceLog() {
  const fields=['boot_id','id','state','type','method','timeout','sent','tx_errors','channel_errors',
    'reason','radio_error_code','radio_error_name','radio_error_stage','current_target','targets','channel'];
  const snapshot=Object.fromEntries(fields.filter(key=>job[key]!==undefined).map(key=>[key,job[key]]));
  const signature=JSON.stringify(snapshot);
  if (signature===lastDeviceLog) return;
  lastDeviceLog=signature;
  deviceLog.push(`${new Date().toISOString()} elapsed=${Number(job.elapsed || 0).toFixed(3)}s ${signature}`);
  if (deviceLog.length>200) deviceLog.shift();
}
function saveDeviceLog() {
  const header=['Wi-Fi Audit device diagnostics',`Exported: ${new Date().toISOString()}`,
    `Firmware: ${device?.firmware || 'unknown'}`,`Chip: ${device?.chip || 'unknown'}`,
    `ESP-IDF: ${device?.idf_version || 'unknown'}`,
    'Browser-observed job status (last 200 changes); full boot/SDK logs require USB serial.',
    'Passwords, wordlists and offline audit results are excluded.',''];
  download(new Blob([[...header,...deviceLog].join('\n')+'\n'],{type:'text/plain;charset=utf-8'}),
    `esp32-device-log-${job?.boot_id || 'unknown'}-${job?.id || 0}.txt`);
}
function badge(id, label, state='') { text(id,label); $(id).className = `badge ${state}`; }
function message(value='') { text('message',value); }
async function request(path, options={}, binary=false) {
  const response = await fetch(path, {...options, cache:'no-store', signal:AbortSignal.timeout(12000)});
  if (!response.ok) { const error=Error((await response.text()) || `Device request failed (${response.status})`); error.status=response.status; throw error; }
  return binary ? response.arrayBuffer() : response.json();
}
const post = (path, data) => request(path,{method:'POST', headers:{'Content-Type':'application/json'}, body:data ? JSON.stringify(data) : undefined});
const identity = value => `${value.boot_id}/${value.id}`;
const busy = () => job && ['running','scanning','stopping'].includes(job.state);
function controls() {
  for (const id of ['scan','capture','capture-audit']) $(id).disabled = offline || busy();
  $('stop-device').disabled = offline || !busy() || job.state === 'scanning' || job.state === 'stopping';
  $('start-audit').disabled = auditing || inspecting || !$('pair').value;
  $('cancel-audit').disabled = !auditing && !inspecting;
  $('save-capture').disabled = !activeCapture;
  $('save-device-log').disabled = !deviceLog.length;
  for (const id of ['capture-choice','import','pair']) $(id).disabled = auditing || inspecting;
}
function operationFields() {
  const operation = Number($('operation').value), select = $('method'); select.replaceChildren();
  const methods = operation === 1 ? [[2,'Passive capture only'],[1,'Broadcast deauthentication'],[0,'Rogue AP']] :
    operation === 3 ? [[0,'Rogue AP'],[1,'Broadcast deauthentication'],[2,'Combined']] : [[0,operation===4?'Broadcast deauthentication':'Not applicable']];
  for (const [value,label] of methods) select.add(new Option(label,String(value)));
  select.disabled = operation === 2 || operation === 4;
  $('capture-audit').hidden = operation !== 1;
}
function auditFields() {
  $('password-field').hidden = $('audit-mode').value !== 'verify';
  $('wordlist-field').hidden = $('audit-mode').value !== 'wordlist';
}
function auditConfig() {
  const mode = $('audit-mode').value, maxTries = Number($('max-tries').value);
  if (!Number.isInteger(maxTries) || maxTries < 1 || maxTries > 1000000) throw Error('Attempt limit must be 1–1,000,000');
  const wordlist = $('wordlist').files[0], password = $('password').value;
  if (mode === 'wordlist' && !wordlist) throw Error('Select your wordlist before starting');
  if (mode === 'verify' && (new TextEncoder().encode(password).length < 8 || new TextEncoder().encode(password).length > 63))
    throw Error('Known WPA2 password must be 8–63 bytes');
  return {mode,maxTries,wordlist,password};
}
async function networks() {
  const report = await request('/api/v1/networks'); scanGeneration = report.scan_generation; lastScan = scanGeneration;
  networkRows = report.networks; $('networks').replaceChildren();
  for (const ap of networkRows) {
    const row = document.createElement('tr'), cell = document.createElement('td'), check = document.createElement('input');
    check.type='checkbox'; check.value=String(ap.id); check.setAttribute('aria-label',`Select ${decode(ap.ssid_hex) || 'hidden network'}`);
    cell.append(check); row.append(cell);
    for (const value of [decode(ap.ssid_hex) || '(hidden)',ap.channel,`${ap.rssi} dBm`,ap.security,ap.pmf]) {
      const td = document.createElement('td'); td.textContent=String(value);
      if (row.children.length === 1) { const mac=document.createElement('small'); mac.textContent=ap.bssid.match(/../g).join(':'); td.append(mac); }
      row.append(td);
    }
    $('networks').append(row);
  }
  text('network-status',`${networkRows.length} networks · select one for a capture, up to eight for the controller.`);
}
function selectedTargets() { return Array.from($('networks').querySelectorAll('input:checked'), input => Number(input.value)); }
async function startCapture(withAudit) {
  try {
    message(); const targets=selectedTargets(), type=Number($('operation').value), timeout=Number($('duration').value);
    if (!targets.length || targets.length > 8 || (type !== 4 && targets.length !== 1)) throw Error('Select one network for capture, or up to eight for the controller');
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 255) throw Error('Duration must be 1–255 seconds');
    const config=withAudit ? auditConfig() : null;
    job = await post('/api/v1/jobs',{boot_id:device.boot_id, targets,type,method:Number($('method').value),timeout,scan_generation:scanGeneration});
    if (config) pendingAudit.set(identity(job),config);
    renderJob(); schedulePoll(250);
  } catch (error) { message(error.message); }
}
function renderJob() {
  recordDeviceLog();
  badge('device-state',job.state,busy()?'busy':job.state==='error'?'offline':'');
  const error=job.radio_error_code ? ` · ${job.radio_error_stage}: ${job.radio_error_name} (0x${(job.radio_error_code >>> 0).toString(16)}) · target ${(job.current_target || 0)+1}` : '';
  text('device-progress',`${job.state} · ${(job.elapsed || 0).toFixed(1)} s · sent ${job.sent || 0} · TX errors ${job.tx_errors || 0} · channel errors ${job.channel_errors || 0}${job.reason ? ' · '+job.reason : ''}${error}`);
  text('radio-hint',job.type===4 && busy() ?
    `ManagementAP pauses during this controller test. It returns when the job ends, within the ${job.timeout}-second limit. Keep this page open and reconnect afterward. While disconnected, use USB serial Stop or reset the board to end it early.` :
    'The radio runs one operation at a time. During controller tests, ManagementAP pauses until the job ends. Keep this page open and reconnect to ManagementAP afterward. The device stops at its own time limit.');
  controls();
}
const schedulePoll = (delay=1000) => { clearTimeout(pollTimer); pollTimer=setTimeout(poll,delay); };
async function poll() {
  try {
    const next=await request('/api/v1/job'); offline=false; badge('connection','Device connected','ok');
    if(!device)device=await request('/api/v1/device');
    if (device && next.boot_id !== device.boot_id) {
      pendingAudit.clear(); lastScan=-1; device=await request('/api/v1/device'); message('Device restarted. Saved captures on this page remain available.');
    }
    job=next; renderJob();
    if (job.state !== 'scanning' && job.scan_generation !== lastScan) await networks();
    const key=identity(job);
    if (!busy() && !fetched.has(key)) {
      if (job.pcap) {
        const query=`boot_id=${job.boot_id}&id=${job.id}`;
        const buffer=await request(`/api/v1/capture.pcap?${query}`,{},true);
        const metadata=await request(`/api/v1/capture?${query}`);
        addCapture({key,buffer,metadata,name:`Capture ${job.id} · ${decode(metadata.ssid_hex || '') || metadata.bssid}`},pendingAudit.get(key));
      }
      fetched.add(key); pendingAudit.delete(key); renderResult();
    }
  } catch (error) {
    if(error.status) {
      if(error.status===404 && job) { fetched.add(identity(job)); pendingAudit.delete(identity(job)); }
      message(error.message); controls(); return;
    }
    offline=true; badge('connection','Reconnecting…','offline'); controls();
    text('device-progress','Live device contact is unavailable. The device keeps its own time limit. Reconnect to ManagementAP if your phone changed networks. Offline auditing can continue.');
  } finally { schedulePoll(); }
}
function download(blob,name) {
  const url=URL.createObjectURL(blob), link=document.createElement('a'); link.href=url; link.download=name; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
}
$('save-device-log').addEventListener('click',saveDeviceLog);
function renderResult() {
  $('device-result').replaceChildren();
  if (job.pcap && captures.has(identity(job))) {
    const button=document.createElement('button'); button.textContent='Save PCAP'; button.onclick=()=>download(new Blob([captures.get(identity(job)).buffer]),'capture.pcap'); $('device-result').append(button);
    if (job.hccapx) { const link=document.createElement('a'); link.href=`/api/v1/capture.hccapx?boot_id=${job.boot_id}&id=${job.id}`; link.textContent=' Download HCCAPX (legacy)'; $('device-result').append(link); }
  }
  if (job.pmkids) {
    const pre=document.createElement('pre'); pre.textContent=job.pmkids.length ? job.pmkids.map(p=>`${p}*${job.pmkid_bssid}*${job.station}*${job.ssid_hex}`).join('\n') : 'No PMKID observed. The browser audit uses WPA2 handshake captures.';
    $('device-result').append(pre);
    if(job.pmkids.length) {
      const button=document.createElement('button'); button.textContent='Save PMKID text';
      button.onclick=()=>download(new Blob([pre.textContent+'\n'],{type:'text/plain'}),'pmkids.txt'); $('device-result').append(button);
    }
  }
}
function addCapture(capture, config) {
  captures.set(capture.key,capture); $('capture-choice').add(new Option(capture.name,capture.key));
  if (config && (auditing || inspecting)) { auditQueue.push({capture,config}); text('inspection','New capture received; its requested audit is queued.'); }
  else if (!auditing && !inspecting) loadCapture(capture,config);
}
function newWorker() {
  worker?.terminate(); const epoch=++workerEpoch;
  worker=new Worker('/audit-worker.js');
  worker.onerror=error=>{ if(epoch!==workerEpoch)return; inspecting=auditing=false; autoOptions=null; text('audit-progress',`Audit engine failed: ${error.message}`); badge('audit-state','Error','offline'); controls(); nextAudit(); };
  worker.onmessage=({data})=>{
    if(epoch!==workerEpoch || data.id!==workerRequest)return;
    if(data.event==='inspection') {
      inspecting=false; $('pair').replaceChildren();
      for(const pair of data.pairs) $('pair').add(new Option(`${pair.bssid} · client ${pair.station} · ${pair.messages}`,pair.id));
      text('inspection',`${data.records} records · ${data.frames} key frames · ${data.pairs.length} usable exchanges${data.unsupported ? ' · unsupported descriptor versions present' : ''}`);
      badge('audit-state',data.pairs.length?'Ready':'No usable pair');
      if(!data.pairs.length) text('audit-progress','No supported WPA2 exchange. Capture again or select another PCAP.');
      controls(); const config=autoOptions; autoOptions=null;
      if(config && data.pairs.length) startAudit(config); else nextAudit();
    } else if(data.event==='progress') {
      text('audit-progress',`${data.tested.toLocaleString()} tested · ${data.elapsed.toFixed(1)} s · ${(data.tested/Math.max(data.elapsed,.01)).toFixed(0)} attempts/s`);
    } else if(data.event==='result') {
      auditing=false; badge('audit-state',data.state==='match'?'Match':'No match',data.state==='match'?'ok':'');
      text('audit-progress',`${data.tested.toLocaleString()} tested in ${data.elapsed.toFixed(1)} s`);
      text('audit-result',data.state==='match'?`Password matched the selected exchange: ${data.password}`:'No match within the selected candidates and attempt limit.');
      controls(); nextAudit();
    } else if(data.event==='error') {
      inspecting=auditing=false; autoOptions=null; badge('audit-state','Error','offline'); text('audit-progress',data.message); controls(); nextAudit();
    }
  };
}
function loadCapture(capture, config) {
  activeCapture=capture; autoOptions=config; $('capture-choice').value=capture.key;
  $('pair').replaceChildren();
  auditSsidHex=capture.metadata.ssid_hex || ''; ssidDisplay=decode(auditSsidHex); $('ssid').value=ssidDisplay;
  text('audit-result',''); inspecting=true; badge('audit-state','Inspecting','busy'); controls();
  newWorker(); workerRequest=String(++requestSequence); worker.postMessage({id:workerRequest,action:'inspect',buffer:capture.buffer.slice(0)});
}
function startAudit(config) {
  try {
    if(auditing || inspecting)return;
    if(!activeCapture || !$('pair').value)throw Error('Select a usable handshake exchange');
    config ||= auditConfig();
    const ssidHex=$('ssid').value===ssidDisplay && auditSsidHex ? auditSsidHex : encode($('ssid').value);
    if(!ssidHex.length || ssidHex.length>64)throw Error('Supply the exact SSID (1–32 bytes)');
    auditing=true; workerRequest=String(++requestSequence); badge('audit-state','Running','busy');
    text('audit-result',''); text('audit-progress','Starting local audit…'); controls();
    worker.postMessage({id:workerRequest,action:'audit',pairId:$('pair').value,ssidHex,...config});
  } catch(error) { message(error.message); }
}
function nextAudit() { if(!auditing && !inspecting && auditQueue.length) { const {capture,config}=auditQueue.shift(); loadCapture(capture,config); } }
function cancelAudit() {
  worker?.terminate(); worker=null; ++workerEpoch; workerRequest=''; auditing=inspecting=false;
  autoOptions=null; auditQueue.length=0; pendingAudit.clear(); $('pair').replaceChildren();
  badge('audit-state','Cancelled'); text('audit-progress','Audit cancelled. Device operation is unchanged. Select the capture again to restart.'); controls();
}
$('scan').onclick=async()=>{try{job=await post('/api/v1/scan');renderJob();schedulePoll(250);}catch(error){message(error.message);}};
$('capture').onclick=()=>startCapture(false); $('capture-audit').onclick=()=>startCapture(true);
$('stop-device').onclick=async()=>{try{job=await post('/api/v1/stop',{boot_id:job.boot_id,id:job.id});renderJob();}catch(error){message(error.message);}};
$('operation').onchange=operationFields; $('audit-mode').onchange=auditFields;
$('start-audit').onclick=()=>startAudit(); $('cancel-audit').onclick=cancelAudit;
$('save-capture').onclick=()=>{if(activeCapture)download(new Blob([activeCapture.buffer]),'capture.pcap');};
$('capture-choice').onchange=()=>{const capture=captures.get($('capture-choice').value);if(capture&&!auditing&&!inspecting)loadCapture(capture);};
$('import').onchange=async()=>{try{
  const file=$('import').files[0]; if(!file)return;
  if(file.size>32*1024*1024)throw Error('Capture exceeds the 32 MiB import limit');
  const capture={key:`import/${++captureSequence}`,name:file.name,buffer:await file.arrayBuffer(),metadata:{}};
  addCapture(capture); $('import').value='';
}catch(error){message(error.message);}};
operationFields(); auditFields(); controls();
(async()=>{try{device=await request('/api/v1/device');await poll();}catch(error){offline=true;badge('connection','Reconnecting…','offline');schedulePoll();}})();
