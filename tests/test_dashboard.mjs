import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile,mkdir} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {chromium} from 'playwright';
import {gzipSync} from 'node:zlib';

const oracle=JSON.parse(execFileSync(process.env.PYTHON || 'python',['tests/make_fixtures.py'],{encoding:'utf8'}));
const fixture=Buffer.from(oracle.cases.m1m2.pcap,'hex');
let job={boot_id:'1234567890abcdef',id:0,state:'idle',type:0,scan_generation:1,elapsed:0,sent:0,tx_errors:0};
let disconnected=false; const submitted=[], errors=[], outside=[];
const server=createServer(async(req,res)=>{
  const path=new URL(req.url,'http://localhost').pathname;
  if(disconnected && path.startsWith('/api/')) {req.socket.destroy();return;}
  let body=''; for await(const chunk of req)body+=chunk;
  const json=value=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));};
  if(path==='/api/v1/device')return json({boot_id:job.boot_id,management_ssid:'ManagementAP'});
  if(path==='/api/v1/networks')return json({scan_generation:1,networks:[{id:0,ssid_hex:Buffer.from('<img src=x onerror=alert(1)>').toString('hex'),
    bssid:'021122334455',channel:1,rssi:-71,security:'WPA2-Personal',pmf:'Supported, optional'}]});
  if(path==='/api/v1/job')return json(job);
  if(path==='/api/v1/jobs') {
    const config=JSON.parse(body);submitted.push(config);
    job={...job,id:job.id+1,state:'running',type:config.type,pcap:false,reason:'',
      timeout:config.timeout,ssid_hex:Buffer.from(oracle.ssid).toString('hex'),bssid:'021122334455'};
    res.statusCode=202;return json(job);
  }
  if(path==='/api/v1/stop') {job={...job,state:'complete',reason:'cancelled'};return json(job);}
  if(path==='/api/v1/capture.pcap') {res.setHeader('Content-Type','application/octet-stream');res.end(fixture);return;}
  if(path==='/api/v1/capture')return json(job);
  const file=path==='/'?'index.html':path.slice(1);
  if(!['index.html','dashboard.js','audit-worker.js','style.css'].includes(file)){res.statusCode=404;res.end();return;}
  res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');
  res.end(await readFile(`web/dist/${file}`));
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
let browser;
try {
  browser=await chromium.launch({headless:true,...(process.env.BROWSER_EXECUTABLE?{executablePath:process.env.BROWSER_EXECUTABLE}:
    process.platform==='win32'?{channel:'msedge'}:{})});
  const page=await browser.newPage({viewport:{width:1100,height:1100}});
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(!request.url().startsWith(`http://127.0.0.1:${server.address().port}/`))outside.push(request.url());});
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.waitForFunction(()=>document.querySelector('#networks input'));
  assert.match(await page.locator('#networks').textContent(),/<img src=x/);
  assert.equal(await page.locator('#networks img').count(),0);
  await page.locator('#import').setInputFiles('build-tests/m1m2.pcap');
  await page.waitForFunction(()=>document.querySelector('#pair').options.length===1 && document.querySelector('#pair').value!=='');
  await page.locator('#ssid').fill(oracle.ssid);await page.locator('#password').fill(oracle.password);
  await page.locator('#start-audit').click();
  await page.waitForFunction(()=>document.querySelector('#audit-state').textContent==='Match');
  assert.match(await page.locator('#audit-result').textContent(),new RegExp(oracle.password));

  // A long local audit and a live radio job remain independent.
  await page.locator('#audit-mode').selectOption('wordlist');
  const words=Array.from({length:10000},(_,i)=>`wrong-word-${i}`).join('\n');
  await page.locator('#wordlist').setInputFiles({name:'words.txt',mimeType:'text/plain',buffer:Buffer.from(words)});
  await page.locator('#start-audit').click();
  await page.locator('#networks input').check();await page.locator('#capture').click();
  await page.waitForFunction(()=>document.querySelector('#device-state').textContent==='running');
  await page.waitForFunction(()=>document.querySelector('#audit-progress').textContent.includes('tested'));
  assert.equal(job.state,'running');
  assert.equal(Object.hasOwn(submitted.at(-1),'password'),false);
  assert.equal(Object.hasOwn(submitted.at(-1),'wordlist'),false);
  disconnected=true;
  await page.waitForFunction(()=>document.querySelector('#connection').textContent==='Reconnecting…');
  assert.equal(await page.locator('#audit-state').textContent(),'Running');
  const before=await page.locator('#audit-progress').textContent();
  await page.waitForFunction(old=>document.querySelector('#audit-progress').textContent!==old,before);
  const start=Date.now();await page.locator('#cancel-audit').click();
  assert.equal(await page.locator('#audit-state').textContent(),'Cancelled');
  assert.ok(Date.now()-start<1000);assert.equal(job.state,'running');
  // A late response from a replaced worker must not resurrect the job.
  await page.waitForTimeout(300);assert.equal(await page.locator('#audit-state').textContent(),'Cancelled');
  disconnected=false;
  await page.waitForFunction(()=>document.querySelector('#connection').textContent==='Device connected');
  await page.locator('#stop-device').click();
  await page.waitForFunction(()=>document.querySelector('#device-state').textContent==='complete');

  // Capture & Audit transfers a completed capture and starts the selected local mode.
  await page.locator('#audit-mode').selectOption('verify');await page.locator('#password').fill(oracle.password);
  await page.locator('#capture-audit').click();
  job={...job,state:'complete',reason:'deadline',pcap:true,hccapx:false,elapsed:1};
  await page.waitForFunction(()=>document.querySelector('#audit-state').textContent==='Match');
  assert.equal(await page.locator('#ssid').inputValue(),oracle.ssid);
  assert.equal(await page.locator('#capture-choice option').count(),3);
  assert.equal(await page.locator('#device-result button').textContent(),'Save PCAP');

  // Gzip wordlist path uses the browser streaming API.
  await page.locator('#audit-mode').selectOption('wordlist');
  await page.locator('#wordlist').setInputFiles({name:'words.txt.gz',mimeType:'application/gzip',buffer:gzipSync(`wrong-pass\n${oracle.password}\n`)});
  await page.locator('#start-audit').click();
  await page.waitForFunction(()=>document.querySelector('#audit-state').textContent==='Match');
  assert.deepEqual(errors,[]);assert.deepEqual(outside,[]);
  await mkdir('build-tests',{recursive:true});
  await page.screenshot({path:'build-tests/dashboard-desktop.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
  await page.screenshot({path:'build-tests/dashboard-mobile.png',fullPage:true});
  console.log('PASS: real browser worker, safe SSID rendering, local password verification, simultaneous radio/audit, reconnection, cancellation, automatic transfer, gzip, no external requests, mobile layout');
} finally {await browser?.close();await new Promise(resolve=>server.close(resolve));}
