import {inspectCapture, pairSummary, runAudit, unhex} from './audit-core.js';
let capture;
self.onmessage = async ({data}) => {
  const {id, action} = data;
  const send = message => self.postMessage({id, ...message});
  try {
    if (action === 'inspect') {
      capture = inspectCapture(data.buffer);
      send({event: 'inspection', records: capture.records, frames: capture.frames,
        unsupported: capture.unsupported, pairs: capture.pairs.map(pairSummary)});
    } else if (action === 'audit') {
      const pair = capture?.pairs.find(p => p.id === data.pairId);
      if (!pair) throw Error('Select a usable WPA2 handshake exchange');
      const result = await runAudit({...data, pair, ssid: unhex(data.ssidHex)}, p => send({event: 'progress', ...p}));
      send({event: 'result', ...result});
    } else throw Error('Unknown worker action');
  } catch (error) { send({event: 'error', message: error.message}); }
};
