// Live ownership lifecycle: runs only our generated PE, including a bounded spin.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildPE64Fixture } from './fixtures/pe64.mjs';
import { runtimeConfiguration } from '../engine_runtime.js';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const runtime = runtimeConfiguration().x64dbg;
assert.equal(runtime.available, true, runtime.reason);
const cfgPath = runtime.manifest;
const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8').replace(/^\uFEFF/, ''));
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-x64dbg-cleanup-'));
const target = path.join(temp, 'generated-spin.exe'); fs.writeFileSync(target, buildPE64Fixture().image);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
async function gone(pids) {
  const end = Date.now() + 5000;
  while (pids.some(alive) && Date.now() < end) await delay(50);
  assert.deepEqual(pids.filter(alive), [], 'owned process tree must be gone');
}
function client() {
  const child = spawn(path.resolve(path.dirname(cfgPath), cfg.pythonExe), ['-I', '-B', path.join(root, 'adapters/x64dbg/adapter.py')], {
    windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, IG5_X64DBG_RUNTIME: cfgPath, IG5_X64DBG_STATE_ROOT: path.join(temp, 'state') },
  });
  const pending = new Map(); let seq = 0, buffer = '', readyResolve;
  const ready = new Promise(resolve => { readyResolve = resolve; });
  child.stdout.on('data', chunk => {
    buffer += chunk.toString('utf8');
    while (buffer.includes('\n')) {
      const pos = buffer.indexOf('\n'), line = buffer.slice(0, pos); buffer = buffer.slice(pos + 1);
      const message = JSON.parse(line); if (message.ig5 === 'ready') { readyResolve(message); continue; }
      const request = pending.get(message.id); if (!request) continue;
      clearTimeout(request.timer); pending.delete(message.id);
      message.error ? request.reject(Object.assign(new Error(message.error.message), message.error)) : request.resolve(message.result);
    }
  });
  child.stderr.on('data', d => process.stderr.write(d));
  child.on('exit', () => { for (const req of pending.values()) { clearTimeout(req.timer); req.reject(new Error('adapter exited')); } pending.clear(); });
  const rpc = (method, params = {}) => {
    const id = ++seq;
    const promise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('JSONL timeout')); }, 20000);
      pending.set(id, { resolve, reject, timer }); child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    });
    promise.requestId = id; return promise;
  };
  return { child, ready, rpc };
}
try {
  for (const mode of ['suspend', 'stop-during-cont', 'wrong-cancel', 'queued-cancel', 'timeout', 'cancel', 'forced-adapter-exit']) {
    const c = client(); let owned = [];
    try {
      await c.ready; await c.rpc('open', { path: target });
      const started = await c.rpc('dbg', { op: 'start', timeout: 15 }); assert.equal(started.ok, true);
      owned = [started.debuggerPid, started.pid];
      await c.rpc('dbg', { op: 'bpt', rva: '0x1000' });
      const entry = await c.rpc('dbg', { op: 'cont', timeout: 5 }); assert.equal(entry.eventName, 'breakpoint');
      const untouched = (await c.rpc('dbg', { op: 'readmem', rva: '0x1010', size: 2 })).hex;
      await c.rpc('dbg', { op: 'setreg', reg: 'rip', value: '0x' + (BigInt(started.context.mainModuleBase) + 0x1080n).toString(16) });
      const operation = c.rpc('dbg', { op: 'cont', timeout: mode === 'timeout' ? 0.3 : 8 });
      if (['suspend', 'stop-during-cont', 'wrong-cancel', 'queued-cancel'].includes(mode)) {
        const waiting = operation.catch(error => { throw error; });
        await delay(80);
        if (mode === 'wrong-cancel') assert.equal((await c.rpc('cancel', { requestId: operation.requestId + 1000 })).cancelRequested, false);
        let skipped;
        if (mode === 'queued-cancel') {
          const queued = c.rpc('dbg', { op: 'writemem', rva: '0x1010', hex: '1122' });
          skipped = assert.rejects(queued, error => error.code === 'ECANCELLED' && error.cancelledBeforeExecution === true && error.cleanedUp === false);
          assert.equal((await c.rpc('cancel', { requestId: queued.requestId })).queued, true);
        }
        const controlOp = mode === 'stop-during-cont' ? 'stop' : 'suspend';
        const controlled = await c.rpc('dbg', { op: controlOp, timeout: 3 });
        const completed = await waiting;
        assert.equal(controlled.ok, true); assert.equal(completed.runId, controlled.runId);
        assert.equal(completed.stopSeq, controlled.stopSeq); assert.equal(completed.interruptedBy, controlOp);
        if (controlOp === 'suspend') {
          assert.equal(completed.ok, true); assert.equal(completed.state, 'suspended');
          assert.equal(completed.stopSeq, entry.stopSeq + 1, 'one physical pause must increment stopSeq once');
          assert.ok(owned.every(alive), 'suspend must preserve both debugger and target');
          assert.equal((await c.rpc('dbg', { op: 'regs' })).ok, true);
          if (skipped) { await skipped; assert.equal((await c.rpc('dbg', { op: 'readmem', rva: '0x1010', size: 2 })).hex, untouched); }
        } else {
          assert.equal(completed.ok, false); assert.equal(completed.state, 'no-task');
          assert.equal(completed.terminalReason, 'stopped-by-control');
          assert.ok(alive(owned[0])); await gone([owned[1]]);
        }
        console.log(`PASS ${mode}: ${controlOp} interrupted the active cont without session cleanup`);
        continue;
      }
      // Register the rejection immediately to avoid an unhandled promise race.
      const checked = assert.rejects(operation, error => {
        if (mode === 'forced-adapter-exit') return /adapter exited/.test(error.message);
        assert.equal(error.code, mode === 'timeout' ? 'ETIMEDOUT' : 'ECANCELLED');
        assert.equal(error.cleanedUp, true); assert.equal(error.state, 'no-task'); assert.equal(error.pid, null); return true;
      });
      if (mode === 'cancel') { await delay(80); assert.equal((await c.rpc('cancel', { requestId: operation.requestId })).cancelRequested, true); }
      if (mode === 'forced-adapter-exit') { await delay(100); c.child.kill(); }
      await checked; await gone(owned);
      console.log(`PASS ${mode}: debugger and target exited (${owned.join(', ')})`);
    } finally {
      if (c.child.exitCode === null && !c.child.killed) { try { await c.rpc('close'); } catch {} c.child.stdin.end(); }
      if (c.child.exitCode === null) await Promise.race([new Promise(resolve => c.child.once('exit', resolve)), delay(2000)]);
      if (c.child.exitCode === null) c.child.kill();
      await gone(owned);
    }
  }
} finally { fs.rmSync(temp, { recursive: true, force: true }); }
