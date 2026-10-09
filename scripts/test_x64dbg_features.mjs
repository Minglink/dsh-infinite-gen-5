// Live opt-in: only generated PE bytes in a new private temporary directory.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const configPath = path.join(root, 'runtimes/x64dbg/runtime.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8').replace(/^\uFEFF/, ''));
const proof = JSON.parse(fs.readFileSync(path.join(root, 'runtimes/x64dbg/source-build-proof.json'), 'utf8').replace(/^\uFEFF/, ''));
assert.equal(proof.upstreamCommit, '9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87');
assert.equal(proof.architectures.length, 2);
const python = path.resolve(path.dirname(configPath), config.pythonExe);
const bits = process.argv.includes('--x86') ? 32 : 64;
const slotArg = process.argv.indexOf('--slot');
const expectedSlot = slotArg < 0 ? 0 : Number(process.argv[slotArg + 1]);
assert.ok(Number.isInteger(expectedSlot) && expectedSlot >= 0 && expectedSlot < 4);
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-source-x64dbg-'));

function fixture64() {
  const image = buildPE64Fixture().image;
  const raw = rva => rva < 0x2000 ? 0x400 + rva - 0x1000 : rva < 0x3000 ? 0x800 + rva - 0x2000 : 0xe00 + rva - 0x3000;
  // One CreateThread import; the second generated thread spins without OS calls.
  image.writeUInt32LE(0x3a00, 0x98 + 120); image.writeUInt32LE(40, 0x98 + 124);
  image.fill(0, raw(0x3a00), raw(0x3b00));
  image.writeUInt32LE(0x3a60, raw(0x3a00)); image.writeUInt32LE(0x3a40, raw(0x3a00) + 12); image.writeUInt32LE(0x3a80, raw(0x3a00) + 16);
  image.write('kernel32.dll\0', raw(0x3a40));
  image.writeBigUInt64LE(0x3aa0n, raw(0x3a60)); image.writeBigUInt64LE(0x3aa0n, raw(0x3a80));
  image.write('CreateThread\0', raw(0x3aa0) + 2);
  const bytes = []; const hex = x => bytes.push(...Buffer.from(x, 'hex'));
  const rel = (opcode, target) => { hex(opcode); const at = 0x1000 + bytes.length; const b = Buffer.alloc(4); b.writeInt32LE(target - (at + 4)); bytes.push(...b); };
  hex('4883ec3831c931d2'); rel('4c8d05', 0x1100); hex('4531c948c74424200000000048c744242800000000');
  rel('ff15', 0x3a80); hex('4883c438'); rel('803d', 0x3bff); hex('0175f7'); rel('e8', 0x1040); hex('ebfe');
  Buffer.from(bytes).copy(image, raw(0x1000)); Buffer.from('9090c3', 'hex').copy(image, raw(0x1040));
  Buffer.from('c6015aebfe', 'hex').copy(image, raw(0x1080));
  // Child announces actual execution before spinning; the main waits for it.
  Buffer.from('c605f92a000001ebfe', 'hex').copy(image, raw(0x1100)); image[raw(0x3c00)] = 0;
  // Genuine Win64 unwind metadata for the entry's 56-byte stack allocation.
  image.writeUInt32LE(0x3b00, 0x98 + 112 + 3 * 8); image.writeUInt32LE(12, 0x98 + 116 + 3 * 8);
  [0x1000, 0x1000 + bytes.length, 0x3b40].forEach((x, i) => image.writeUInt32LE(x, raw(0x3b00) + i * 4));
  Buffer.from('0104010004620000', 'hex').copy(image, raw(0x3b40));
  return image;
}
function fixture32() {
  const b = Buffer.alloc(0x600); b.write('MZ'); b.writeUInt32LE(0x80, 0x3c); b.write('PE\0\0', 0x80);
  const c = 0x84, o = c + 20, s = o + 0xe0;
  b.writeUInt16LE(0x14c, c); b.writeUInt16LE(2, c + 2); b.writeUInt16LE(0xe0, c + 16); b.writeUInt16LE(0x102, c + 18);
  b.writeUInt16LE(0x10b, o); b.writeUInt32LE(0x200, o + 4); b.writeUInt32LE(0x200, o + 8);
  b.writeUInt32LE(0x1000, o + 16); b.writeUInt32LE(0x1000, o + 20); b.writeUInt32LE(0x2000, o + 24);
  b.writeUInt32LE(0x400000, o + 28); b.writeUInt32LE(0x1000, o + 32); b.writeUInt32LE(0x200, o + 36);
  b.writeUInt16LE(6, o + 40); b.writeUInt16LE(6, o + 48); b.writeUInt32LE(0x3000, o + 56); b.writeUInt32LE(0x200, o + 60);
  b.writeUInt16LE(3, o + 68); b.writeUInt32LE(0x100000, o + 72); b.writeUInt32LE(0x1000, o + 76);
  b.writeUInt32LE(0x100000, o + 80); b.writeUInt32LE(0x1000, o + 84); b.writeUInt32LE(16, o + 92);
  for (const [i, name, rva, offset, flags] of [[0, '.text', 0x1000, 0x200, 0x60000020], [1, '.data', 0x2000, 0x400, 0xc0000040]]) {
    const h = s + i * 40; b.write(name, h); b.writeUInt32LE(0x200, h + 8); b.writeUInt32LE(rva, h + 12);
    b.writeUInt32LE(0x200, h + 16); b.writeUInt32LE(offset, h + 20); b.writeUInt32LE(flags, h + 36);
  }
  Buffer.from('e83b000000ebfe', 'hex').copy(b, 0x200); Buffer.from('5589e590905dc3', 'hex').copy(b, 0x240);
  Buffer.from('c6015aebfe', 'hex').copy(b, 0x280); return b;
}
const target = path.join(scratch, `源码构建-${bits}.exe`);
fs.writeFileSync(target, bits === 64 ? fixture64() : fixture32());
const worker = spawn(python, ['-I', '-B', path.join(root, 'adapters/x64dbg/adapter.py')], {
  windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, IG5_X64DBG_RUNTIME: configPath, IG5_X64DBG_STATE_ROOT: path.join(scratch, 'state') },
});
let sequence = 0, buffer = ''; const pending = new Map();
let readyResolve, readyReject;
const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
worker.stdout.on('data', data => {
  buffer += data.toString('utf8');
  for (;;) {
    const end = buffer.indexOf('\n'); if (end < 0) break;
    const line = buffer.slice(0, end).trim(); buffer = buffer.slice(end + 1); if (!line) continue;
    let message; try { message = JSON.parse(line); } catch { readyReject(new Error('invalid JSONL: ' + line)); continue; }
    if (message.ig5 === 'ready') { readyResolve(message); continue; }
    const request = pending.get(message.id); if (!request) continue;
    clearTimeout(request.timer); pending.delete(message.id);
    if (message.error) request.reject(Object.assign(new Error(message.error.message), message.error)); else request.resolve(message.result);
  }
});
worker.stderr.on('data', data => process.stderr.write(data));
worker.on('exit', code => { readyReject(new Error('adapter exited: ' + code)); for (const request of pending.values()) request.reject(new Error('adapter exited: ' + code)); pending.clear(); });
function rpc(method, params = {}) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('JSONL timeout: ' + method)); }, 25000);
    pending.set(id, { resolve, reject, timer }); worker.stdin.write(JSON.stringify({ id, method, params }) + '\n');
  });
}
async function dbg(op, params = {}) {
  const result = await rpc('dbg', { op, timeout: 15, ...params }); console.log(`[${op}] ${JSON.stringify(result)}`);
  assert.equal(result.ok, true, `${op}: ${JSON.stringify(result)}`); return result;
}
try {
  assert.equal((await ready).engine, 'x64dbg'); assert.equal((await rpc('doctor')).ok, true);
  assert.equal((await rpc('open', { path: target })).targetExecuted, false); await dbg('load');
  const started = await dbg('start'); assert.equal(started.mode, 'headless');
  const base = BigInt(started.context.mainModuleBase), ip = bits === 64 ? 'rip' : 'eip', cx = bits === 64 ? 'rcx' : 'ecx';
  const va = rva => '0x' + (base + BigInt(rva)).toString(16);
  await dbg('bpt', { rva: '0x1040' });
  for (let attempt = 0; attempt < 3 && (await dbg('regs')).regs[ip] !== va(0x1040); ++attempt) await dbg('cont');
  assert.equal((await dbg('regs')).regs[ip], va(0x1040));
  if (bits === 32) { await dbg('step'); await dbg('step'); }
  const threads = await dbg('threads'); assert.equal(threads.native, true); assert.ok(threads.threads.length >= (bits === 64 ? 2 : 1));
  assert.equal(threads.threads.filter(t => t.current).length, 1); assert.ok(threads.threads.every(t => t.threadId > 0 && !('handle' in t)));
  const stack = await dbg('callstack'); assert.equal(stack.native, true); assert.equal(stack.heuristic, true);
  assert.ok(stack.frames.length > 0); assert.equal(stack.threadId, threads.threads.find(t => t.current).threadId);
  assert.ok(stack.frames.some(f => [f.from, f.to].some(x => BigInt(x) >= base + 0x1000n && BigInt(x) < base + 0x1040n)), 'real caller return address must appear');
  await dbg('unbpt', { rva: '0x1040' });
  for (let slot = 0; slot < expectedSlot; ++slot) await dbg('bpt', {rva:'0x' + (0x10e0 + slot).toString(16),kind:'hardware'});
  const execRVA = bits === 64 ? 0x1041 : 0x1044;
  const hardware = await dbg('bpt', { rva: '0x' + execRVA.toString(16), kind: 'hardware', access: 'execute', size: 1 });
  assert.equal(hardware.breakpoint.exists, true); assert.ok(hardware.breakpoint.slot >= 0 && hardware.breakpoint.slot < 4);
  assert.equal(hardware.breakpoint.slot, expectedSlot);
  const hit = await dbg('cont'); assert.equal(hit.eventName, 'breakpoint'); assert.equal(Number(hit.event.data.type), 2);
  assert.equal((await dbg('regs')).regs[ip], va(execRVA));
  await dbg('unbpt', { rva: '0x' + execRVA.toString(16), kind: 'hardware' });
  for (const params of [{ rva: '0x1041', kind: 'hardware', access: 'write', size: 2 }, { rva: '0x1040', kind: 'hardware', access: 'execute', size: 4 }, { rva: '0x1040', kind: 'hardware', access: 'write;quit', size: 1 }]) {
    await assert.rejects(rpc('dbg', { op: 'bpt', ...params }), error => error.code === 'EINVAL');
  }
  const dataRVA = bits === 64 ? 0x3000 : 0x2000;
  await dbg('setreg', { reg: cx, value: va(dataRVA) }); await dbg('setreg', { reg: ip, value: va(0x1080) });
  const watch = await dbg('bpt', { rva: '0x' + dataRVA.toString(16), kind: 'hardware', access: 'write', size: 1 });
  assert.equal(watch.breakpoint.size, 1);
  assert.equal(watch.breakpoint.slot, expectedSlot);
  if (expectedSlot === 3) {
    assert.equal((await rpc('dbg', {op:'bpt',rva:'0x10ef',kind:'hardware'})).ok,false,'fifth hardware breakpoint must fail');
  }
  assert.equal((await dbg('readmem', {rva:'0x1080',size:3})).hex,'c6015a');
  const watchRegs = await dbg('regs'); assert.equal(watchRegs.regs['dr' + watch.breakpoint.slot], va(dataRVA));
  const writeHit = await dbg('cont'); assert.equal(writeHit.eventName, 'breakpoint'); assert.equal(Number(writeHit.event.data.type), 2);
  assert.equal((await dbg('readmem', { rva: '0x' + dataRVA.toString(16), size: 1 })).hex, '5a');
  const mismatch = await rpc('dbg', { op: 'bpt', rva: '0x' + dataRVA.toString(16), kind: 'hardware', access: 'readwrite', size: 1 });
  assert.equal(mismatch.ok, false, 'same address must not silently accept a different hardware access');
  await dbg('unbpt', { rva: '0x' + dataRVA.toString(16), kind: 'hardware' });
  for (let slot = 0; slot < expectedSlot; ++slot) await dbg('unbpt', {rva:'0x' + (0x10e0 + slot).toString(16),kind:'hardware'});
  assert.equal((await dbg('stop')).state, 'no-task'); await rpc('close');
  console.log(`PASS: source-built ${bits}-bit headless, native threads/callstack, slot ${expectedSlot} execute/write hardware hits and guarded metadata`);
} finally {
  try { await rpc('close'); } catch {}
  worker.stdin.end();
  await new Promise(resolve => { if (worker.exitCode !== null) resolve(); else { worker.once('exit', resolve); setTimeout(() => { worker.kill(); resolve(); }, 4000).unref(); } });
  // Keep generated samples and state logs as reviewable evidence, never user data.
  console.log('EVIDENCE ' + scratch);
}
