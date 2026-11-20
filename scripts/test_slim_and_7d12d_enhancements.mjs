import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { DelegationControl } from '../source/delegation_control.js';
import { runManagedToolExecution } from '../source/delegation_execution.js';
import { RootInvestigationStore } from '../source/investigation_root.js';
import { runWorkspace } from '../source/investigation_workflow.js';
import { parseAsarHeader, analyzeJsApplicationBuiltin, BUILTIN_JS_STATIC_SOURCE } from '../source/native_js_static.js';
import { analyzeJsApplicationStatic } from '../source/native_rea_bridge.js';
import * as ApkRules from '../source/apk_rules.js';
import { inspectBytes, payloadDisguiseCheck } from '../source/protocol_analysis.js';
import { routeFailure, KNOWLEDGE_CARD_HINTS } from '../source/failure_router.js';
import { knowledgeSeeds } from '../source/knowledge_seeds.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function buildPickleAsar(filesSpec) {
  const payloadChunks = [];
  let currentOffset = 0;
  function buildTree(spec) {
    const out = {};
    for (const [k, v] of Object.entries(spec)) {
      if (Buffer.isBuffer(v)) {
        out[k] = { size: v.length, offset: String(currentOffset) };
        payloadChunks.push(v);
        currentOffset += v.length;
      } else if (v && typeof v === 'object' && v.link) {
        out[k] = { link: v.link };
      } else if (v && typeof v === 'object' && v.rawEntry) {
        out[k] = v.rawEntry;
      } else if (v && typeof v === 'object') {
        out[k] = { files: buildTree(v) };
      }
    }
    return out;
  }
  const headerObj = { files: buildTree(filesSpec) };
  const jsonBytes = Buffer.from(JSON.stringify(headerObj), 'utf8');
  const jsonLen = jsonBytes.length;
  const alignedJsonLen = (jsonLen + 3) & ~3;
  const headerPayloadSize = 4 + alignedJsonLen;
  const headerSize = 4 + headerPayloadSize;
  const prefix = Buffer.alloc(16 + alignedJsonLen, 0);
  prefix.writeUInt32LE(4, 0);
  prefix.writeUInt32LE(headerSize, 4);
  prefix.writeUInt32LE(headerPayloadSize, 8);
  prefix.writeUInt32LE(jsonLen, 12);
  jsonBytes.copy(prefix, 16);
  return Buffer.concat([prefix, ...payloadChunks]);
}

test('Phase 0 & 1: package_portable default output, SKILL.md < 10 KiB split, and root-create/root-update incremental summary (>90% reduction)', async (t) => {
  const pkgScript = fs.readFileSync(path.join(REPO_ROOT, 'scripts', 'package_portable.ps1'), 'utf8');
  assert.match(pkgScript, /\.dsh\\ig5\\releases/);
  assert.doesNotMatch(pkgScript, /\$OutputRoot\s*=\s*\(Join-Path\s+\$env:USERPROFILE\s+'\.dsh\\ig5\\artifacts'\)/);

  const skillBytes = fs.readFileSync(path.join(REPO_ROOT, 'skills', 'ig5-reverse-agent', 'SKILL.md'));
  assert.ok(skillBytes.length < 10000, `SKILL.md must be < 10 KB (10,000 B), got ${skillBytes.length} bytes`);
  assert.match(skillBytes.toString('utf8'), /references\/handler-semantics\.md/);

  const jsStaticBytes = fs.readFileSync(path.join(REPO_ROOT, 'source', 'native_js_static.js'));
  assert.ok(jsStaticBytes.length < 25000, `native_js_static.js must be < 25 KB (25,000 B), got ${jsStaticBytes.length} bytes`);

  const resEval = fs.readFileSync(path.join(REPO_ROOT, 'skills', 'ig5-reverse-agent', 'references', 'research-evaluation.md'), 'utf8');
  assert.doesNotMatch(resEval, /固定208的32次复制/);

  const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-phase1-ws-'));
  const artifacts = new AnalysisArtifacts(path.join(tmp, 'artifacts'));
  t.after(async () => {
    await artifacts.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const cfg = { projectRoot: path.join(tmp, 'projects'), artifactDir: path.join(tmp, 'artifacts'), host: { id: 'win32-x64', supported: true } };
  const owner = { id: 'agent-1', session: { header: { id: 'agent-1', cwd: tmp } } };
  const coordination = new DelegationControl({ root: cfg.projectRoot, getAgent: (id) => (id === owner.id ? owner : undefined) });
  const rStore = new RootInvestigationStore({ projectRoot: cfg.projectRoot });
  const mgr = { analysis: { artifacts }, coordination, rootInvestigations: rStore, sessions: new Map(), debugOwners: new Map(), engines: () => [] };

  const pePath = path.join(tmp, 'target.exe');
  const peBuf = Buffer.alloc(256, 0);
  peBuf[0] = 0x4d; peBuf[1] = 0x5a; peBuf.writeUInt32LE(0x80, 0x3c); peBuf.write('PE\0\0', 0x80, 'ascii'); peBuf.writeUInt16LE(0x8664, 0x84);
  fs.writeFileSync(pePath, peBuf);

  assert.throws(
    () => runWorkspace(mgr, cfg, { workspace: { action: 'root-create', goal: 'Bad param', include_task: 'yes' } }, { agent: owner }),
    (err) => err.code === 'INVALID_ARGUMENT',
  );

  const createdSummary = runWorkspace(mgr, cfg, {
    workspace: { action: 'root-create', goal: 'Incremental summary check', root: { component: { componentId: 'c1', path: pePath, role: 'main-pe' } } },
  }, { agent: owner }).workspace;
  assert.equal(createdSummary.created, true);
  assert.equal(createdSummary.counts.components, 1);
  assert.equal(createdSummary.hasCandidate, false);
  assert.equal('receipts' in createdSummary, false);

  for (let i = 0; i < 30; i++) {
    await runManagedToolExecution({
      mgr,
      toolName: 'ig5_funcs',
      rawArgs: { target: pePath, research: { id: createdSummary.rootId, key: `k-${i}`, note: `prep-${i}-${'X'.repeat(80)}` } },
      execution: { agent: owner },
      runCore: async () => ({ functions: Array.from({ length: 12 }, (_, j) => ({ ea: `0x14000${i}${j}`, name: `fn_${i}_${j}` })) }),
    });
  }

  const defaultUpdate = runWorkspace(mgr, cfg, {
    workspace: {
      action: 'root-update',
      id: createdSummary.rootId,
      root: { question: { questionId: 'q1', question: 'What is the framing?' } },
    },
  }, { agent: owner }).workspace;

  const fullUpdate = runWorkspace(mgr, cfg, {
    workspace: {
      action: 'root-update',
      id: createdSummary.rootId,
      include_task: true,
      root: { question: { questionId: 'q2', question: 'What is the trailer checksum?' } },
    },
  }, { agent: owner }).workspace;

  const defaultBytes = Buffer.byteLength(JSON.stringify(defaultUpdate), 'utf8');
  const fullBytes = Buffer.byteLength(JSON.stringify(fullUpdate), 'utf8');
  assert.equal(defaultUpdate.summary.counts.receipts, 30);
  assert.equal(defaultUpdate.task.summaryOnly, true);
  assert.equal(Array.isArray(fullUpdate.task.receipts), true);
  assert.equal(fullUpdate.task.receipts.length, 30);
  assert.ok(defaultBytes < 2500, `Default root-update should be < 2.5 KB, got ${defaultBytes} B`);
  assert.ok(defaultBytes < fullBytes * 0.1, `Expected >90% reduction: default=${defaultBytes}B vs full=${fullBytes}B`);
});

test('Phase 2: native_js_static unpackaged dir, ASAR pickle archive, Electron Fuses, and adversarial ASAR guards', (t) => {
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-phase2-js-'));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  const appDir = path.join(tmp, 'electron-unpackaged');
  fs.mkdirSync(path.join(appDir, 'src'), { recursive: true });
  fs.mkdirSync(path.join(appDir, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(appDir, 'package.json'), JSON.stringify({ name: 'demo-el', version: '1.2.0', main: 'src/main.js' }), 'utf8');
  fs.writeFileSync(path.join(appDir, 'src', 'main.js'), `
    const { app, BrowserWindow, ipcMain } = require('electron');
    const path = require('node:path');
    const { execFileSync } = require('node:child_process');
    // execFileSync('commented_decoy.exe', ['--fake']);
    const helperBin = path.join(__dirname, '..', 'bin', 'frame_helper.exe');
    function createWin() {
      const win = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false } });
      win.loadFile('index.html');
    }
    ipcMain.handle('codec:seal', (_ev, hex) => execFileSync(helperBin, ['--seal', hex]));
  `, 'utf8');
  fs.writeFileSync(path.join(appDir, 'src', 'preload.js'), `
    const { contextBridge, ipcRenderer } = require('electron');
    contextBridge.exposeInMainWorld('codecBridge', {
      sealPayload: (hex) => ipcRenderer.invoke('codec:seal', hex),
    });
  `, 'utf8');
  fs.writeFileSync(path.join(appDir, 'index.html'), `
    <html><body>
      <input id="hex-input" name="payload" type="text" />
      <button id="seal-btn" data-action="seal">Seal</button>
      <div id="result-box"></div>
    </body></html>
  `, 'utf8');
  fs.writeFileSync(path.join(appDir, 'bin', 'frame_helper.exe'), Buffer.from('MZ-fake-helper-pe'));

  const savedReaRoot = process.env.IG5_REA_ROOT;
  const savedReaCli = process.env.IG5_REA_CLI;
  delete process.env.IG5_REA_ROOT;
  delete process.env.IG5_REA_CLI;
  try {
    const report = analyzeJsApplicationStatic(appDir, { pluginRoot: tmp, cfg: { runtimeRoot: tmp } });
    assert.equal(report.schema, 'ig5-js-app-static-report-v2');
    assert.equal(report.reaEngine.provider, 'ig5-builtin-js-static');
    assert.equal(report.reaAnalysis.evidenceSource, BUILTIN_JS_STATIC_SOURCE);
    assert.ok(report.nativeArtifacts.some((n) => n.relativePath === 'bin/frame_helper.exe'));
    const graph = report.reaAnalysis.application_graph;
    assert.ok(graph.entrypoints.some((e) => e.role === 'main' && e.path === 'src/main.js'));
    assert.ok(graph.entrypoints.some((e) => e.role === 'preload' && e.path === 'preload.js'));
    assert.ok(graph.ipc_channels.some((c) => c.channel === 'codec:seal' && c.actor === 'ipcMain'));
    assert.ok(graph.ipc_channels.some((c) => c.channel === 'codec:seal' && c.actor === 'ipcRenderer'));
    assert.ok(graph.preload_bridges.some((b) => b.global === 'codecBridge' && b.methods.includes('sealPayload')));
    assert.ok(graph.html_controls.some((c) => c.selector === '#hex-input'));
    assert.ok(graph.html_controls.some((c) => c.selector === '#seal-btn'));
    const cp = graph.boundaries.find((b) => b.kind === 'child-process');
    assert.ok(cp && cp.targetCandidates.includes('frame_helper.exe'));
    assert.ok(!graph.boundaries.some((b) => b.targetCandidates.includes('commented_decoy.exe')));

    assert.throws(
      () => analyzeJsApplicationStatic(appDir, { pluginRoot: tmp, cfg: { reaRoot: path.join(tmp, 'missing-rea') } }),
      (err) => err.code === 'REA_CLI_UNAVAILABLE',
    );
  } finally {
    if (savedReaRoot !== undefined) process.env.IG5_REA_ROOT = savedReaRoot;
    if (savedReaCli !== undefined) process.env.IG5_REA_CLI = savedReaCli;
  }

  const pkgDir = path.join(tmp, 'packaged-app');
  fs.mkdirSync(path.join(pkgDir, 'resources'), { recursive: true });
  const fuseExe = Buffer.concat([
    Buffer.from('MZ-electron-stub-padding'),
    Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'ascii'),
    Buffer.from([1, 6]),
    Buffer.from('010011', 'ascii'),
  ]);
  fs.writeFileSync(path.join(pkgDir, 'MyDesktopApp.exe'), fuseExe);
  const validAsar = buildPickleAsar({
    'package.json': Buffer.from(JSON.stringify({ name: 'asar-app', main: 'main.js' }), 'utf8'),
    'main.js': Buffer.from('const { ipcMain } = require("electron"); ipcMain.on("asar:ping", () => {});', 'utf8'),
    'evil-link': { link: '../../Windows/System32/cmd.exe' },
  });
  const asarPath = path.join(pkgDir, 'resources', 'app.asar');
  fs.writeFileSync(asarPath, validAsar);

  const asarParsed = parseAsarHeader(asarPath);
  assert.ok(asarParsed.dataBaseOffset >= 16);
  const asarReport = analyzeJsApplicationBuiltin(pkgDir);
  assert.equal(asarReport.reaAnalysis.electron_fuses?.sentinelFound, true);
  assert.equal(asarReport.reaAnalysis.electron_fuses?.runAsNode, false);
  assert.equal(asarReport.reaAnalysis.electron_fuses?.enableEmbeddedAsarIntegrityValidation, true);
  assert.ok(asarReport.reaAnalysis.ipc_channels.some((c) => c.channel === 'asar:ping'));
  assert.ok(asarReport.reaAnalysis.skipped_entries.some((s) => s.path === 'evil-link' && s.reason === 'asar-symlink-rejected'));

  const truncAsar = path.join(tmp, 'trunc.asar');
  fs.writeFileSync(truncAsar, Buffer.from('04000000', 'hex'));
  assert.throws(() => parseAsarHeader(truncAsar), (err) => err.code === 'INVALID_ASAR');

  const oobAsar = path.join(tmp, 'oob.asar');
  fs.writeFileSync(oobAsar, buildPickleAsar({
    'bad.js': { rawEntry: { size: 999999, offset: '0' } },
  }));
  assert.throws(() => analyzeJsApplicationBuiltin(oobAsar), (err) => err.code === 'INVALID_ASAR');

  // Minified single-line bundle with URL/quote regexes, electron_1.BrowserWindow namespace, and nested {} in exposeInMainWorld
  const minDir = path.join(tmp, 'minified-bundle');
  fs.mkdirSync(minDir, { recursive: true });
  fs.writeFileSync(path.join(minDir, 'package.json'), JSON.stringify({ name: 'min-app', main: 'bundle.js' }), 'utf8');
  fs.writeFileSync(path.join(minDir, 'bundle.js'), 'const electron_1=require("electron"),isUrl=/^https?:\\/\\//,clean=(s)=>s.replace(/"/g,""),tpl=`${clean("x")}`;const w=new electron_1.BrowserWindow({width:800,webPreferences:{preload:path.join(__dirname,"preload.js"),contextIsolation:true,nodeIntegration:false}});electron_1.ipcMain.handle("secret:channel",()=>1);', 'utf8');
  fs.writeFileSync(path.join(minDir, 'preload.js'), 'const {contextBridge,ipcRenderer}=require("electron");contextBridge.exposeInMainWorld("api",{sendFrame:(x)=>ipcRenderer.invoke("secret:channel",{x}),secondMethod:()=>ipcRenderer.send("other:ch")});', 'utf8');
  const minReport = analyzeJsApplicationBuiltin(minDir);
  assert.ok(minReport.reaAnalysis.ipc_channels.some((c) => c.actor === 'ipcMain' && c.channel === 'secret:channel'));
  assert.equal(minReport.reaAnalysis.application_graph.windows[0]?.preload, 'preload.js');
  assert.equal(minReport.reaAnalysis.application_graph.windows[0]?.contextIsolation, true);
  assert.deepEqual(minReport.reaAnalysis.application_graph.preload_bridges[0]?.methods, ['sendFrame', 'secondMethod']);

  // ASAR with unpacked node_modules native .node addon + unpacked worker.js + oversized single-file guard
  const unpDir = path.join(tmp, 'unpacked-asar');
  fs.mkdirSync(unpDir, { recursive: true });
  const unpAsarPath = path.join(unpDir, 'app.asar');
  fs.mkdirSync(path.join(`${unpAsarPath}.unpacked`, 'node_modules', 'native-pkg'), { recursive: true });
  fs.writeFileSync(path.join(`${unpAsarPath}.unpacked`, 'node_modules', 'native-pkg', 'addon.node'), Buffer.from('MZ-native-addon'));
  fs.writeFileSync(path.join(`${unpAsarPath}.unpacked`, 'worker.js'), 'const { ipcMain } = require("electron"); ipcMain.on("unpacked:work", () => {});', 'utf8');
  fs.writeFileSync(unpAsarPath, buildPickleAsar({
    'package.json': Buffer.from(JSON.stringify({ name: 'unp', main: 'worker.js' }), 'utf8'),
    'worker.js': { rawEntry: { size: 78, unpacked: true } },
    'node_modules': { 'native-pkg': { 'addon.node': { rawEntry: { size: 15, unpacked: true } } } },
  }));
  const unpReport = analyzeJsApplicationBuiltin(unpAsarPath);
  assert.ok(unpReport.reaAnalysis.application_graph.native_addons.includes('node_modules/native-pkg/addon.node'));
  assert.ok(unpReport.reaAnalysis.ipc_channels.some((c) => c.channel === 'unpacked:work'));

  const hugeJs = path.join(tmp, 'huge.js');
  fs.writeFileSync(hugeJs, Buffer.alloc(4 * 1024 * 1024 + 64, 0x20));
  const hugeReport = analyzeJsApplicationBuiltin(hugeJs);
  assert.equal(hugeReport.reaAnalysis.scanned_files_count, 0);
  assert.ok(hugeReport.reaAnalysis.skipped_entries.some((s) => s.reason === 'single-file-budget-exceeded'));
});

test('Phase 3: APK rules, protocol payloadDisguiseCheck, failure_router card pointers, and .NET BSJB CLR parser', (t) => {
  assert.deepEqual(ApkRules.classifyApi('Landroid/security/keystore/KeyInfo;', 'isInsideSecurityHardware').map((r) => r.id), ['crypto.keyinfo']);
  assert.deepEqual(ApkRules.classifyApi('Ljava/security/KeyStore;', 'getEntry').map((r) => r.id), ['crypto.keystore']);
  assert.ok(ApkRules.classifyString('libjiagu.so').some((r) => r.id === 'str.packer-wrapper' && r.category === 'packer-wrapper'));
  assert.ok(ApkRules.classifyString('lib/arm64-v8a/libjiagu_64.so').some((r) => r.id === 'str.packer-wrapper'));
  assert.ok(ApkRules.classifyString('lib/arm64-v8a/libSecShell_x86.so').some((r) => r.id === 'str.packer-wrapper'));
  assert.ok(ApkRules.classifyString('lib/arm64-v8a/libexecmain.so').some((r) => r.id === 'str.packer-wrapper'));
  assert.equal(ApkRules.classifyString('/usr/libexec/git-core').some((r) => r.id === 'str.packer-wrapper'), false);
  assert.ok(ApkRules.classifyString('_kDartVmSnapshotInstructions').some((r) => r.id === 'str.cross-platform-flutter'));
  assert.ok(ApkRules.classifyString('index.android.bundle').some((r) => r.id === 'str.cross-platform-rn'));
  assert.ok(ApkRules.classifyString('RegisterNatives').some((r) => r.id === 'str.jni-registernatives'));

  assert.equal(payloadDisguiseCheck(Buffer.alloc(0)).suspectedBinaryEnvelope, false);
  assert.equal(payloadDisguiseCheck(Buffer.alloc(24, 0)).suspectedBinaryEnvelope, false);
  assert.equal(payloadDisguiseCheck(Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex')).suspectedBinaryEnvelope, false);
  assert.equal(payloadDisguiseCheck(Buffer.from('{"status":"ok","items":[1,2,3]}', 'utf8')).suspectedBinaryEnvelope, false);
  assert.equal(payloadDisguiseCheck(Buffer.from('hello plain ascii words', 'utf8')).suspectedBinaryEnvelope, false);

  const env24 = Buffer.alloc(32, 0xaa);
  env24[0] = 0x13; env24[1] = 0x37;
  env24.writeUInt32BE(8, 20);
  const check24 = inspectBytes(env24);
  assert.equal(check24.payloadDisguise.suspectedBinaryEnvelope, true);
  assert.ok(check24.payloadDisguise.candidates.some((c) => c.kind === 'fixed-20b-header-plus-u32-length' && c.lengthEndian === 'big'));

  const pbBuf = Buffer.from('089601120774657374696e67', 'hex');
  const checkPb = payloadDisguiseCheck(pbBuf);
  assert.equal(checkPb.suspectedBinaryEnvelope, true);
  assert.ok(checkPb.candidates.some((c) => c.kind === 'protobuf-varint-wire-candidate' && c.fieldCount === 2));

  const seedIds = new Set(knowledgeSeeds.map((s) => s.id));
  for (const [errCode, cardId] of Object.entries(KNOWLEDGE_CARD_HINTS)) {
    assert.ok(seedIds.has(cardId), `KNOWLEDGE_CARD_HINTS[${errCode}] -> "${cardId}" missing from knowledgeSeeds`);
    const routed = routeFailure({ failureCode: errCode });
    assert.equal(routed.recommendedCardId, cardId);
  }
  assert.ok(seedIds.has('vm-role-experiments'));
  assert.equal(routeFailure({ failureCode: 'UNKNOWN_RANDOM_CODE' }).recommendedCardId, undefined);

  const candidates = [
    process.env.IG5_PYTHON,
    process.env.IG5_RUNTIME_ROOT ? path.join(process.env.IG5_RUNTIME_ROOT, 'ghidra', 'python', 'python.exe') : null,
    path.join(REPO_ROOT, 'runtimes', 'ghidra', 'python', 'python.exe'),
  ].filter(Boolean);
  const pyExe = candidates.find((p) => fs.existsSync(p));
  const cscExe = 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe';

  if (pyExe && fs.existsSync(cscExe)) {
    const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-clr-test-'));
    t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
    const csPath = path.join(tmp, 'ManifestSample.cs');
    const exePath = path.join(tmp, 'ManifestSample.exe');
    fs.writeFileSync(csPath, `
      using System;
      namespace Ig5ClrFixture {
        public class FrameCodec {
          public static int ComputeTag(byte[] data) {
            string marker = "MAGIC_FRAME_PREFIX_v2";
            return marker.Length + (data != null ? data.Length : 0);
          }
          public static void Main(string[] args) {
            Console.WriteLine("CLR_ENTRY_BANNER:" + ComputeTag(new byte[]{1,2,3}));
          }
        }
      }
    `, 'utf8');
    const cscRes = spawnSync(cscExe, ['/nologo', '/optimize+', `/out:${exePath}`, csPath], { encoding: 'utf8', windowsHide: true });
    assert.equal(cscRes.status, 0, `csc.exe failed: ${cscRes.stdout} ${cscRes.stderr}`);

    const pyProbe = spawnSync(pyExe, ['-I', '-B', '-X', 'utf8', '-c', `
import json, struct, sys
sys.path.insert(0, 'worker')
from packer_analysis import analyze_packing
from scan_analysis import scan_image, parse_clr_metadata_bytes

assert parse_clr_metadata_bytes(b'') is None
assert parse_clr_metadata_bytes(b'BSJB\\x01\\x00') is None
assert parse_clr_metadata_bytes(b'BSJB' + b'\\xff' * 64) is None

ver = b'v4.0.30319\\x00\\x00'
s_heap = b'\\x00MyModule\\x00SecretType\\x00MyNs\\x00DecodeFrame\\x00'
us_heap = b'\\x00\\x0bH\\x00I\\x00_\\x00U\\x00S\\x00\\x00'
valid_mask = (1 << 0x00) | (1 << 0x02) | (1 << 0x06)
tilde = struct.pack('<IBBBBQQIIII', 0, 2, 0, 0x40, 1, valid_mask, 0, 1, 1, 1, 0xdeadbeef)
tilde += struct.pack('<HHHHH', 0, 1, 0, 0, 0) + struct.pack('<IHHHHH', 0, 10, 21, 0, 1, 1) + struct.pack('<IHHHHH', 0x2050, 0, 6, 26, 0, 1)
hdr_len = 20 + len(ver) + 12 + 12 + 20 + 12
adv_bsjb = (b'BSJB' + struct.pack('<HHII', 1, 1, 0, len(ver)) + ver + struct.pack('<HH', 0, 4)
            + struct.pack('<II', hdr_len, len(tilde)) + b'#~\\x00\\x00'
            + struct.pack('<II', hdr_len, 0) + b'#~\\x00\\x00'
            + struct.pack('<II', hdr_len + len(tilde), len(s_heap)) + b'#Strings\\x00\\x00\\x00\\x00'
            + struct.pack('<II', hdr_len + len(tilde) + len(s_heap), len(us_heap)) + b'#US\\x00'
            + tilde + s_heap + us_heap)
seg_with_decoy = b'\\x90' * 32 + b'\\x3dBSJB\\x75\\x10' + b'\\x90' * 128 + adv_bsjb
adv_scan = scan_image([{'name': '.text', 'start': 0x401000, 'size': len(seg_with_decoy), 'readable': True, 'read': lambda o, n: seg_with_decoy[o:o+n]}], source_engine='ghidra')

raw = open(sys.argv[1], 'rb').read()
pack = analyze_packing(sys.argv[1])
scan = scan_image([{'name': '.text', 'start': 0x400000, 'size': len(raw), 'readable': True, 'read': lambda o, n: raw[o:o+n]}], source_engine='ghidra')
print(json.dumps({'packClr': pack.get('clrMetadata'), 'scanClr': scan.get('clrMetadata'), 'advClr': adv_scan.get('clrMetadata')}))
`, exePath], { cwd: REPO_ROOT, encoding: 'utf8', windowsHide: true });
    assert.equal(pyProbe.status, 0, `Python CLR probe failed: ${pyProbe.stderr}`);
    const parsed = JSON.parse(pyProbe.stdout.trim());
    assert.equal(parsed.advClr?.types?.[0]?.fullName, 'MyNs.SecretType');
    assert.equal(parsed.advClr?.methods?.[0]?.name, 'DecodeFrame');
    assert.equal(parsed.advClr?.methods?.[0]?.rva, '0x2050');
    for (const clr of [parsed.packClr, parsed.scanClr]) {
      assert.ok(clr, 'clrMetadata must be extracted');
      assert.equal(clr.signature, 'BSJB');
      assert.match(clr.runtimeVersion, /^v4\.0/);
      assert.ok(clr.userStrings.includes('MAGIC_FRAME_PREFIX_v2'), `Missing #US literal in ${JSON.stringify(clr.userStrings)}`);
      assert.ok(clr.userStrings.some((s) => s.startsWith('CLR_ENTRY_BANNER:')));
      assert.ok(clr.types.some((ty) => ty.fullName === 'Ig5ClrFixture.FrameCodec'));
      assert.ok(clr.methods.some((m) => m.name === 'ComputeTag' && m.type === 'Ig5ClrFixture.FrameCodec' && m.rva && m.rva !== '0x0'));
    }
    assert.ok(parsed.packClr.methods.some((m) => m.name === 'ComputeTag' && m.ilCodeSize > 0));
  }
  if (pyExe) {
    const pr = spawnSync(pyExe, ['-I', '-B', '-X', 'utf8', '-c', `
import sys
sys.path.insert(0, 'worker')
import packer_rules as pr
pr.validate()
for sec in ('.enigma', '.obsidiu', '.taz', '.perplex', '.packed'):
    assert sec in pr.SECTION_NAMES, sec
for std in ('.go.buil', '.gopclnt', '.symtab', '.strtab', '.note'):
    assert std in pr.STANDARD_NAMES, std
names = {name for _, name, _ in pr.MARKERS}
assert 'ConfuserEx' in names and 'PyInstaller' in names, names
print('OK')
`], { cwd: REPO_ROOT, encoding: 'utf8', windowsHide: true });
    assert.equal(pr.status, 0, `packer_rules validation failed: ${pr.stderr}`);
    assert.equal(pr.stdout.trim(), 'OK');
  }
});

test('Phase 4: v1.4.0 version alignment, build_slim_donor.ps1 presence, and runtime_pack companion/portable helpers', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.version, '1.4.0');
  assert.equal(pkg.dsh.version, '1.4.0');
  assert.ok(fs.existsSync(path.join(REPO_ROOT, 'docs', 'RELEASE_1.4.0.md')));
  assert.ok(fs.existsSync(path.join(REPO_ROOT, 'scripts', 'build_slim_donor.ps1')));
  const slimScript = fs.readFileSync(path.join(REPO_ROOT, 'scripts', 'build_slim_donor.ps1'), 'utf8');
  for (const needle of ['jmods/', 'lib/src.zip', 'lib/ct.sym', 'docs/', 'Extensions/Ghidra/', 'Ghidra/Debug/', 'Ghidra/Features/BSim/', 'Ghidra/Features/GhidraServer/', 'sources-compliance.zip', 'companion-sources.json']) {
    assert.ok(slimScript.includes(needle), `build_slim_donor.ps1 missing Phase 4 rule: ${needle}`);
  }
  const rtPack = fs.readFileSync(path.join(REPO_ROOT, 'scripts', 'runtime_pack.ps1'), 'utf8');
  assert.match(rtPack, /function Test-IG5VersionAtLeast/);
  assert.match(rtPack, /PortableRelease/);
  assert.match(rtPack, /companion-sources\.json/);
});
