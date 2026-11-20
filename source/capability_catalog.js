import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { readStableFile } from './analysis_artifacts.js';
import { runtimeIdentity } from './capability_acceptance.js';

const digest = value => createHash('sha256').update(value).digest('hex');
const operations = [
  ['query-xrefs', 'ig5_xrefs', 'xrefs', null, 'Full toolset + opened target + explicit address/direction', 'observed code/data references; not exhaustive', 'read-only', 'static'],
  ['query-calls', 'ig5_calls', 'calls', null, 'Full toolset + opened target + function/direction', 'observed function relationships; unresolved indirect calls remain unknown', 'read-only', 'static'],
  ['query-cfg', 'ig5_cfg', 'cfg', null, 'Full toolset + opened target + function', 'provider CFG; not a reachability proof', 'read-only', 'static'],
  ['function-context', 'ig5_decompile', 'decompile', 'dossier', 'opened static target + function', 'function dossier', 'read-only', 'static'],
  ['read-bytes', 'ig5_bytes', 'bytes', null, 'opened static target + range', 'bytes', 'read-only', 'static'],
  ['project-path', 'ig5_ir', null, 'project', 'byte-bound explicit path', 'projection report', 'bounded analysis', 'static'],
  ['read-recording', 'ig5_recovery', null, 'observations', 'committed recording UUID/SHA', 'observation report', 'offline read', 'data'],
  ['record-execution', 'ig5_dbg', 'dbg-native', 'record_trace', 'authorized target + current run/stop', 'recording', 'approved target execution', 'debug'],
  ['debug-scenario', 'ig5_dbg', 'dbg-native', 'start', 'registered component + runtime scenario (args/cwd/trigger)', 'stop receipt + regs/readmem observations (launch-only; live PID attach is not implemented)', 'approved target execution + pre-reserved owner stop', 'debug'],
  ['analyze-js-app', 'ig5_package', null, 'js_app', 'local Electron/JS app directory', 'pinned rea@6.4.0 static graph + embedded native binary SHA-256 inventory', 'read-only static analysis', 'data'],
  ['diff-traces', 'ig5_package', null, 'trace_diff', 'two execution traces bound to identical targetSha256 + moduleBase', 'run-length alignment + first divergence + unique blocks', 'offline analysis', 'data'],
  ['observe-app-chain', 'ig5_app_observe', null, 'electron_scenario', 'parent Electron app or process-chain entry + payload', 'IPC + child spawn handoff + Windows CreationDate lineage + verified cleanup', 'approved target execution + owned tree cleanup', 'data'],
  ['write-comment', 'ig5_comment', 'comment', null, 'opened target + address + comment', 'write receipt', 'approved database write', 'static'],
  ['export-patch', 'ig5_export_diff', null, null, 'current target + patch history', 'patch report', 'artifact write', 'static'],
  ['decode-data', 'ig5_crypto', null, 'transform', 'bounded bytes or source reference + recipe', 'decode report', 'offline analysis', 'data'],
  ['frame-protocol', 'ig5_protocol', null, 'infer', 'bounded source-bound stream', 'framing candidates', 'offline analysis', 'data'],
  ['restore-history', 'ig5_profile', null, 'restore', 'executing DSH session', 'LCM references', 'local history read', 'history'],
];

/** Read the same component-path key as runtime_policy.py; unknown stays unknown. */
export function readLaunchPolicy(component, { root = path.join(process.env.IG5_HOME || path.join(os.homedir(), '.dsh', 'ig5'), 'runtime-policy-blocks') } = {}) {
  if (!component || process.platform !== 'win32') return { state: 'unknown' };
  const key = path.win32.resolve(component).toLowerCase();
  try {
    const stat = fs.lstatSync(root);
    if (stat.isSymbolicLink() || !stat.isDirectory()) return { state: 'unknown' };
    const file = path.join(root, digest(key) + '.json');
    let raw;
    try { raw = readStableFile(file, 8192).data; } catch (error) { if (error.code === 'ENOENT') return { state: 'no-known-block' }; throw error; }
    const value = JSON.parse(raw);
    if (value.schema !== 'ig5-runtime-policy-block-v1' || value.component !== key || value.winError !== 4551
      || value.automaticRetryAllowed !== false || Object.keys(value).sort().join(',') !== ['schema', 'component', 'winError', 'recordedAt', 'source', 'evidence', 'automaticRetryAllowed'].sort().join(',')
      || typeof value.recordedAt !== 'string' || !value.recordedAt.length || value.recordedAt.length > 64
      || !['observed-launch-error', 'imported-policy-evidence'].includes(value.source)
      || value.evidence !== null && (!value.evidence || Object.keys(value.evidence).sort().join(',') !== 'path,sha256'
        || typeof value.evidence.path !== 'string' || !path.win32.isAbsolute(value.evidence.path)
        || value.evidence.path.length > 4096 || value.evidence.path.includes('\0') || !/^[a-f0-9]{64}$/.test(value.evidence.sha256))) return { state: 'unknown' };
    return { state: 'blocked', winError: 4551, recordSha256: digest(raw), automaticRetryAllowed: false };
  } catch (error) { return { state: error.code === 'ENOENT' ? 'no-known-block' : 'unknown' }; }
}

/** Uses already resolved file checks and current sessions; no RPC, probe or launch. */
export function capabilityCatalog(mgr, cfg, { engine, ownQueue = false } = {}) {
  const sessions = [...(mgr.sessions?.values() || [])];
  const engines = mgr.engines?.() || [];
  const entries = [];
  for (const [operation, tool, method, mode, inputs, returns, sideEffects, lane] of operations) {
    let candidates = lane === 'static' ? engines.filter(e => e.id !== 'x64dbg' && (!engine || e.id === engine))
      : lane === 'debug' ? engines.filter(e => e.id === 'x64dbg') : [{ id: lane, provider: lane === 'data' ? 'node' : 'lcm', available: lane !== 'history' || !!mgr.memory }];
    if (lane === 'debug') candidates = [...candidates, ...sessions.filter(s => s.engine === 'x64dbg' && s.executionLocation?.kind === 'vmci-guest' && mgr.alive?.(s))
      .map(s => ({ id: 'x64dbg', provider: 'x64dbg', guestSession: s }))];
    for (const candidate of candidates) {
      const guest = candidate.guestSession;
      const location = guest?.executionLocation;
      const runtime = guest ? undefined : candidate.id === 'reverse' ? cfg.reverseRuntime : cfg[candidate.id];
      const manifest = runtime?.manifest;
      let runtimeDigest = guest ? location.bundleSha256 || null : runtimeIdentity(cfg, candidate.id);
      let files = candidate.available === true ? 'present' : runtime?.validationErrors?.length ? 'mismatch' : 'unknown';
      try { if (manifest) runtimeDigest = digest(readStableFile(manifest, 1024 * 1024).data); }
      catch (error) { files = error.code === 'ENOENT' ? 'missing' : 'unknown'; }
      const matching = guest ? [guest] : sessions.filter(s => s.engine === candidate.id && !s.guestProfile && (!s.executionLocation || s.executionLocation.kind === 'local') && mgr.alive?.(s));
      const policy = lane === 'debug' && !guest ? {
        x64: readLaunchPolicy(cfg.x64dbg?.headlessExe), x86: readLaunchPolicy(cfg.x64dbg?.headless32Exe),
      } : null;
      const policyState = policy ? Object.values(policy).some(x => x.state === 'blocked') ? 'blocked'
        : Object.values(policy).some(x => x.state === 'unknown') ? 'unknown' : 'no-known-block' : 'unknown';
      const states = matching.some(s => s.closing) ? 'cleanup-pending' : matching.some(s => s.pending?.size || s.queuedOperations > (ownQueue ? 1 : 0)) ? 'busy'
        : matching.length ? 'compatible' : lane === 'static' ? 'stale' : 'unknown';
      const unsupported = ['static','debug'].includes(lane) && cfg.host?.supported === false || lane === 'debug' && cfg.host?.id && cfg.host.id !== 'win32-x64';
      const declared = unsupported || method && matching.length && matching.every(s => Array.isArray(s.capabilities) && !s.capabilities.includes(method)) ? 'unsupported' : 'declared';
      let acceptance = { status: 'not-tested' };
      try { acceptance = !guest && mgr.capabilityAcceptance?.view(operation, candidate.id, candidate.provider || candidate.id, runtimeDigest, matching) || acceptance; }
      catch (error) { acceptance = { status: 'unverified', reason: error.code || 'ACCEPTANCE_RECORD_INVALID' }; }
      entries.push({ operation, engine: candidate.id, provider: candidate.provider || candidate.id,
        executionLocation: guest ? 'vmci-guest' : 'local', ...(guest ? { executionBinding: Object.fromEntries(['kind','profileSha256','guestCID','bundleSha256','serverInstanceId','sessionId'].filter(k => location[k] !== undefined).map(k => [k,location[k]])) } : {}), platform: candidate.platform || cfg.host?.id || process.platform, runtimeDigest,
        runtimeDigestScope: runtimeDigest ? guest ? 'bound-guest-bundle-manifest-only' : 'manifest-bytes-only' : 'unknown', mode, tool, inputs, returns, sideEffects,
        budget: lane === 'debug' ? 'existing approved recorder limits' : 'existing tool limits; no increase',
        declared, files,
        startup: candidate.startupVerified === true || matching.length ? 'verified' : runtime?.readiness === 'startup-failed' ? 'failed' : 'not-probed',
        startupScope: 'engine-session-only; operation remains not-tested',
        functionalEvidence: acceptance.status, acceptance, policy: policyState, ...(policy ? { launchPolicy: policy } : {}), session: states,
        nextCheck: policyState === 'blocked' ? 'read-recording; do not retry native launch' : 'check input identity and existing tool prerequisites',
      });
    }
  }
  return { schema: 'ig5-capability-catalog-v1', nativeProbePerformed: false, entries,
    limitations: ['File presence is not startup or functional verification.', 'Reverse bundled and Ghidra share the Ghidra provider.', 'Acceptance closes only its named properties and recorded scope.'] };
}
