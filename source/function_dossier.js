import { createHash } from 'node:crypto';
import { createAddressRef, normalizeHex } from './address_ref.js';
import { jsonToolOutput } from './json_output.js';

const PREFIX = 'dossier:v1:';
const CACHE_MARKER = 'ig5-function-dossier-cache';
const IDENTITY_FIELDS = ['target', 'projectId', 'artifactId', 'sha256', 'engine', 'provider', 'attachmentId', 'dbRevision'];
const SECTIONS = [
  ['decompile', 'decompile'], ['cfg', 'cfg'],
  ['callers', 'calls', 'callers'], ['callees', 'calls', 'callees'], ['stack', 'stack'],
];
const FIELDS = {
  decompile: ['ea', 'name', 'size', 'lines', 'code'],
  cfg: ['ea', 'name', 'func', 'start_ea', 'total_blocks', 'total_edges', 'blocks', 'edges'],
  callers: ['ea', 'name', 'direction', 'total', 'refsMeaning', 'calls'],
  callees: ['ea', 'name', 'direction', 'total', 'refsMeaning', 'calls'],
  stack: ['ea', 'name', 'ok', 'has_frame', 'frame_size', 'local_size', 'total_members', 'members', 'parts',
    'return_address_size', 'frame_type_size', 'offset_basis', 'note', 'error'],
};
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const bytes = value => Buffer.byteLength(JSON.stringify(value), 'utf8');
const clone = value => structuredClone(value);

function budget(value, fallback, low, high, field) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < low || value > high) fail('INVALID_DOSSIER_ARGUMENT', `${field} must be an integer from ${low} to ${high}`);
  return value;
}

function snapshot(mgr, session) {
  const evidence = jsonToolOutput(mgr.evidence(session));
  const result = {};
  for (const field of IDENTITY_FIELDS) {
    const value = evidence[field];
    if (field === 'dbRevision') {
      if (!Number.isSafeInteger(value) || value < 0) fail('INVALID_DOSSIER_CONTEXT', 'Database revision is unavailable');
    } else if (typeof value !== 'string' || !value.trim()) fail('INVALID_DOSSIER_CONTEXT', `Dossier ${field} identity is unavailable`);
    result[field] = value;
  }
  return result;
}

function assertCurrent(mgr, session, expected) {
  mgr.checkCancelled();
  if (!mgr.alive(session)) fail('DOSSIER_SESSION_STOPPED', 'Dossier worker stopped; reopen the target before collecting new evidence');
  if (typeof mgr.get === 'function' && mgr.get(session.target, session.engine) !== session)
    fail('DOSSIER_CONTEXT_CHANGED', 'Dossier session was replaced; collect a new snapshot');
  const current = snapshot(mgr, session);
  if (expected && IDENTITY_FIELDS.some(field => current[field] !== expected[field]))
    fail('DOSSIER_CONTEXT_CHANGED', 'Dossier database identity or revision changed during collection');
  return current;
}

function assertResultIdentity(value, expected) {
  if (value?._ig5 && IDENTITY_FIELDS.some(field => value._ig5[field] !== undefined && value._ig5[field] !== expected[field]))
    fail('DOSSIER_CONTEXT_CHANGED', 'Dossier provider returned evidence from a different database snapshot');
}

function fatal(error) {
  return /^(ABORT_ERR|WORKER_|EPIPE$|ECONNRESET$|ETIMEDOUT$|INVALID_IG5_OUTPUT|DOSSIER_|STALE_|ADDRESS_IDENTITY_MISMATCH)/.test(String(error?.code || ''))
    || /cancel(?:led|ed)|\btransport\b|worker.*(?:exited|recycled|stopped|not.*running|queue.*full)|worker rpc.*(?:超时|timeout)|worker 不在运行/i.test(String(error?.message || error));
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  return value;
}

function prefix(value, maximum) {
  if (bytes(value) <= maximum) return value;
  let low = 0, high = value.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (bytes(value.slice(0, middle)) <= maximum) low = middle;
    else high = middle - 1;
  }
  // Keep a Unicode code point whole even when its UTF-16 representation straddles the limit.
  if (low && /[\uD800-\uDBFF]/.test(value[low - 1])) low--;
  return value.slice(0, low);
}

/** Bound an already validated provider projection, preserving explicit omission counts. */
function compact(value, maximum, rowLimit) {
  const omitted = { rows: 0, fields: 0, stringBytes: 0, depth: 0 };
  function visit(node, room, depth) {
    if (room < 4 || depth > 16) { omitted.depth++; return null; }
    if (typeof node === 'string') {
      // A shortened hex address can still look valid while naming another
      // location. Preserve it whole or explicitly omit it as unknown.
      if (/^0x[0-9a-f]+$/i.test(node) && bytes(node) > room) { omitted.fields++; return null; }
      const result = prefix(node, room);
      omitted.stringBytes += Buffer.byteLength(node, 'utf8') - Buffer.byteLength(result, 'utf8');
      return result;
    }
    if (node === null || typeof node !== 'object') return bytes(node) <= room ? node : (omitted.fields++, null);
    if (Array.isArray(node)) {
      const result = [];
      let used = 2;
      for (const child of node.slice(0, rowLimit)) {
        const remaining = room - used - (result.length ? 1 : 0);
        if (remaining < 16) break;
        const item = visit(child, remaining, depth + 1), size = bytes(item);
        if (size > remaining) break;
        used += size + (result.length ? 1 : 0); result.push(item);
      }
      omitted.rows += node.length - result.length;
      return result;
    }
    const result = {};
    let used = 2;
    for (const [key, child] of Object.entries(node)) {
      const cost = Buffer.byteLength(JSON.stringify(key), 'utf8') + 1 + (Object.keys(result).length ? 1 : 0);
      const remaining = room - used - cost;
      if (remaining < 16) { omitted.fields++; continue; }
      const item = visit(child, remaining, depth + 1), size = bytes(item);
      if (size > remaining) { omitted.fields++; continue; }
      Object.defineProperty(result, key, { value: item, enumerable: true, writable: true, configurable: true });
      used += cost + size;
    }
    return result;
  }
  const data = visit(value, maximum, 0);
  return { data, omitted, truncated: Object.values(omitted).some(value => value > 0) };
}

function projected(section, value) {
  const result = {};
  for (const field of FIELDS[section]) if (Object.hasOwn(value, field)) result[field] = value[field];
  return result;
}

function providerOmissions(section, value) {
  const records = [];
  const checks = section === 'cfg' ? [['blocks', 'total_blocks'], ['edges', 'total_edges']]
    : section === 'stack' ? [['members', 'total_members']]
      : ['callers', 'callees'].includes(section) ? [['calls', 'total']] : [];
  for (const [field, totalField] of checks) {
    if (Array.isArray(value[field]) && Number.isSafeInteger(value[totalField]) && value[totalField] > value[field].length)
      records.push({ field, returned: value[field].length, available: value[totalField], omitted: value[totalField] - value[field].length });
  }
  return { truncated: value.truncated === true || value.partial === true || records.length > 0, records };
}

function cacheStore(session, key, value) {
  session.cache ||= new Map();
  const encodedBytes = bytes(value);
  session.cache.set(key, { marker: CACHE_MARKER, bytes: encodedBytes, value: clone(value) });
  let entries = [...session.cache.entries()].filter(([key, item]) => typeof key === 'string' && key.startsWith(PREFIX) && item?.marker === CACHE_MARKER);
  let total = entries.reduce((sum, [, item]) => sum + item.bytes, 0);
  while (entries.length > 16 || total > 1024 * 1024) {
    const [oldest, item] = entries.shift(); session.cache.delete(oldest); total -= item.bytes;
  }
}

/**
 * The caller must hold one session operation queue for the complete collection.
 * Only existing static, read-only RPC methods are used. Response/row limits do
 * not claim to bound all computation inside a provider or to complete analysis.
 */
export async function collectFunctionDossier(mgr, session, args = {}) {
  const maximum = budget(args.dossier_max_bytes, 16000, 4000, 64000, 'dossier_max_bytes');
  const rowLimit = budget(args.dossier_max_rows, 32, 1, 128, 'dossier_max_rows');
  const requestedEA = args.ea === undefined || args.ea === '' ? null : normalizeHex(args.ea, 'ea');
  const requestedName = args.name === undefined || args.name === '' ? null : typeof args.name === 'string' ? args.name.trim() : null;
  if (args.name !== undefined && args.name !== '' && (!requestedName || requestedName.length > 512))
    fail('INVALID_DOSSIER_ARGUMENT', 'name must be a non-empty function name of at most 512 characters');
  if (!requestedEA && !requestedName) fail('INVALID_DOSSIER_ARGUMENT', 'Dossier requires an explicit ea or exact function name');
  const provenance = assertCurrent(mgr, session);
  const key = PREFIX + JSON.stringify(stable({ provenance, requestedEA, requestedName, maximum, rowLimit, capabilities: session.capabilities || null }));
  const saved = session.cache?.get(key);
  if (saved?.marker === CACHE_MARKER) {
    assertCurrent(mgr, session, provenance);
    const result = clone(saved.value); result.cache.hit = true; return result;
  }

  const rawSections = {}, analysis = {
    partial: typeof session.info?.partial === 'boolean' ? session.info.partial : null,
    analysisComplete: typeof session.info?.analysisComplete === 'boolean' ? session.info.analysisComplete : null,
    analysisProfile: session.info?.analysisProfile || null,
  };
  let functionEA = null, reliableEA = null, functionName = requestedName, size = null;
  for (const [section, method, direction] of SECTIONS) {
    assertCurrent(mgr, session, provenance);
    if (Array.isArray(session.capabilities) && !session.capabilities.includes(method)) {
      rawSections[section] = { status: 'unsupported', reason: `Selected provider does not advertise ${method}` }; continue;
    }
    const params = functionEA || requestedEA ? { ea: functionEA || requestedEA } : { name: requestedName };
    if (section !== 'decompile') params.limit = rowLimit;
    if (direction) params.direction = direction;
    try {
      const value = jsonToolOutput(await mgr.rpc(session, method, params, Math.min(60000, mgr.cfg?.requestTimeoutMs || 60000)));
      assertCurrent(mgr, session, provenance); assertResultIdentity(value, provenance);
      if (!value || typeof value !== 'object' || Array.isArray(value)) fail('DOSSIER_INVALID_RESULT', `Provider ${method} did not return an object`);
      const address = value.start_ea ?? value.ea;
      if (address !== undefined) {
        const resolved = normalizeHex(address, `${section}.ea`);
        // Ghidra's decompiler reports the containing function entry, so its C
        // and CFG must identify exactly the same function. The commercial
        // compatibility provider can report the requested interior address;
        // its first assembly section establishes the canonical entry instead.
        if (section !== 'decompile' || provenance.provider === 'ghidra') {
          if (reliableEA && reliableEA !== resolved) fail('DOSSIER_FUNCTION_CHANGED', 'Provider sections resolved to different functions');
          reliableEA = resolved;
        }
        functionEA = reliableEA || resolved;
      }
      if (typeof (value.name ?? value.func) === 'string' && (value.name ?? value.func).trim()) functionName = value.name ?? value.func;
      if (section === 'decompile' && Number.isSafeInteger(value.size) && value.size >= 0) size = value.size;
      if (value.ok === false || value.error) rawSections[section] = {
        status: 'error', error: String(value.error || 'Provider could not complete this section'), data: projected(section, value),
      };
      else rawSections[section] = { status: 'ok', data: projected(section, value), provider: providerOmissions(section, value) };
    } catch (error) {
      assertCurrent(mgr, session, provenance);
      if (fatal(error) || /^(INVALID_ADDRESS|ADDRESS_OVERFLOW)/.test(String(error?.code || ''))) throw error;
      const unsupported = /^UNSUPPORTED/.test(String(error?.code || '')) || /does not support|not supported by|unsupported (?:method|capability)/i.test(String(error?.message || error));
      rawSections[section] = unsupported
        ? { status: 'unsupported', reason: String(error?.message || error) }
        : { status: 'error', error: String(error?.message || error) };
    }
  }
  assertCurrent(mgr, session, provenance);
  if (!functionEA && !requestedEA) fail('DOSSIER_FUNCTION_UNRESOLVED', 'Exact name could not be resolved to a function address; provide an explicit ea or inspect the function list');
  const resolved = functionEA !== null;
  functionEA ||= requestedEA;
  const result = {
    kind: 'function-dossier', schemaVersion: 1,
    function: { ea: functionEA, name: functionName || null, size, resolved,
      addressRole: resolved ? 'function' : 'requested-address', requestedEA },
    functionAddress: createAddressRef({ ...provenance, space: 'static', kind: 'va', value: functionEA }),
    // Include the public wrapper's evidence inside this byte budget, so it does
    // not append another unbudgeted identity after collection has completed.
    provenance, _ig5: clone(provenance), analysis, sections: {}, cache: { hit: false }, responseTruncated: false,
    responseBudgetBytes: maximum, responseMaxRows: rowLimit,
    snapshotDigest: '0'.repeat(64),
    limitations: ['Provider observations are not semantic or vulnerability proof.', 'Response limits do not bound all provider computation.'],
  };
  const minimumOverhead = bytes(result) + 5 * 256;
  if (minimumOverhead >= maximum) fail('DOSSIER_RESPONSE_LIMIT', 'Database identity exceeds the response budget; request a larger dossier_max_bytes');
  let remaining = maximum - minimumOverhead;
  for (let index = 0; index < SECTIONS.length; index++) {
    const [name, method, direction] = SECTIONS[index], raw = rawSections[name];
    const room = Math.max(16, Math.floor(remaining / (SECTIONS.length - index)));
    const section = { status: raw.status, method, ...(direction ? { direction } : {}) };
    if (raw.reason) section.reason = prefix(raw.reason, Math.min(256, room));
    if (raw.error) section.error = prefix(raw.error, Math.min(256, room));
    if (raw.reason && section.reason !== raw.reason || raw.error && section.error !== raw.error) {
      section.messageTruncated = true; result.responseTruncated = true;
    }
    if (raw.data) {
      const view = compact(raw.data, room, rowLimit);
      section.data = view.data;
      if (view.truncated || raw.provider?.truncated) {
        if (section.status === 'ok') section.status = 'truncated';
        section.truncation = { response: view.truncated, omitted: view.omitted, providerTruncated: raw.provider?.truncated === true, provider: raw.provider?.records || [] };
        result.responseTruncated = true;
      }
      remaining -= bytes(view.data);
    }
    result.sections[name] = section;
  }
  // The fixed section allowance also covers statuses and omission counts. For
  // unusually large provider totals, trim only bounded data and disclose it.
  while (bytes(result) > maximum) {
    const largest = Object.values(result.sections).filter(section => section.data && bytes(section.data) > 32)
      .sort((a, b) => bytes(b.data) - bytes(a.data))[0];
    if (!largest) fail('DOSSIER_RESPONSE_LIMIT', 'Dossier metadata exceeds the response budget');
    const view = compact(largest.data, Math.max(16, Math.floor(bytes(largest.data) / 2)), rowLimit);
    largest.data = view.data;
    if (largest.status === 'ok') largest.status = 'truncated';
    largest.truncation ||= { response: true, omitted: { rows: 0, fields: 0, stringBytes: 0, depth: 0 }, providerTruncated: false, provider: [] };
    largest.truncation.response = true;
    for (const field of Object.keys(view.omitted)) largest.truncation.omitted[field] += view.omitted[field];
    result.responseTruncated = true;
  }
  const { cache, snapshotDigest, ...content } = result;
  result.snapshotDigest = createHash('sha256').update(JSON.stringify(stable(content)), 'utf8').digest('hex');
  const output = jsonToolOutput(result);
  assertCurrent(mgr, session, provenance);
  if (!Object.values(result.sections).some(section => section.status === 'error')) cacheStore(session, key, output);
  return output;
}
