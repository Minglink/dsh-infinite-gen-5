// Differential execution-trace reduction & alignment with strict build/module/RVA/runId binding.
// Core run-length & divergence model adapted from apk-reverse (MIT License, Copyright (c) 2026 apk-reverse contributors),
// extended for IG5 with mandatory targetSha256, moduleBase->RVA rebasing, ASLR raw-pointer refusal, and runId provenance.

const HEX_TOK = /^(?:0x[0-9a-fA-F]+|(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{8,})$/;
const MOD_OFF = /^([A-Za-z0-9_.+-]+)\+0x([0-9a-fA-F]+)$/;
const BLK_LINE = /(?:^|\s)BLK\s+\d+\s+(\S+)(?:\s|$)/;
const SHA256_RE = /^[a-f0-9]{64}$/i;

function fail(code, message) {
  throw Object.assign(new Error(message), { code, retryable: false });
}

function parseRawToken(line, format = 'auto') {
  if (typeof line !== 'string') return null;
  if (format === 'stalker' || format === 'auto') {
    const m = BLK_LINE.exec(line);
    if (m) return m[1];
    if (format === 'stalker') return null;
  }
  const toks = line.trim().split(/\s+/).filter(Boolean);
  for (let i = toks.length - 1; i >= 0; i -= 1) {
    const tok = toks[i];
    if (MOD_OFF.test(tok)) return tok;
    if (HEX_TOK.test(tok)) return tok.toLowerCase();
  }
  return null;
}

function normalizeBlockKey(rawKey, { moduleName = null, moduleBase = null, moduleSize = null, aslrActive = false } = {}) {
  const modMatch = MOD_OFF.exec(rawKey);
  if (modMatch) {
    const mod = modMatch[1].toLowerCase();
    const off = BigInt('0x' + modMatch[2]);
    return `${mod}+0x${off.toString(16)}`;
  }
  const addrStr = rawKey.startsWith('0x') ? rawKey : `0x${rawKey}`;
  let va;
  try { va = BigInt(addrStr); } catch { return null; }

  if (moduleBase !== null && moduleBase !== undefined) {
    const base = BigInt(moduleBase);
    if (va >= base && (moduleSize === null || moduleSize === undefined || va < base + BigInt(moduleSize))) {
      const rva = va - base;
      const mod = (moduleName || 'main').toLowerCase();
      return `${mod}+0x${rva.toString(16)}`;
    }
  }
  if (aslrActive) {
    fail(
      'UNREBASED_ASLR_TRACE_REFUSED',
      `Raw runtime address ${addrStr} cannot be compared across ASLR runs without moduleBase rebasing`,
    );
  }
  return `0x${va.toString(16)}`;
}

export function parseTraceBlocks(traceInput, options = {}) {
  const lines = Array.isArray(traceInput)
    ? traceInput.map((item) => {
        if (typeof item === 'string') return item;
        if (item?.rva) return `${options.moduleName || 'main'}+${String(item.rva).startsWith('0x') ? item.rva : '0x' + item.rva}`;
        return item?.ea || item?.ip || item?.pc || item?.block || '';
      })
    : String(traceInput || '').split(/\r?\n/);
  if (lines.length > 200_000) {
    fail('TRACE_BUDGET_EXCEEDED', `Trace exceeds 200,000-line budget (${lines.length})`);
  }
  const blocks = [];
  for (const line of lines) {
    const raw = parseRawToken(line, options.format || 'auto');
    if (!raw) continue;
    const norm = normalizeBlockKey(raw, options);
    if (norm) blocks.push(norm);
  }
  if (blocks.length === 0) {
    fail('EMPTY_TRACE_REFUSED', 'Zero block keys parsed from trace input; empty trace is a capture failure, not an analysis result');
  }
  return blocks;
}

export function runLengthEncode(blocks) {
  const runs = [];
  for (const b of blocks) {
    if (runs.length > 0 && runs[runs.length - 1][0] === b) {
      runs[runs.length - 1][1] += 1;
    } else {
      runs.push([b, 1]);
    }
  }
  return runs;
}

export function reduceTrace(traceSpec) {
  const blocks = Array.isArray(traceSpec?.blocksNormalized)
    ? traceSpec.blocksNormalized
    : parseTraceBlocks(traceSpec?.lines ?? traceSpec?.text ?? traceSpec, {
        format: traceSpec?.format || 'auto',
        moduleName: traceSpec?.moduleName || null,
        moduleBase: traceSpec?.moduleBase ?? null,
        moduleSize: traceSpec?.moduleSize ?? null,
        aslrActive: Boolean(traceSpec?.aslrActive),
      });
  const counts = new Map();
  for (const b of blocks) counts.set(b, (counts.get(b) || 0) + 1);
  const runs = runLengthEncode(blocks);
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return {
    events: blocks.length,
    distinctBlocks: counts.size,
    runsCount: runs.length,
    top: top.slice(0, 64),
    sequence: runs,
  };
}

// Deterministic Myers/DP LCS opcode alignment over run-length block keys (bounded to <= 4096 runs per trace)
function computeAlignmentOpcodes(aKeys, bKeys) {
  const n = aKeys.length;
  const m = bKeys.length;
  if (n > 4096 || m > 4096) {
    fail('TRACE_RUNS_BUDGET_EXCEEDED', `Compressed run count (${n}, ${m}) exceeds 4096-run alignment budget`);
  }
  // Trim common prefix and suffix first for speed and exact first-divergence accuracy
  let prefix = 0;
  while (prefix < n && prefix < m && aKeys[prefix] === bKeys[prefix]) prefix += 1;
  let suffix = 0;
  while (suffix < (n - prefix) && suffix < (m - prefix) && aKeys[n - 1 - suffix] === bKeys[m - 1 - suffix]) suffix += 1;

  const midN = n - prefix - suffix;
  const midM = m - prefix - suffix;
  const dp = new Uint16Array((midN + 1) * (midM + 1));
  const width = midM + 1;
  for (let i = midN - 1; i >= 0; i -= 1) {
    for (let j = midM - 1; j >= 0; j -= 1) {
      dp[i * width + j] = aKeys[prefix + i] === bKeys[prefix + j]
        ? dp[(i + 1) * width + (j + 1)] + 1
        : Math.max(dp[(i + 1) * width + j], dp[i * width + (j + 1)]);
    }
  }

  const ops = [];
  const pushOp = (tag, i1, i2, j1, j2) => {
    if (i1 === i2 && j1 === j2) return;
    const prev = ops[ops.length - 1];
    if (prev && prev.tag === tag && prev.i2 === i1 && prev.j2 === j1) {
      prev.i2 = i2;
      prev.j2 = j2;
      return;
    }
    ops.push({ tag, i1, i2, j1, j2 });
  };

  if (prefix > 0) pushOp('equal', 0, prefix, 0, prefix);
  let i = 0;
  let j = 0;
  while (i < midN || j < midM) {
    if (i < midN && j < midM && aKeys[prefix + i] === bKeys[prefix + j]) {
      pushOp('equal', prefix + i, prefix + i + 1, prefix + j, prefix + j + 1);
      i += 1;
      j += 1;
    } else {
      let delEnd = i;
      let insEnd = j;
      while (delEnd < midN && (insEnd >= midM || dp[(delEnd + 1) * width + insEnd] >= dp[delEnd * width + (insEnd + 1)])
             && !(insEnd < midM && aKeys[prefix + delEnd] === bKeys[prefix + insEnd])) {
        delEnd += 1;
      }
      while (insEnd < midM && (delEnd >= midN || dp[delEnd * width + (insEnd + 1)] > dp[(delEnd + 1) * width + insEnd])
             && !(delEnd < midN && aKeys[prefix + delEnd] === bKeys[prefix + insEnd])) {
        insEnd += 1;
      }
      if (delEnd === i && insEnd === j) {
        if (i < midN) delEnd += 1;
        else insEnd += 1;
      }
      const tag = delEnd > i && insEnd > j ? 'replace' : (delEnd > i ? 'delete' : 'insert');
      pushOp(tag, prefix + i, prefix + delEnd, prefix + j, prefix + insEnd);
      i = delEnd;
      j = insEnd;
    }
  }
  if (suffix > 0) pushOp('equal', n - suffix, n, m - suffix, m);
  return ops;
}

export function diffTraces(traceA, traceB, { allowSameRun = false } = {}) {
  if (!traceA?.targetSha256 || !traceB?.targetSha256 || !SHA256_RE.test(traceA.targetSha256) || !SHA256_RE.test(traceB.targetSha256)) {
    fail('TRACE_MISSING_BUILD_SHA256', 'Both traces must bind an explicit 64-hex targetSha256');
  }
  if (traceA.targetSha256.toLowerCase() !== traceB.targetSha256.toLowerCase()) {
    fail('TRACE_BUILD_MISMATCH', `Refusing to diff traces across different target builds (${traceA.targetSha256} != ${traceB.targetSha256})`);
  }
  const warnings = [];
  if (traceA.runId && traceB.runId && traceA.runId === traceB.runId && !allowSameRun) {
    warnings.push('SAME_RUN_TRACE_WARNING: traceA and traceB share identical runId');
  }

  const aBlocks = parseTraceBlocks(traceA.lines ?? traceA.events ?? traceA.text, {
    format: traceA.format || 'auto',
    moduleName: traceA.moduleName || 'main',
    moduleBase: traceA.moduleBase ?? null,
    moduleSize: traceA.moduleSize ?? null,
    aslrActive: Boolean(traceA.aslrActive),
  });
  const bBlocks = parseTraceBlocks(traceB.lines ?? traceB.events ?? traceB.text, {
    format: traceB.format || 'auto',
    moduleName: traceB.moduleName || traceA.moduleName || 'main',
    moduleBase: traceB.moduleBase ?? null,
    moduleSize: traceB.moduleSize ?? null,
    aslrActive: Boolean(traceB.aslrActive),
  });

  const aRuns = runLengthEncode(aBlocks);
  const bRuns = runLengthEncode(bBlocks);
  const aKeys = aRuns.map((r) => r[0]);
  const bKeys = bRuns.map((r) => r[0]);
  const opcodes = computeAlignmentOpcodes(aKeys, bKeys);

  const aHist = new Map();
  const bHist = new Map();
  for (const k of aBlocks) aHist.set(k, (aHist.get(k) || 0) + 1);
  for (const k of bBlocks) bHist.set(k, (bHist.get(k) || 0) + 1);

  let identicalRunSpan = 0;
  let firstDivergence = null;
  const regions = [];

  for (const op of opcodes) {
    if (op.tag === 'equal') {
      identicalRunSpan += (op.i2 - op.i1);
      continue;
    }
    if (firstDivergence === null) {
      let evA = 0;
      for (let x = 0; x < op.i1; x += 1) evA += aRuns[x][1];
      let evB = 0;
      for (let y = 0; y < op.j1; y += 1) evB += bRuns[y][1];
      firstDivergence = {
        runIndexA: op.i1,
        runIndexB: op.j1,
        eventIndexA: evA,
        eventIndexB: evB,
        lastCommonBlock: op.i1 > 0 ? aRuns[op.i1 - 1][0] : null,
      };
    }
    regions.push({
      tag: op.tag,
      aRuns: aRuns.slice(op.i1, op.i2),
      bRuns: bRuns.slice(op.j1, op.j2),
    });
  }

  const uniqueToA = [];
  const uniqueToB = [];
  let sharedBlockExecutions = 0;
  const allKeys = new Set([...aHist.keys(), ...bHist.keys()]);
  for (const k of allKeys) {
    const ca = aHist.get(k) || 0;
    const cb = bHist.get(k) || 0;
    sharedBlockExecutions += Math.min(ca, cb);
    if (ca > 0 && cb === 0) uniqueToA.push([k, ca]);
    if (cb > 0 && ca === 0) uniqueToB.push([k, cb]);
  }
  uniqueToA.sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));
  uniqueToB.sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));

  return {
    schema: 'ig5-trace-diff-v1',
    provenance: {
      targetSha256: traceA.targetSha256.toLowerCase(),
      runIdA: traceA.runId || null,
      runIdB: traceB.runId || null,
      moduleBaseA: traceA.moduleBase || null,
      moduleBaseB: traceB.moduleBase || null,
      warnings,
    },
    aEvents: aBlocks.length,
    bEvents: bBlocks.length,
    aDistinct: aHist.size,
    bDistinct: bHist.size,
    sharedBlockExecutions,
    identicalRunSpan,
    divergentRegionsCount: regions.length,
    firstDivergence,
    regions: regions.slice(0, 32),
    uniqueToA: uniqueToA.slice(0, 32),
    uniqueToB: uniqueToB.slice(0, 32),
  };
}
