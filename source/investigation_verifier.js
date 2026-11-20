import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { readStableFile } from './analysis_artifacts.js';

export const SUPPORTED_DELIVERABLE_KINDS = new Set([
  'io-transform',
  'structured-frame-transform',
  'electron-native-chain',
  'dll-host-transform',
  'process-chain-transform',
  'apk-jni-chain',
]);
export const SUPPORTED_OBSERVATIONS = new Set([
  'static-locate',
  'dynamic-runtime-observation',
  'parent-child-handoff',
  'parent-to-helper-handoff',
  'non-cooperative-ui-trigger',
  'aslr-module-rebasing',
  'process-chain-correlation',
  'multi-process-lineage',
  'apk-jni-static-emulation',
  'dynamic-device-hook',
]);

const ALLOWED_OUTPUT_REGISTERS = new Set([
  'rax', 'eax', 'ax', 'al',
  'rbx', 'ebx', 'bx', 'bl',
  'rcx', 'ecx', 'cx', 'cl',
  'rdx', 'edx', 'dx', 'dl',
  'rsi', 'esi', 'rdi', 'edi',
  'r8', 'r8d', 'r9', 'r9d', 'r10', 'r10d', 'r11', 'r11d',
  'r12', 'r12d', 'r13', 'r13d', 'r14', 'r14d', 'r15', 'r15d',
]);

const BINARY_OPS = new Set(['xor', 'add', 'sub', 'mul', 'and', 'or', 'shl', 'shr', 'mod', 'rol8', 'ror8']);

function fail(code, message) {
  throw Object.assign(new Error(message), { code, retryable: false });
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).filter(k => value[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export function hashExecutableCandidate(executableRule, outputSpec) {
  return createHash('sha256').update(canonical({ executableRule, outputSpec })).digest('hex');
}

export function hashOutputSpec(outputSpec) {
  return createHash('sha256').update(canonical(outputSpec)).digest('hex');
}

export function canonicalPathKey(targetPath) {
  if (typeof targetPath !== 'string' || !targetPath.trim()) return null;
  const resolved = path.resolve(targetPath);
  const realNative = fs.realpathSync.native || fs.realpathSync;
  try {
    return realNative(resolved).toLowerCase();
  } catch {
    let cur = resolved;
    const tail = [];
    while (true) {
      const parent = path.dirname(cur);
      if (parent === cur) break;
      tail.unshift(path.basename(cur));
      cur = parent;
      try {
        return path.join(realNative(cur), ...tail).toLowerCase();
      } catch { /* walk up */ }
    }
    return resolved.toLowerCase();
  }
}

function decodeChannelString(raw, encoding) {
  if (encoding === 'utf8') {
    return Buffer.from(raw, 'utf8');
  }
  if (encoding === 'ascii') {
    if (/[^\x00-\x7f]/.test(raw)) return null;
    return Buffer.from(raw, 'ascii');
  }
  if (encoding === 'hex') {
    if (!raw.length || raw.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(raw)) return null;
    return Buffer.from(raw, 'hex');
  }
  if (encoding === 'base64') {
    if (!raw.length || raw.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(raw)) return null;
    const decoded = Buffer.from(raw, 'base64');
    if (decoded.toString('base64') !== raw) return null;
    return decoded;
  }
  return null;
}

/**
 * Derive canonical input bytes and SHA-256 directly from a typed delivery channel
 * (`cli-arg` or `file`), verifying any caller-claimed `sampleHex` against the actual channel bytes.
 * Channels that are ambiguous, out-of-bounds, mismatched, or unobserved (`stdin`, `ipc`, `none`)
 * return `{ verified: false, reason }`.
 */
export function deriveCanonicalScenarioInput({ args = [], cwd = null, inputSpec = {} } = {}) {
  const kind = inputSpec?.kind || (Array.isArray(args) && args.length ? 'cli-arg' : 'none');
  const rawSample = typeof inputSpec?.sampleHex === 'string' && inputSpec.sampleHex.length > 0
    ? inputSpec.sampleHex.trim().toLowerCase()
    : null;
  if (rawSample !== null && (rawSample.length % 2 !== 0 || !/^[0-9a-f]+$/.test(rawSample))) {
    return { verified: false, reason: 'invalid-claimed-sampleHex-format' };
  }

  if (kind === 'cli-arg') {
    if (!Array.isArray(args) || args.length === 0) {
      return { verified: false, reason: 'cli-arg-channel-has-empty-argv' };
    }
    const prefix = typeof inputSpec?.prefix === 'string' ? inputSpec.prefix : '';
    const suffix = typeof inputSpec?.suffix === 'string' ? inputSpec.suffix : '';
    let argIndex = inputSpec?.argIndex;
    if (argIndex === undefined) {
      if (args.length === 1 && !prefix && !suffix) {
        argIndex = 0;
      } else {
        return { verified: false, reason: 'cli-arg-requires-explicit-argIndex-when-argc-not-1-or-affixed' };
      }
    }
    if (!Number.isSafeInteger(argIndex) || argIndex < 0 || argIndex >= args.length) {
      return { verified: false, reason: `cli-arg-index-out-of-bounds(${argIndex}/${args.length})` };
    }
    const argText = args[argIndex];
    if (typeof argText !== 'string') {
      return { verified: false, reason: 'cli-arg-element-not-string' };
    }
    if (!argText.startsWith(prefix) || (suffix && !argText.endsWith(suffix)) || argText.length < prefix.length + suffix.length) {
      return { verified: false, reason: 'cli-arg-affix-mismatch' };
    }
    const payloadStr = argText.slice(prefix.length, suffix ? argText.length - suffix.length : argText.length);
    const requestedEncoding = inputSpec?.encoding === undefined ? 'utf8' : inputSpec.encoding;
    if (!['utf8', 'ascii', 'hex', 'base64'].includes(requestedEncoding)) {
      return { verified: false, reason: `unsupported-cli-arg-encoding(${requestedEncoding})` };
    }
    const encoding = (
      rawSample !== null
      && (inputSpec?.encoding === undefined || requestedEncoding === 'utf8' || requestedEncoding === 'ascii')
      && rawSample === payloadStr.trim().toLowerCase()
    ) ? 'hex' : requestedEncoding;
    const bytes = decodeChannelString(payloadStr, encoding);
    if (!bytes || bytes.length < 1 || bytes.length > 4096) {
      return { verified: false, reason: 'cli-arg-decoded-bytes-empty-or-invalid' };
    }
    const canonicalInputHex = bytes.toString('hex');
    if (rawSample !== null && rawSample !== canonicalInputHex) {
      return {
        verified: false,
        reason: `claimed-sampleHex-contradicts-channel(claimed=${rawSample},derived=${canonicalInputHex})`,
      };
    }
    const canonicalInputSha256 = createHash('sha256').update(bytes).digest('hex');
    return {
      verified: true,
      provenanceState: 'verified-inline',
      channel: { kind: 'cli-arg', argIndex, prefix, suffix, encoding },
      plannedInputHex: canonicalInputHex,
      plannedInputSha256: canonicalInputSha256,
      canonicalInputHex,
      canonicalInputSha256,
      byteLength: bytes.length,
    };
  }

  if (kind === 'file') {
    const filePathRaw = typeof inputSpec?.filePath === 'string' ? inputSpec.filePath.trim() : '';
    if (!filePathRaw) {
      return { verified: false, provenanceState: 'invalid-channel', reason: 'file-channel-requires-filePath' };
    }
    const resolvedFile = cwd ? path.resolve(cwd, filePathRaw) : path.resolve(filePathRaw);
    const prefix = typeof inputSpec?.prefix === 'string' ? inputSpec.prefix : '';
    const suffix = typeof inputSpec?.suffix === 'string' ? inputSpec.suffix : '';
    let argIndex = inputSpec?.argIndex;
    let effectivePrefix = prefix;
    const fixedFilename = typeof inputSpec?.fixedFilename === 'string' ? inputSpec.fixedFilename.trim() : '';
    let deliveryBound = false;
    if (Number.isSafeInteger(argIndex) && argIndex >= 0 && argIndex < args.length) {
      const argText = String(args[argIndex] || '');
      if (argText.startsWith(prefix) && (!suffix || argText.endsWith(suffix)) && argText.length >= prefix.length + suffix.length) {
        const argPathStr = argText.slice(prefix.length, suffix ? argText.length - suffix.length : argText.length);
        const argResolved = cwd ? path.resolve(cwd, argPathStr) : path.resolve(argPathStr);
        deliveryBound = canonicalPathKey(argResolved) === canonicalPathKey(resolvedFile);
      }
    } else if (fixedFilename && cwd) {
      deliveryBound = canonicalPathKey(path.resolve(cwd, fixedFilename)) === canonicalPathKey(resolvedFile);
    } else if (argIndex === undefined && !fixedFilename && Array.isArray(args) && args.length > 0) {
      // If caller omitted argIndex, infer it ONLY if an element of `args` unambiguously resolves to `resolvedFile`.
      const matches = [];
      for (let idx = 0; idx < args.length; idx += 1) {
        const rawArg = String(args[idx] || '');
        if (!rawArg) continue;
        const directResolved = cwd ? path.resolve(cwd, rawArg) : path.resolve(rawArg);
        if (canonicalPathKey(directResolved) === canonicalPathKey(resolvedFile)) {
          matches.push({ idx, pfx: '' });
          continue;
        }
        const eqPos = rawArg.indexOf('=');
        if (eqPos > 0 && eqPos + 1 < rawArg.length) {
          const rhs = rawArg.slice(eqPos + 1);
          const rhsResolved = cwd ? path.resolve(cwd, rhs) : path.resolve(rhs);
          if (canonicalPathKey(rhsResolved) === canonicalPathKey(resolvedFile)) {
            matches.push({ idx, pfx: rawArg.slice(0, eqPos + 1) });
          }
        }
      }
      if (matches.length === 1) {
        argIndex = matches[0].idx;
        effectivePrefix = matches[0].pfx;
        deliveryBound = true;
      }
    }
    if (!deliveryBound) {
      return { verified: false, provenanceState: 'unbound-channel', reason: 'file-channel-not-bound-to-argv-or-cwd-filename' };
    }
    const channelObj = {
      kind: 'file',
      filePath: resolvedFile,
      ...(Number.isSafeInteger(argIndex) ? { argIndex, prefix: effectivePrefix, suffix } : { fixedFilename }),
    };
    let bytes;
    try {
      bytes = readStableFile(resolvedFile, 4096).data;
    } catch (err) {
      // Separate "planned input intent" from "verified execution evidence":
      // If the file does not exist yet at registration time AND caller declared an explicit valid `sampleHex`,
      // record planned intent (`verified: false`, `provenanceState: "planned-awaiting-materialization"`) so
      // execution MUST materialize & witness the exact bytes on the bound channel before verification!
      if (err?.code === 'ENOENT' && rawSample !== null) {
        const plannedBytes = Buffer.from(rawSample, 'hex');
        if (plannedBytes.length >= 1 && plannedBytes.length <= 4096) {
          const plannedInputSha256 = createHash('sha256').update(plannedBytes).digest('hex');
          return {
            verified: false,
            provenanceState: 'planned-awaiting-materialization',
            reason: 'file-awaiting-execution-materialization',
            channel: channelObj,
            plannedInputHex: rawSample,
            plannedInputSha256,
            canonicalInputHex: null,
            canonicalInputSha256: null,
            byteLength: plannedBytes.length,
          };
        }
      }
      return {
        verified: false,
        provenanceState: err?.code === 'ENOENT' ? 'missing-unplanned-file' : 'unreadable-file',
        channel: channelObj,
        reason: `file-channel-unreadable(${err.code || 'IO_ERROR'})`,
      };
    }
    if (!bytes.length) {
      return { verified: false, provenanceState: 'empty-file', channel: channelObj, reason: 'file-channel-empty' };
    }
    const canonicalInputHex = bytes.toString('hex');
    if (rawSample !== null && rawSample !== canonicalInputHex) {
      return {
        verified: false,
        provenanceState: 'channel-sample-conflict',
        channel: channelObj,
        reason: `claimed-sampleHex-contradicts-file(claimed=${rawSample},derived=${canonicalInputHex})`,
      };
    }
    const canonicalInputSha256 = createHash('sha256').update(bytes).digest('hex');
    return {
      verified: true,
      provenanceState: 'verified-on-disk',
      channel: channelObj,
      plannedInputHex: canonicalInputHex,
      plannedInputSha256: canonicalInputSha256,
      canonicalInputHex,
      canonicalInputSha256,
      byteLength: bytes.length,
    };
  }

  if (kind === 'ipc') {
    const rawIpc = inputSpec?.ipcPayload ?? inputSpec?.payloadHex;
    const ipcPayload = typeof rawIpc === 'string' ? rawIpc.trim() : '';
    if (!ipcPayload) {
      return { verified: false, provenanceState: 'invalid-channel', reason: 'ipc-channel-requires-ipcPayload' };
    }
    const encoding = inputSpec?.encoding === undefined
      ? (/^[0-9a-f]{2,}$/i.test(ipcPayload) && ipcPayload.length % 2 === 0 ? 'hex' : 'utf8')
      : inputSpec.encoding;
    if (!['utf8', 'ascii', 'hex', 'base64'].includes(encoding)) {
      return { verified: false, provenanceState: 'invalid-channel', reason: `unsupported-ipc-encoding(${encoding})` };
    }
    const bytes = decodeChannelString(ipcPayload, encoding);
    if (!bytes || bytes.length < 1 || bytes.length > 4096) {
      return { verified: false, provenanceState: 'invalid-channel', reason: 'ipc-decoded-bytes-empty-or-invalid' };
    }
    const canonicalInputHex = bytes.toString('hex');
    if (rawSample !== null && rawSample !== canonicalInputHex) {
      return {
        verified: false,
        provenanceState: 'channel-sample-conflict',
        reason: `claimed-sampleHex-contradicts-ipc(claimed=${rawSample},derived=${canonicalInputHex})`,
      };
    }
    const canonicalInputSha256 = createHash('sha256').update(bytes).digest('hex');
    return {
      verified: true,
      provenanceState: 'verified-inline',
      channel: { kind: 'ipc', ipcPayload, encoding },
      plannedInputHex: canonicalInputHex,
      plannedInputSha256: canonicalInputSha256,
      canonicalInputHex,
      canonicalInputSha256,
      byteLength: bytes.length,
    };
  }

  if (kind === 'emulate') {
    const emuHex = rawSample || (typeof inputSpec?.inputHex === 'string' ? inputSpec.inputHex.trim().toLowerCase() : '');
    if (!emuHex || !/^[0-9a-f]+$/.test(emuHex) || emuHex.length % 2 !== 0) {
      return { verified: false, provenanceState: 'invalid-channel', reason: 'emulate-channel-requires-sampleHex' };
    }
    const bytes = Buffer.from(emuHex, 'hex');
    if (bytes.length < 1 || bytes.length > 4096) {
      return { verified: false, provenanceState: 'invalid-channel', reason: 'emulate-input-bytes-out-of-range' };
    }
    const canonicalInputSha256 = createHash('sha256').update(bytes).digest('hex');
    return {
      verified: true,
      provenanceState: 'verified-inline',
      channel: { kind: 'emulate', encoding: 'hex' },
      plannedInputHex: emuHex,
      plannedInputSha256: canonicalInputSha256,
      canonicalInputHex: emuHex,
      canonicalInputSha256,
      byteLength: bytes.length,
    };
  }

  if (kind === 'stdin') {
    const rawStdin = inputSpec?.stdinHex ?? inputSpec?.payload ?? '';
    const stdinStr = typeof rawStdin === 'string' ? rawStdin.trim() : '';
    if (!stdinStr) {
      return { verified: false, provenanceState: 'unbound-channel', reason: 'unverified-input-channel(stdin)' };
    }
    const encoding = inputSpec?.encoding === undefined
      ? (/^[0-9a-f]{2,}$/i.test(stdinStr) && stdinStr.length % 2 === 0 ? 'hex' : 'utf8')
      : inputSpec.encoding;
    if (!['utf8', 'ascii', 'hex', 'base64'].includes(encoding)) {
      return { verified: false, provenanceState: 'invalid-channel', reason: `unsupported-stdin-encoding(${encoding})` };
    }
    const bytes = decodeChannelString(stdinStr, encoding);
    if (!bytes || bytes.length < 1 || bytes.length > 4096) {
      return { verified: false, provenanceState: 'invalid-channel', reason: 'stdin-decoded-bytes-empty-or-invalid' };
    }
    const canonicalInputHex = bytes.toString('hex');
    if (rawSample !== null && rawSample !== canonicalInputHex) {
      return {
        verified: false,
        provenanceState: 'channel-sample-conflict',
        reason: `claimed-sampleHex-contradicts-stdin(claimed=${rawSample},derived=${canonicalInputHex})`,
      };
    }
    const canonicalInputSha256 = createHash('sha256').update(bytes).digest('hex');
    return {
      verified: true,
      provenanceState: 'verified-inline',
      channel: { kind: 'stdin', encoding },
      plannedInputHex: canonicalInputHex,
      plannedInputSha256: canonicalInputSha256,
      canonicalInputHex,
      canonicalInputSha256,
      byteLength: bytes.length,
    };
  }

  if (kind === 'android-intent') {
    const extraKey = typeof inputSpec?.extraKey === 'string' ? inputSpec.extraKey.trim() : 'payload';
    const rawIntentVal = inputSpec?.extraValue ?? inputSpec?.ipcPayload ?? rawSample ?? '';
    const valStr = typeof rawIntentVal === 'string' ? rawIntentVal.trim() : '';
    if (!valStr) {
      return { verified: false, provenanceState: 'invalid-channel', reason: 'android-intent-requires-extraValue-or-sampleHex' };
    }
    const encoding = inputSpec?.encoding === undefined
      ? (/^[0-9a-f]{2,}$/i.test(valStr) && valStr.length % 2 === 0 ? 'hex' : 'utf8')
      : inputSpec.encoding;
    const bytes = decodeChannelString(valStr, encoding);
    if (!bytes || bytes.length < 1 || bytes.length > 4096) {
      return { verified: false, provenanceState: 'invalid-channel', reason: 'android-intent-decoded-bytes-invalid' };
    }
    const canonicalInputHex = bytes.toString('hex');
    if (rawSample !== null && rawSample !== canonicalInputHex) {
      return { verified: false, provenanceState: 'channel-sample-conflict', reason: `claimed-sampleHex-contradicts-intent(claimed=${rawSample},derived=${canonicalInputHex})` };
    }
    const canonicalInputSha256 = createHash('sha256').update(bytes).digest('hex');
    return {
      verified: true,
      provenanceState: 'verified-inline',
      channel: { kind: 'android-intent', extraKey, extraValue: valStr, encoding },
      plannedInputHex: canonicalInputHex,
      plannedInputSha256: canonicalInputSha256,
      canonicalInputHex,
      canonicalInputSha256,
      byteLength: bytes.length,
    };
  }

  return { verified: false, provenanceState: 'unverified-channel', reason: `unverified-input-channel(${kind})` };
}

/**
 * Parse the preferred ImageBase directly from a PE32 / PE32+ file's Optional Header on disk.
 * Never assumes a hardcoded `0x180000000` or `0x140000000` constant.
 */
export function parsePePreferredImageBase(filePath) {
  try {
    const buf = readStableFile(filePath, 64 * 1024 * 1024).data;
    if (buf.length < 0x100 || buf[0] !== 0x4d || buf[1] !== 0x5a) return null;
    const peOff = buf.readUInt32LE(0x3c);
    if (peOff + 24 + 64 > buf.length) return null;
    if (!buf.subarray(peOff, peOff + 4).equals(Buffer.from('PE\0\0'))) return null;
    const optOff = peOff + 24;
    const magic = buf.readUInt16LE(optOff);
    if (magic === 0x20b) {
      return '0x' + buf.readBigUInt64LE(optOff + 24).toString(16);
    }
    if (magic === 0x10b) {
      return '0x' + (buf.readUInt32LE(optOff + 28) >>> 0).toString(16);
    }
    return null;
  } catch {
    return null;
  }
}

export function normalizeHexAddress(addr) {
  if (typeof addr !== 'string' || !addr.trim()) return null;
  const trimmed = addr.trim().toLowerCase();
  if (!/^(?:0x)?[0-9a-f]{1,16}$/.test(trimmed)) return null;
  const stripped = trimmed.replace(/^0x/, '').replace(/^0+/, '') || '0';
  return `0x${stripped}`;
}

export function validateOutputSpec(spec) {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
    fail('INVALID_ARGUMENT', 'candidate.outputSpec must be an object specifying output location and bounds');
  }
  const { kind, byteLength, minByteLength, maxByteLength } = spec;
  const hasVariableBounds = minByteLength !== undefined || maxByteLength !== undefined;
  if (hasVariableBounds) {
    if (kind !== 'app-output') {
      fail('INVALID_ARGUMENT', 'Variable-length minByteLength/maxByteLength bounds are supported only on outputSpec.kind="app-output"');
    }
    if (!Number.isSafeInteger(minByteLength) || !Number.isSafeInteger(maxByteLength)
      || minByteLength < 1 || maxByteLength < minByteLength || maxByteLength > 256) {
      fail('INVALID_ARGUMENT', 'outputSpec minByteLength..maxByteLength must satisfy 1 <= minByteLength <= maxByteLength <= 256');
    }
  } else if (!Number.isSafeInteger(byteLength) || byteLength < 1 || byteLength > 256) {
    fail('INVALID_ARGUMENT', 'outputSpec.byteLength must be an integer in 1..256');
  }
  if (kind === 'memory') {
    const rva = spec.rva !== undefined ? normalizeHexAddress(spec.rva) : null;
    const ea = spec.ea !== undefined ? normalizeHexAddress(spec.ea) : null;
    if (!rva && !ea) {
      fail('INVALID_ARGUMENT', 'memory outputSpec requires an explicit hex rva or ea');
    }
    if (spec.rva !== undefined && !rva) fail('INVALID_ARGUMENT', 'outputSpec.rva must be a valid hex address');
    if (spec.ea !== undefined && !ea) fail('INVALID_ARGUMENT', 'outputSpec.ea must be a valid hex address');
    return {
      kind: 'memory',
      byteLength,
      ...(rva ? { rva } : {}),
      ...(ea ? { ea } : {}),
    };
  }
  if (kind === 'register') {
    const reg = typeof spec.register === 'string' ? spec.register.trim().toLowerCase() : '';
    if (!ALLOWED_OUTPUT_REGISTERS.has(reg)) {
      fail('INVALID_ARGUMENT', `outputSpec.register "${spec.register}" is not an allowed value register (stack/instruction pointers like rsp/rip are forbidden)`);
    }
    if (![1, 2, 4, 8].includes(byteLength)) {
      fail('INVALID_ARGUMENT', 'register outputSpec.byteLength must be 1, 2, 4, or 8');
    }
    const endian = spec.endian === undefined ? 'big' : spec.endian;
    if (!['little', 'big'].includes(endian)) {
      fail('INVALID_ARGUMENT', 'register outputSpec.endian must be "little" or "big"');
    }
    return { kind: 'register', register: reg, byteLength, endian };
  }
  if (kind === 'module-memory') {
    const modName = typeof spec.module === 'string' ? spec.module.trim() : '';
    if (!modName || modName.length > 128) fail('INVALID_ARGUMENT', 'module-memory outputSpec requires non-empty module name');
    const rva = normalizeHexAddress(spec.rva);
    if (!rva) fail('INVALID_ARGUMENT', 'module-memory outputSpec requires a valid hex rva');
    return { kind: 'module-memory', module: modName.toLowerCase(), rva, byteLength };
  }
  if (kind === 'app-output') {
    const channel = spec.channel === undefined ? 'electron-ipc' : spec.channel;
    if (!['electron-ipc', 'electron-dom', 'process-chain', 'android-hook'].includes(channel)) {
      fail('INVALID_ARGUMENT', 'app-output outputSpec.channel must be "electron-ipc", "electron-dom", "process-chain", or "android-hook"');
    }
    if (hasVariableBounds) {
      return { kind: 'app-output', channel, minByteLength, maxByteLength };
    }
    return { kind: 'app-output', channel, byteLength };
  }
  if (kind === 'emulate-capture') {
    const endian = spec.endian === undefined ? 'little' : spec.endian;
    if (!['little', 'big'].includes(endian)) fail('INVALID_ARGUMENT', 'emulate-capture endian must be "little" or "big"');
    const reg = spec.register !== undefined ? String(spec.register).trim().toLowerCase() : null;
    if (reg && !ALLOWED_OUTPUT_REGISTERS.has(reg)) {
      fail('INVALID_ARGUMENT', `emulate-capture register "${spec.register}" is not an allowed value register`);
    }
    const ea = spec.ea !== undefined ? normalizeHexAddress(spec.ea) : null;
    if (!reg && !ea) fail('INVALID_ARGUMENT', 'emulate-capture outputSpec requires register or ea');
    return { kind: 'emulate-capture', byteLength, endian, ...(reg ? { register: reg } : {}), ...(ea ? { ea } : {}) };
  }
  fail('INVALID_ARGUMENT', 'outputSpec.kind must be "memory", "register", "module-memory", "app-output", or "emulate-capture"');
}

function validateExpr(node, constants, allowBuf, stats, exprPath = 'expr') {
  stats.nodes += 1;
  if (stats.nodes > 512) fail('INVALID_ARGUMENT', 'executableRule expression exceeds 512 AST nodes');
  if (stats.depth > 24) fail('INVALID_ARGUMENT', 'executableRule expression exceeds max depth 24');
  if (typeof node === 'number') {
    if (!Number.isSafeInteger(node) || node < 0 || node > 0xffffffff) {
      fail('INVALID_ARGUMENT', `executableRule numeric literal at ${exprPath} must be an integer in 0..0xffffffff`);
    }
    return;
  }
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    fail(
      'INVALID_ARGUMENT',
      `Invalid AST node in executableRule at ${exprPath}: expected non-negative integer literal or object {"op": ...} (got ${Array.isArray(node) ? 'array' : typeof node})`,
    );
  }
  const op = node.op;
  if (op === 'i' || op === 'len' || (allowBuf && op === 'prev')) return;
  stats.depth += 1;
  try {
    if (op === 'in' || (allowBuf && op === 'buf')) {
      validateExpr(node.index, constants, allowBuf, stats, `${exprPath}.index`);
      return;
    }
    if (op === 'const') {
      if (typeof node.name !== 'string' || !Object.hasOwn(constants, node.name)) {
        fail('INVALID_ARGUMENT', `executableRule at ${exprPath} references undeclared constant table "${node.name}"`);
      }
      validateExpr(node.index, constants, allowBuf, stats, `${exprPath}.index`);
      return;
    }
    if (op === 'not8') {
      validateExpr(node.arg, constants, allowBuf, stats, `${exprPath}.arg`);
      return;
    }
    if (BINARY_OPS.has(op)) {
      if (!Array.isArray(node.args) || node.args.length !== 2) {
        fail('INVALID_ARGUMENT', `executableRule op "${op}" at ${exprPath} requires args: [lhs, rhs]`);
      }
      validateExpr(node.args[0], constants, allowBuf, stats, `${exprPath}.args[0]`);
      validateExpr(node.args[1], constants, allowBuf, stats, `${exprPath}.args[1]`);
      return;
    }
    fail('INVALID_ARGUMENT', `Unsupported executableRule op "${op}" at ${exprPath}`);
  } finally {
    stats.depth -= 1;
  }
}

export function validateExecutableRule(rule, outputSpec) {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
    fail('INVALID_ARGUMENT', 'candidate.executableRule must be an object');
  }
  if (rule.schema === 'ig5-bounded-frame-rule-v1') {
    const headerHex = rule.headerHex === undefined ? '' : String(rule.headerHex).trim().toLowerCase();
    if (headerHex.length > 64 || headerHex.length % 2 !== 0 || (headerHex && !/^[0-9a-f]+$/.test(headerHex))) {
      fail('INVALID_ARGUMENT', 'frame rule headerHex must be an even-length hex string (<= 32 bytes)');
    }
    const lenKind = rule.lengthField?.kind ?? 'none';
    if (!['none', 'payload-len-u8', 'payload-len-u16be', 'payload-len-u16le', 'total-len-u8'].includes(lenKind)) {
      fail('INVALID_ARGUMENT', `Unsupported frame lengthField.kind "${lenKind}"`);
    }
    const lenBias = rule.lengthField?.bias ?? 0;
    if (!Number.isSafeInteger(lenBias) || lenBias < -64 || lenBias > 64) {
      fail('INVALID_ARGUMENT', 'frame lengthField.bias must be an integer in -64..64');
    }
    const rawConsts = rule.constants ?? {};
    if (typeof rawConsts !== 'object' || Array.isArray(rawConsts) || Object.keys(rawConsts).length > 16) {
      fail('INVALID_ARGUMENT', 'executableRule.constants must be an object with at most 16 hex tables');
    }
    const normalizedConsts = {};
    for (const [k, hex] of Object.entries(rawConsts)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,31}$/.test(k)) fail('INVALID_ARGUMENT', `Invalid constant name "${k}"`);
      if (typeof hex !== 'string' || hex.length === 0 || hex.length > 2048 || hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) {
        fail('INVALID_ARGUMENT', `Constant "${k}" must be non-empty even-length hex (<= 1024 bytes)`);
      }
      normalizedConsts[k] = hex.toLowerCase();
    }
    if (!rule.bodyByteExpr || typeof rule.bodyByteExpr !== 'object' || Array.isArray(rule.bodyByteExpr)) {
      fail('INVALID_ARGUMENT', 'ig5-bounded-frame-rule-v1 requires bodyByteExpr AST object');
    }
    const stats = { nodes: 0, depth: 0 };
    validateExpr(rule.bodyByteExpr, normalizedConsts, true, stats, 'bodyByteExpr');
    const prevInit = rule.prevInit ?? 0;
    if (!Number.isSafeInteger(prevInit) || prevInit < 0 || prevInit > 255) {
      fail('INVALID_ARGUMENT', 'frame rule prevInit must be an integer in 0..255');
    }
    const csumKind = rule.trailerChecksum?.kind ?? 'none';
    if (!['none', 'xor8', 'sum8', 'crc16ccitt-be', 'crc16ccitt-le', 'fnv1a32-be', 'fnv1a32-le'].includes(csumKind)) {
      fail('INVALID_ARGUMENT', `Unsupported frame trailerChecksum.kind "${csumKind}"`);
    }
    const csumScope = rule.trailerChecksum?.scope ?? 'header-and-body';
    if (!['body', 'header-and-body'].includes(csumScope)) {
      fail('INVALID_ARGUMENT', 'trailerChecksum.scope must be "body" or "header-and-body"');
    }
    const csumInit = rule.trailerChecksum?.init ?? (csumKind.startsWith('crc16') ? 0xffff : csumKind.startsWith('fnv1a32') ? 0x811c9dc5 : 0);
    if (!Number.isSafeInteger(csumInit) || csumInit < 0 || csumInit > 0xffffffff) {
      fail('INVALID_ARGUMENT', 'trailerChecksum.init must be an integer in 0..0xffffffff');
    }
    return {
      schema: 'ig5-bounded-frame-rule-v1',
      headerHex,
      lengthField: { kind: lenKind, bias: lenBias },
      prevInit,
      constants: normalizedConsts,
      bodyByteExpr: structuredClone(rule.bodyByteExpr),
      trailerChecksum: { kind: csumKind, scope: csumScope, init: csumInit },
    };
  }
  if (rule.schema !== 'ig5-bounded-byte-rule-v1') {
    fail('INVALID_ARGUMENT', 'executableRule.schema must be "ig5-bounded-byte-rule-v1" or "ig5-bounded-frame-rule-v1"');
  }
  if (!Number.isSafeInteger(rule.outputLength) || rule.outputLength < 1 || rule.outputLength > 256) {
    fail('INVALID_ARGUMENT', 'executableRule.outputLength must be an integer in 1..256');
  }
  if (outputSpec && outputSpec.byteLength !== undefined && rule.outputLength !== outputSpec.byteLength) {
    fail('INVALID_ARGUMENT', `executableRule.outputLength (${rule.outputLength}) must equal outputSpec.byteLength (${outputSpec.byteLength})`);
  }
  if (rule.inputLength !== undefined && (!Number.isSafeInteger(rule.inputLength) || rule.inputLength < 1 || rule.inputLength > 256)) {
    fail('INVALID_ARGUMENT', 'executableRule.inputLength must be an integer in 1..256');
  }
  const rawConsts = rule.constants ?? {};
  if (typeof rawConsts !== 'object' || Array.isArray(rawConsts) || Object.keys(rawConsts).length > 16) {
    fail('INVALID_ARGUMENT', 'executableRule.constants must be an object with at most 16 hex tables');
  }
  const normalizedConsts = {};
  for (const [k, hex] of Object.entries(rawConsts)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,31}$/.test(k)) fail('INVALID_ARGUMENT', `Invalid constant name "${k}"`);
    if (typeof hex !== 'string' || hex.length === 0 || hex.length > 2048 || hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) {
      fail('INVALID_ARGUMENT', `Constant "${k}" must be non-empty even-length hex (<= 1024 bytes)`);
    }
    normalizedConsts[k] = hex.toLowerCase();
  }

  const hasByteExpr = rule.byteExpr !== undefined;
  const hasSteps = Array.isArray(rule.steps) && rule.steps.length > 0;
  if (hasByteExpr === hasSteps) {
    fail('INVALID_ARGUMENT', 'executableRule must specify exactly one of byteExpr or non-empty steps[]');
  }
  const stats = { nodes: 0, depth: 0 };
  if (hasByteExpr) {
    if (Array.isArray(rule.byteExpr)) {
      if (rule.byteExpr.length !== rule.outputLength) {
        fail('INVALID_ARGUMENT', `executableRule.byteExpr array length (${rule.byteExpr.length}) must equal outputLength (${rule.outputLength})`);
      }
      for (let idx = 0; idx < rule.byteExpr.length; idx++) {
        validateExpr(rule.byteExpr[idx], normalizedConsts, false, stats, `byteExpr[${idx}]`);
      }
    } else {
      validateExpr(rule.byteExpr, normalizedConsts, false, stats, 'byteExpr');
    }
    return {
      schema: 'ig5-bounded-byte-rule-v1',
      ...(rule.inputLength !== undefined ? { inputLength: rule.inputLength } : {}),
      outputLength: rule.outputLength,
      constants: normalizedConsts,
      byteExpr: structuredClone(rule.byteExpr),
    };
  }
  if (rule.steps.length > 64) fail('INVALID_ARGUMENT', 'executableRule.steps supports at most 64 step blocks');
  const stateLength = rule.stateLength ?? rule.outputLength;
  if (!Number.isSafeInteger(stateLength) || stateLength < rule.outputLength || stateLength > 256) {
    fail('INVALID_ARGUMENT', 'executableRule.stateLength must be in outputLength..256');
  }
  for (const [stepIdx, step] of rule.steps.entries()) {
    if (!step || typeof step !== 'object') fail('INVALID_ARGUMENT', `Invalid step in executableRule.steps[${stepIdx}]`);
    const repeat = step.repeat ?? 1;
    if (!Number.isSafeInteger(repeat) || repeat < 1 || repeat > 256) {
      fail('INVALID_ARGUMENT', `steps[${stepIdx}].repeat must be 1..256`);
    }
    validateExpr(step.targetIndex, normalizedConsts, true, stats, `steps[${stepIdx}].targetIndex`);
    validateExpr(step.valueExpr, normalizedConsts, true, stats, `steps[${stepIdx}].valueExpr`);
  }
  return {
    schema: 'ig5-bounded-byte-rule-v1',
    ...(rule.inputLength !== undefined ? { inputLength: rule.inputLength } : {}),
    outputLength: rule.outputLength,
    stateLength,
    initFromInput: Boolean(rule.initFromInput),
    constants: normalizedConsts,
    steps: structuredClone(rule.steps),
  };
}

function evalNode(node, env) {
  if (typeof node === 'number') return node >>> 0;
  switch (node.op) {
    case 'i': return env.i >>> 0;
    case 'len': return env.input.length >>> 0;
    case 'prev': return (env.prev ?? 0) >>> 0;
    case 'in': {
      const idx = evalNode(node.index, env);
      if (idx >= env.input.length) fail('CANDIDATE_EVAL_OOB', `Input read index ${idx} out of bounds (${env.input.length})`);
      return env.input[idx];
    }
    case 'buf': {
      const idx = evalNode(node.index, env);
      if (!env.buf || idx >= env.buf.length) fail('CANDIDATE_EVAL_OOB', `State buffer read index ${idx} out of bounds`);
      return env.buf[idx];
    }
    case 'const': {
      const tbl = env.consts[node.name];
      const idx = evalNode(node.index, env);
      if (idx >= tbl.length) fail('CANDIDATE_EVAL_OOB', `Constant "${node.name}" index ${idx} out of bounds (${tbl.length})`);
      return tbl[idx];
    }
    case 'not8':
      return (~evalNode(node.arg, env)) & 0xff;
    case 'xor':
      return (evalNode(node.args[0], env) ^ evalNode(node.args[1], env)) >>> 0;
    case 'add':
      return (evalNode(node.args[0], env) + evalNode(node.args[1], env)) >>> 0;
    case 'sub':
      return (evalNode(node.args[0], env) - evalNode(node.args[1], env)) >>> 0;
    case 'mul':
      return Math.imul(evalNode(node.args[0], env), evalNode(node.args[1], env)) >>> 0;
    case 'and':
      return (evalNode(node.args[0], env) & evalNode(node.args[1], env)) >>> 0;
    case 'or':
      return (evalNode(node.args[0], env) | evalNode(node.args[1], env)) >>> 0;
    case 'shl':
      return (evalNode(node.args[0], env) << (evalNode(node.args[1], env) & 31)) >>> 0;
    case 'shr':
      return (evalNode(node.args[0], env) >>> (evalNode(node.args[1], env) & 31)) >>> 0;
    case 'mod': {
      const rhs = evalNode(node.args[1], env);
      if (rhs === 0) fail('CANDIDATE_EVAL_DIV_ZERO', 'Modulo by zero in executableRule');
      return (evalNode(node.args[0], env) % rhs) >>> 0;
    }
    case 'rol8': {
      const v = evalNode(node.args[0], env) & 0xff;
      const s = evalNode(node.args[1], env) & 7;
      return ((v << s) | (v >>> (8 - s))) & 0xff;
    }
    case 'ror8': {
      const v = evalNode(node.args[0], env) & 0xff;
      const s = evalNode(node.args[1], env) & 7;
      return ((v >>> s) | (v << (8 - s))) & 0xff;
    }
    default:
      fail('CANDIDATE_EVAL_UNSUPPORTED', `Unsupported op "${node.op}"`);
  }
}

function computeTrailerChecksumBytes(kind, initVal, dataBuf) {
  if (kind === 'none') return Buffer.alloc(0);
  if (kind === 'xor8') {
    let acc = initVal & 0xff;
    for (const b of dataBuf) acc = (acc ^ b) & 0xff;
    return Buffer.from([acc]);
  }
  if (kind === 'sum8') {
    let acc = initVal & 0xff;
    for (const b of dataBuf) acc = (acc + b) & 0xff;
    return Buffer.from([acc]);
  }
  if (kind === 'crc16ccitt-be' || kind === 'crc16ccitt-le') {
    let crc = initVal & 0xffff;
    for (const b of dataBuf) {
      crc ^= (b << 8) & 0xffff;
      for (let bit = 0; bit < 8; bit += 1) {
        crc = (crc & 0x8000) ? (((crc << 1) ^ 0x1021) & 0xffff) : ((crc << 1) & 0xffff);
      }
    }
    const out = Buffer.alloc(2);
    if (kind.endsWith('-be')) out.writeUInt16BE(crc, 0);
    else out.writeUInt16LE(crc, 0);
    return out;
  }
  if (kind === 'fnv1a32-be' || kind === 'fnv1a32-le') {
    let h = initVal >>> 0;
    for (const b of dataBuf) {
      h ^= b;
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    const out = Buffer.alloc(4);
    if (kind.endsWith('-be')) out.writeUInt32BE(h, 0);
    else out.writeUInt32LE(h, 0);
    return out;
  }
  return Buffer.alloc(0);
}

export function evaluateBoundedTransform(executableRule, inputHex) {
  if (typeof inputHex !== 'string' || inputHex.length === 0 || inputHex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(inputHex)) {
    fail('CANDIDATE_EVAL_INVALID_INPUT', 'Scenario inputHex must be a non-empty even-length hex string');
  }
  const input = Buffer.from(inputHex, 'hex');
  const consts = Object.fromEntries(
    Object.entries(executableRule.constants || {}).map(([k, hex]) => [k, Buffer.from(hex, 'hex')]),
  );

  if (executableRule.schema === 'ig5-bounded-frame-rule-v1') {
    if (input.length < 1 || input.length > 240) {
      fail('CANDIDATE_EVAL_INPUT_LENGTH', `Frame rule input length (${input.length}) out of bounded range 1..240`);
    }
    const headerBuf = executableRule.headerHex ? Buffer.from(executableRule.headerHex, 'hex') : Buffer.alloc(0);
    const bodyBuf = Buffer.alloc(input.length);
    let prev = (executableRule.prevInit ?? 0) & 0xff;
    for (let i = 0; i < input.length; i += 1) {
      const val = evalNode(executableRule.bodyByteExpr, { i, input, consts, buf: bodyBuf, prev }) & 0xff;
      bodyBuf[i] = val;
      prev = val;
    }
    const csumKind = executableRule.trailerChecksum?.kind || 'none';
    const csumWidth = csumKind === 'none' ? 0 : (csumKind.endsWith('8') ? 1 : csumKind.includes('16') ? 2 : 4);
    const lenKind = executableRule.lengthField?.kind || 'none';
    const lenWidth = lenKind === 'none' ? 0 : (lenKind.includes('u16') ? 2 : 1);
    const lenBias = executableRule.lengthField?.bias || 0;
    let lenBuf = Buffer.alloc(lenWidth);
    if (lenKind === 'payload-len-u8') {
      lenBuf[0] = (bodyBuf.length + lenBias) & 0xff;
    } else if (lenKind === 'payload-len-u16be') {
      lenBuf.writeUInt16BE((bodyBuf.length + lenBias) & 0xffff, 0);
    } else if (lenKind === 'payload-len-u16le') {
      lenBuf.writeUInt16LE((bodyBuf.length + lenBias) & 0xffff, 0);
    } else if (lenKind === 'total-len-u8') {
      lenBuf[0] = (headerBuf.length + lenWidth + bodyBuf.length + csumWidth + lenBias) & 0xff;
    }
    const prefixAndBody = Buffer.concat([headerBuf, lenBuf, bodyBuf]);
    const csumTarget = executableRule.trailerChecksum?.scope === 'body' ? bodyBuf : prefixAndBody;
    const trailerBuf = computeTrailerChecksumBytes(csumKind, executableRule.trailerChecksum?.init ?? 0, csumTarget);
    const fullFrame = Buffer.concat([prefixAndBody, trailerBuf]);
    if (fullFrame.length > 256) {
      fail('CANDIDATE_EVAL_OUTPUT_LIMIT', `Evaluated frame (${fullFrame.length} bytes) exceeds bounded 256-byte cap`);
    }
    return fullFrame.toString('hex');
  }

  if (executableRule.inputLength !== undefined && input.length !== executableRule.inputLength) {
    fail('CANDIDATE_EVAL_INPUT_LENGTH', `Input length (${input.length}) does not match executableRule.inputLength (${executableRule.inputLength})`);
  }
  if (executableRule.byteExpr !== undefined) {
    const out = Buffer.alloc(executableRule.outputLength);
    const exprList = Array.isArray(executableRule.byteExpr) ? executableRule.byteExpr : null;
    for (let i = 0; i < executableRule.outputLength; i++) {
      const exprNode = exprList ? exprList[i] : executableRule.byteExpr;
      out[i] = evalNode(exprNode, { i, input, consts, buf: null }) & 0xff;
    }
    return out.toString('hex');
  }
  const buf = Buffer.alloc(executableRule.stateLength || executableRule.outputLength, 0);
  if (executableRule.initFromInput) {
    input.copy(buf, 0, 0, Math.min(input.length, buf.length));
  }
  let totalOps = 0;
  for (const step of executableRule.steps) {
    const repeat = step.repeat ?? 1;
    for (let i = 0; i < repeat; i++) {
      totalOps += 1;
      if (totalOps > 4096) fail('CANDIDATE_EVAL_STEP_LIMIT', 'executableRule exceeded 4096 bounded iterations');
      const targetIdx = evalNode(step.targetIndex, { i, input, consts, buf });
      if (targetIdx >= buf.length) fail('CANDIDATE_EVAL_OOB', `State write index ${targetIdx} out of bounds (${buf.length})`);
      buf[targetIdx] = evalNode(step.valueExpr, { i, input, consts, buf }) & 0xff;
    }
  }
  return buf.subarray(0, executableRule.outputLength).toString('hex');
}

export function extractObservedOutputHex(artifactRecord, outputSpec) {
  const body = artifactRecord?.result || {};
  const out = body.replayOutput || {};
  const metrics = body.observedMetrics || {};
  const cleanArgs = body.cleanArgsSummary || {};

  if (outputSpec.kind === 'memory') {
    const rawHex = typeof out.hex === 'string' ? out.hex : (typeof metrics.dataHex === 'string' ? metrics.dataHex : null);
    if (!rawHex) {
      return { ok: false, reason: 'receipt-has-no-memory-bytes' };
    }
    const memHex = rawHex.replace(/^0x/i, '').replace(/\s+/g, '').toLowerCase();
    // Match debugger argument semantics: explicit rva wins over ea/address_space.
    // Missing legacy address_space means runtime EA, never an inferred RVA.
    const hasRva = cleanArgs.rva !== undefined;
    const addressSpace = cleanArgs.address_space === undefined ? 'runtime' : cleanArgs.address_space;
    if (outputSpec.rva) {
      const actualRva = hasRva
        ? normalizeHexAddress(cleanArgs.rva)
        : addressSpace === 'rva' ? normalizeHexAddress(cleanArgs.ea) : null;
      if (actualRva !== outputSpec.rva) {
        return { ok: false, reason: `memory-rva-mismatch(expected=${outputSpec.rva},actual=${actualRva || 'absent'})` };
      }
    }
    if (outputSpec.ea) {
      const actualEa = !hasRva && addressSpace === 'runtime' ? normalizeHexAddress(cleanArgs.ea) : null;
      if (actualEa !== outputSpec.ea) {
        return { ok: false, reason: `memory-ea-mismatch(expected=${outputSpec.ea},actual=${actualEa || 'absent'})` };
      }
    }
    if (cleanArgs.size !== undefined && cleanArgs.size !== outputSpec.byteLength) {
      return { ok: false, reason: `memory-size-arg-mismatch(expected=${outputSpec.byteLength},actual=${cleanArgs.size})` };
    }
    if (memHex.length !== outputSpec.byteLength * 2) {
      return { ok: false, reason: `memory-width-mismatch(expectedBytes=${outputSpec.byteLength},actualHexChars=${memHex.length})` };
    }
    return { ok: true, observedHex: memHex };
  }

  if (outputSpec.kind === 'register') {
    const regs = out.regs || metrics.regsSample;
    if (!regs || typeof regs !== 'object') {
      return { ok: false, reason: 'receipt-has-no-registers' };
    }
    const foundEntry = Object.entries(regs).find(([k]) => k.toLowerCase() === outputSpec.register);
    if (!foundEntry) {
      return { ok: false, reason: `register-not-present(${outputSpec.register})` };
    }
    const rawStr = String(foundEntry[1]).trim().toLowerCase().replace(/^0x/, '');
    if (!/^[0-9a-f]{1,16}$/.test(rawStr)) {
      return { ok: false, reason: `invalid-register-hex(${outputSpec.register})` };
    }
    const mask = (1n << BigInt(outputSpec.byteLength * 8)) - 1n;
    const val = BigInt('0x' + rawStr) & mask;
    const buf = Buffer.alloc(outputSpec.byteLength);
    for (let i = 0; i < outputSpec.byteLength; i++) {
      const byteIdx = outputSpec.endian === 'little' ? i : (outputSpec.byteLength - 1 - i);
      buf[byteIdx] = Number((val >> BigInt(i * 8)) & 0xffn);
    }
    return { ok: true, observedHex: buf.toString('hex') };
  }

  if (outputSpec.kind === 'module-memory') {
    const rawHex = typeof out.hex === 'string' ? out.hex : (typeof metrics.dataHex === 'string' ? metrics.dataHex : null);
    if (!rawHex) return { ok: false, reason: 'receipt-has-no-memory-bytes' };
    const memHex = rawHex.replace(/^0x/i, '').replace(/\s+/g, '').toLowerCase();
    const ctx = out.context || body.runtimeIdentity?.context || {};
    const actualMod = typeof ctx.module === 'string' ? ctx.module.trim().toLowerCase() : null;
    if (!actualMod || actualMod !== outputSpec.module) {
      return { ok: false, reason: `module-name-mismatch(expected=${outputSpec.module},actual=${actualMod || 'unmapped'})` };
    }
    const actualRva = normalizeHexAddress(ctx.RVA);
    if (actualRva !== outputSpec.rva) {
      return { ok: false, reason: `module-rva-mismatch(expected=${outputSpec.rva},actual=${actualRva || 'absent'})` };
    }
    if (memHex.length !== outputSpec.byteLength * 2) {
      return { ok: false, reason: `module-memory-width-mismatch(expectedBytes=${outputSpec.byteLength},actualHexChars=${memHex.length})` };
    }
    return { ok: true, observedHex: memHex, moduleBase: ctx.moduleBase || null, moduleSha256: ctx.moduleSha256 || null };
  }

  if (outputSpec.kind === 'app-output') {
    const rawHex = typeof out.outputHex === 'string' ? out.outputHex.trim().toLowerCase() : null;
    if (!rawHex || !/^[0-9a-f]+$/.test(rawHex) || rawHex.length % 2 !== 0) {
      return { ok: false, reason: 'app-observe-receipt-missing-outputHex' };
    }
    const actualBytes = rawHex.length / 2;
    if (outputSpec.byteLength !== undefined && actualBytes !== outputSpec.byteLength) {
      return { ok: false, reason: `app-output-width-mismatch(expectedBytes=${outputSpec.byteLength},actualHexChars=${rawHex.length})` };
    }
    if (outputSpec.minByteLength !== undefined && (actualBytes < outputSpec.minByteLength || actualBytes > outputSpec.maxByteLength)) {
      return { ok: false, reason: `app-output-variable-bounds-mismatch(actualBytes=${actualBytes},bounds=${outputSpec.minByteLength}..${outputSpec.maxByteLength})` };
    }
    return { ok: true, observedHex: rawHex };
  }

  if (outputSpec.kind === 'emulate-capture') {
    if (outputSpec.ea) {
      const caps = Array.isArray(out.memory)
        ? out.memory
        : (Array.isArray(out.captures) ? out.captures : (Array.isArray(out.captured) ? out.captured : []));
      const hit = caps.find((c) => normalizeHexAddress(c?.ea) === outputSpec.ea);
      if (!hit || typeof hit.hex !== 'string') {
        return { ok: false, reason: `emulate-capture-ea-not-present(${outputSpec.ea})` };
      }
      const clean = hit.hex.trim().toLowerCase();
      if (clean.length !== outputSpec.byteLength * 2) {
        return { ok: false, reason: `emulate-capture-width-mismatch(${clean.length})` };
      }
      return { ok: true, observedHex: clean };
    }
    const regs = out.registers || out.regs || metrics.regsSample;
    const retRaw = regs?.[outputSpec.register] ?? (outputSpec.register === 'eax' || outputSpec.register === 'rax' ? out.return_value ?? out.returnValue : undefined);
    if (retRaw === undefined || retRaw === null) {
      return { ok: false, reason: `emulate-register-not-present(${outputSpec.register})` };
    }
    const hexClean = String(retRaw).trim().toLowerCase().replace(/^0x/, '');
    if (!/^[0-9a-f]{1,16}$/.test(hexClean)) {
      return { ok: false, reason: `invalid-emulate-register-hex(${outputSpec.register})` };
    }
    const mask = (1n << BigInt(outputSpec.byteLength * 8)) - 1n;
    const val = BigInt('0x' + hexClean) & mask;
    const buf = Buffer.alloc(outputSpec.byteLength);
    for (let i = 0; i < outputSpec.byteLength; i++) {
      const byteIdx = outputSpec.endian === 'little' ? i : (outputSpec.byteLength - 1 - i);
      buf[byteIdx] = Number((val >> BigInt(i * 8)) & 0xffn);
    }
    return { ok: true, observedHex: buf.toString('hex') };
  }

  return { ok: false, reason: 'unsupported-output-spec' };
}
