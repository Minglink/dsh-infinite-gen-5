import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { auditRecords, targetIdentity } from './audit_history.js';

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const sameFile = (left, right) => ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => left[key] === right[key]);
async function fileHash(handle, size) {
  const hash = createHash('sha256'), buffer = Buffer.alloc(1024 * 1024);
  for (let offset = 0; offset < size;) {
    const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, size - offset), offset);
    if (!bytesRead) fail('INPUT_CHANGED', 'Target became shorter while exporting');
    hash.update(buffer.subarray(0, bytesRead)); offset += bytesRead;
  }
  return hash.digest('hex');
}
async function exportDirectory(cfg, session) {
  const root = path.resolve(cfg.artifactDir), identities = [];
  for (const part of [root, path.join(root, 'exports'), path.join(root, 'exports', session.artifactId), path.join(root, 'exports', session.artifactId, session.engine)]) {
    await fs.promises.mkdir(part, { recursive: true });
    const stat = await fs.promises.lstat(part, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail('INVALID_OUTPUT', 'Export directories must be regular non-linked directories');
    identities.push({ part, dev: stat.dev, ino: stat.ino });
  }
  return { directory: identities.at(-1).part, verify: async () => {
    for (const expected of identities) { const stat = await fs.promises.lstat(expected.part, { bigint: true }); if (!stat.isDirectory() || stat.isSymbolicLink() || stat.dev !== expected.dev || stat.ino !== expected.ino) fail('INVALID_OUTPUT', 'Export directory was replaced'); }
  } };
}

/** Export current database bytes only from audit rows bound to this artifact and database. */
export async function exportPatchDiff({ target, mgr, cfg }) {
  const session = mgr.get(target);
  if (!mgr.alive(session) || !session.artifactId || !session.sha256 || !session.attachmentId)
    fail('NOT_OPEN', 'Open the target before exporting its patch diff');
  const platform = cfg.host?.platform || process.platform, expectedPath = targetIdentity(target, platform);
  const currentAttachment = mgr.projects.getAttachment(session.attachmentId);
  if (!/^[\w.-]+$/.test(session.artifactId) || ['.', '..'].includes(session.artifactId) || !['reverse', 'ghidra'].includes(session.engine)) fail('INVALID_OUTPUT', 'Invalid artifact export identity');
  const databaseMatches = new Map([[session.attachmentId, true]]);
  const patches = new Map(), excludedHistory = { foreignArtifact: 0, foreignDatabase: 0, unbound: 0 }; let rangeBytes = 0;
  for await (const row of auditRecords(path.join(cfg.artifactDir, 'approvals.jsonl'))) {
    mgr.checkCancelled?.();
    if (!['ig5_patch_bytes', 'ig5_sync'].includes(row.tool) || row.isError || targetIdentity(row.args?.target, platform) !== expectedPath) continue;
    const candidates = row.tool === 'ig5_sync' ? (row.detail?.applied || []).filter(value => value.kind === 'patch').map(value => value.result) : [row.detail];
    if (!candidates.some(value => value?.applied)) continue;
    const evidence = row.detail?.destination || row.detail?._ig5;
    if ((evidence?.engine || row.args?.engine || 'reverse') !== session.engine) continue;
    if (!evidence?.artifactId || !evidence.sha256 || !evidence.attachmentId) { excludedHistory.unbound++; continue; }
    if (evidence.artifactId !== session.artifactId || evidence.sha256 !== session.sha256) { excludedHistory.foreignArtifact++; continue; }
    if (!databaseMatches.has(evidence.attachmentId)) {
      let matches = false;
      try { const previous = mgr.projects.getAttachment(evidence.attachmentId); matches = previous.databaseId === currentAttachment.databaseId
        && previous.artifactId === session.artifactId && previous.engine === session.engine; } catch {}
      databaseMatches.set(evidence.attachmentId, matches);
    }
    if (!databaseMatches.get(evidence.attachmentId)) { excludedHistory.foreignDatabase++; continue; }
    for (const patch of candidates) {
      if (!patch?.applied) continue;
      if (!Number.isSafeInteger(patch.fileOffset) || patch.fileOffset < 0 || !Number.isSafeInteger(patch.size) || patch.size < 1 || patch.size > 4096
          || typeof patch.ea !== 'string' || !/^0x[0-9a-f]{1,16}$/i.test(patch.ea)
          || typeof patch.after !== 'string' || !/^[0-9a-f]+$/i.test(patch.after) || patch.after.length !== patch.size * 2)
        fail('INVALID_PATCH_EVIDENCE', 'An audited patch has invalid address, file range or byte evidence');
      const rangeKey = `${patch.ea.toLowerCase()}:${patch.fileOffset}:${patch.size}`;
      if (!patches.has(rangeKey)) rangeBytes += patch.size;
      if (rangeBytes > 8 * 1024 * 1024) fail('EXPORT_LIMIT', 'Audited patch ranges exceed the 8 MiB delivery budget');
      patches.set(rangeKey, patch);
      if (patches.size > 16384) fail('EXPORT_LIMIT', 'Patch export exceeds 16,384 distinct ranges; split the delivery');
    }
  }
  if (excludedHistory.unbound) fail('UNBOUND_PATCH_HISTORY', 'Patch history for this path lacks sample identity; recover or archive its legacy evidence before exporting');
  if (!patches.size) return { target, patches: 0, excludedHistory, note: '当前样本和数据库没有已绑定的字节补丁记录' };
  const before = await fs.promises.lstat(target, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.size > BigInt(Number.MAX_SAFE_INTEGER)) fail('INVALID_INPUT', 'Export target must be a regular non-linked file');
  const original = await fs.promises.open(target, 'r');
  let stage, reportStage, output;
  try {
    if (!sameFile(before, await original.stat({ bigint: true }))) fail('INPUT_CHANGED', 'Target changed while opening');
    const size = Number(before.size);
    if (await fileHash(original, size) !== session.sha256) fail('INPUT_CHANGED', 'Target file changed; reopen it before exporting');
    const rows = [], report = ['# IG5 补丁报告', '', `目标: ${target}`, `样本 SHA-256: ${session.sha256}`, `引擎: ${session.engine}`, '', '| EA | 文件偏移 | before | after |', '|---|---|---|---|'];
    for (const patch of patches.values()) {
      mgr.checkCancelled?.();
      if (patch.fileOffset + patch.size > size) fail('INVALID_PATCH_EVIDENCE', 'Audited patch extends beyond the target file');
      const mapping = await mgr.rpc(session, 'fileoffset', { ea: patch.ea, size: patch.size });
      if (mapping.contiguous !== true || mapping.size !== patch.size || mapping.fileOffset !== patch.fileOffset)
        fail('PATCH_MAPPING_CHANGED', 'Current database mapping does not match the complete audited file range');
      const current = await mgr.rpc(session, 'bytes', { ea: patch.ea, size: patch.size });
      if (typeof current.hex !== 'string' || !/^[0-9a-f]+$/i.test(current.hex) || current.hex.length !== patch.size * 2)
        fail('INVALID_PATCH_EVIDENCE', 'Could not read a complete current database patch range');
      const previous = Buffer.alloc(patch.size);
      for (let position = 0; position < patch.size;) { const read = await original.read(previous, position, patch.size - position, patch.fileOffset + position); if (!read.bytesRead) fail('INPUT_CHANGED', 'Original patch range became shorter'); position += read.bytesRead; }
      const bytes = Buffer.from(current.hex, 'hex');
      rows.push({ ...patch, bytes, before: previous.toString('hex'), after: bytes.toString('hex') });
    }
    const slug = path.basename(target).replace(/[^\w.-]+/g, '_');
    const destinations = await exportDirectory(cfg, session), directory = destinations.directory;
    const outBin = path.join(directory, `${slug}.ig5-patched`), outMd = path.join(directory, `${slug}.changes.md`);
    if ([outBin, outMd].some(filename => targetIdentity(filename, platform) === expectedPath)) fail('INVALID_OUTPUT', 'Export must not overwrite its source');
    stage = path.join(directory, `.export-${randomUUID()}.partial`);
    output = await fs.promises.open(stage, 'wx+', 0o600);
    const buffer = Buffer.alloc(1024 * 1024);
    for (let position = 0; position < size;) {
      mgr.checkCancelled?.();
      const read = await original.read(buffer, 0, Math.min(buffer.length, size - position), position);
      if (!read.bytesRead) fail('INPUT_CHANGED', 'Source file changed during export');
      let written = 0;
      while (written < read.bytesRead) { const result = await output.write(buffer, written, read.bytesRead - written, position + written); if (!result.bytesWritten) fail('EXPORT_FAILED', 'Could not write export'); written += result.bytesWritten; }
      position += read.bytesRead;
    }
    for (const row of rows) { let written = 0; while (written < row.bytes.length) { const value = await output.write(row.bytes, written, row.bytes.length - written, row.fileOffset + written); if (!value.bytesWritten) fail('EXPORT_FAILED', 'Could not write patch'); written += value.bytesWritten; } }
    let applied = 0, reportBytes = Buffer.byteLength(report.join('\n'));
    for (const row of rows) if (row.before !== row.after) { const line = `| ${row.ea} | ${row.fileOffset} | ${row.before} | ${row.after} |`; reportBytes += Buffer.byteLength(line) + 1; if (reportBytes > 4 * 1024 * 1024) fail('EXPORT_LIMIT', 'Changes report exceeds its 4 MiB budget'); applied++; report.push(line); }
    if (!sameFile(before, await original.stat({ bigint: true })) || !sameFile(before, await fs.promises.lstat(target, { bigint: true }))) fail('INPUT_CHANGED', 'Target changed during export');
    await output.sync(); await output.close(); output = null;
    reportStage = path.join(directory, `.report-${randomUUID()}.partial`);
    await fs.promises.writeFile(reportStage, report.join('\n') + '\n', { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await destinations.verify();
    await fs.promises.rename(stage, outBin); stage = null;
    try { await fs.promises.rename(reportStage, outMd); reportStage = null; }
    catch (error) { fail('EXPORT_PARTIAL', `Binary exported at ${outBin}; report commit failed (${error.code || 'unknown'}). Inspect delivery before retrying.`); }
    const derived = mgr.projects.open(outBin, { projectId: session.projectId, ...(applied ? { derivedFrom: session.artifactId } : {}) });
    return { target, patches: applied, auditedRegions: rows.length, excludedHistory, patchedBinary: outBin, report: outMd,
      projectId: derived.projectId, derivedArtifactId: derived.artifactId, sampleSha256: session.sha256 };
  } finally {
    await original.close(); if (output) await output.close();
    if (stage) await fs.promises.unlink(stage).catch(() => {});
    if (reportStage) await fs.promises.unlink(reportStage).catch(() => {});
  }
}
