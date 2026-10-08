import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { createAddressRef, convertAddress } from './source/address_ref.js';

const digest = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const renderDefault = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 1) }];
const fields = { rename: 'name', comment: 'comment', patch: 'hex' };

function mapped(session, rva, size = 1) {
  if (!session.info?.imageBase) throw new Error('Engine did not provide an image base; cannot map an RVA');
  const ref = createAddressRef({ artifactId: session.artifactId, space: 'static', kind: 'rva', value: rva });
  const ea = convertAddress(ref, { space: 'static', kind: 'va' }, { imageBase: session.info.imageBase }).value;
  const start = BigInt(ea), end = start + BigInt(size);
  if (!session.info.segments?.some((segment) => start >= BigInt(segment.start) && end <= BigInt(segment.end))) {
    throw new Error('Selected RVA range is outside the loaded image');
  }
  return ea;
}

function opened(mgr, target, engine) {
  if (!['reverse', 'ghidra'].includes(engine)) throw new Error('Select reverse or ghidra explicitly');
  const session = mgr.get(target, engine);
  if (!mgr.alive(session)) throw new Error(`${engine} target is not open`);
  return session;
}

export function defineIntegrationTools(mgr, cfg, render = renderDefault) {
  const directory = path.join(cfg.projectRoot, 'changesets');
  const filename = (id) => {
    if (!/^[0-9a-f-]{36}$/.test(String(id))) throw new Error('Invalid changeset identifier');
    return path.join(directory, id + '.json');
  };
  const verify = (session, expected) => {
    if (session.attachmentId !== expected.attachmentId || session.dbRevision !== expected.dbRevision || session.sha256 !== expected.sha256) {
      throw new Error('Changeset context is stale; generate and review a new preview');
    }
    if (createHash('sha256').update(fs.readFileSync(session.target)).digest('hex') !== expected.sha256) {
      throw new Error('Target file changed; reopen it and generate a new preview');
    }
  };
  return [
    {
      name: 'ig5_ir',
      description: 'Inspect actual Ghidra raw or high p-code for an opened function. Identifies IR kind and source engine; these levels are distinct from Reverse microcode maturities. Read-only and bounded.',
      parameters: { type: 'object', properties: { target: { type: 'string' }, ea: { type: 'string' }, name: { type: 'string' },
        level: { type: 'string', enum: ['raw', 'high'] }, max_blocks: { type: 'number' }, max_instructions: { type: 'number' } }, required: ['target'], additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render },
      execute(args) {
        const session = opened(mgr, args.target, 'ghidra');
        if (args.engine && args.engine !== 'ghidra') throw new Error('ig5_ir requires engine=ghidra; use ig5_microcode for Reverse');
        return mgr.rpc(session, 'ir', args);
      },
    },
    {
      name: 'ig5_sync',
      description: 'Preview or apply an explicit one-way changeset between two opened databases for the SAME binary hash. Copies selected names, EOL comments or bounded bytes by RVA. Preview includes before/after evidence and a digest. Apply requires that digest, rechecks hash, database revisions and current values, and remains approval-gated. Partial failures report applied rows; there is no cross-engine atomic Undo.',
      parameters: { type: 'object', properties: {
        action: { type: 'string', enum: ['preview', 'apply'] }, target: { type: 'string' },
        source_engine: { type: 'string', enum: ['reverse', 'ghidra'] }, destination_engine: { type: 'string', enum: ['reverse', 'ghidra'] },
        selections: { type: 'array', items: { type: 'object', properties: {
          kind: { type: 'string', enum: ['rename', 'comment', 'patch'] }, rva: { type: 'string' }, size: { type: 'number' } }, required: ['kind', 'rva'], additionalProperties: false } },
        plan_id: { type: 'string' }, plan_digest: { type: 'string' },
      }, required: ['action', 'target'], additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render },
      async execute(args) {
        if (args.action === 'preview') {
          const source = opened(mgr, args.target, args.source_engine);
          const destination = opened(mgr, args.target, args.destination_engine);
          if (source === destination || source.sha256 !== destination.sha256) throw new Error('Select two distinct engines for the same artifact hash');
          if (!Array.isArray(args.selections) || !args.selections.length || args.selections.length > 64) throw new Error('Select between 1 and 64 explicit changes');
          const context = { source: mgr.evidence(source), destination: mgr.evidence(destination) };
          const rows = [], selected = new Set();
          for (const selection of args.selections) {
            if (!Object.hasOwn(fields, selection.kind)) throw new Error('Unsupported change kind');
            const size = selection.kind === 'patch' ? selection.size : 1;
            if (!Number.isSafeInteger(size) || size < 1 || size > 4096) throw new Error('Patch size must be 1..4096 bytes');
            const sourceEA = mapped(source, selection.rva, size), destinationEA = mapped(destination, selection.rva, size);
            const key = selection.kind + ':' + destinationEA;
            if (selected.has(key)) throw new Error('Duplicate changeset selection');
            if (selection.kind === 'patch' && rows.some((row) => row.kind === 'patch'
              && BigInt(destinationEA) < BigInt(row.destinationEA) + BigInt(row.size)
              && BigInt(row.destinationEA) < BigInt(destinationEA) + BigInt(size))) throw new Error('Overlapping patch selections are not supported');
            selected.add(key);
            const [left, right] = await Promise.all([
              mgr.rpc(source, 'inspect', { ea: sourceEA, size }), mgr.rpc(destination, 'inspect', { ea: destinationEA, size }),
            ]);
            const field = fields[selection.kind];
            const before = right[field] || '', after = left[field] || '';
            if (selection.kind === 'rename' && !after) throw new Error('Source address has no name to copy');
            if (selection.kind === 'patch' && (before.length !== size * 2 || after.length !== size * 2)) throw new Error('Incomplete byte evidence');
            if (before !== after) rows.push({ kind: selection.kind, rva: selection.rva, sourceEA, destinationEA, size, before, after });
          }
          verify(source, context.source); verify(destination, context.destination);
          const plan = { schema: 1, id: randomUUID(), target: path.resolve(args.target), createdAt: new Date().toISOString(), ...context, rows };
          const planDigest = digest(plan);
          fs.mkdirSync(directory, { recursive: true });
          fs.writeFileSync(filename(plan.id), JSON.stringify({ plan, digest: planDigest }, null, 2), { flag: 'wx' });
          return { action: 'preview', plan_id: plan.id, plan_digest: planDigest, ...plan, _ig5: context.destination, note: 'Review all rows before applying. Names and comments do not imply matching data types.' };
        }
        if (args.action !== 'apply') throw new Error('action must be preview or apply');
        const file = filename(args.plan_id);
        const record = JSON.parse(fs.readFileSync(file, 'utf8'));
        const { plan } = record;
        if (record.applied || record.attempted) throw new Error('This changeset has already been attempted; create a fresh preview');
        if (digest(plan) !== record.digest || args.plan_digest !== record.digest) throw new Error('Changeset digest does not match the reviewed preview');
        if (path.resolve(args.target).toLowerCase() !== plan.target.toLowerCase()) throw new Error('Changeset target mismatch');
        const source = opened(mgr, args.target, plan.source.engine);
        const destination = opened(mgr, args.target, plan.destination.engine);
        const apply = async () => {
          mgr.checkCancelled?.();
          // Another call may have consumed this file while this request waited.
          const latest = JSON.parse(fs.readFileSync(file, 'utf8'));
          if (latest.attempted || latest.applied) throw new Error('This changeset has already been attempted; create a fresh preview');
          verify(source, plan.source); verify(destination, plan.destination);
          // Recheck every row before the first mutation, including overlapping byte ranges.
          for (const row of plan.rows) {
            const [left, right] = await Promise.all([mgr.rpc(source, 'inspect', { ea: row.sourceEA, size: row.size }),
              mgr.rpc(destination, 'inspect', { ea: row.destinationEA, size: row.size })]);
            if ((left[fields[row.kind]] || '') !== row.after || (right[fields[row.kind]] || '') !== row.before) throw new Error('Changeset before/after evidence changed');
          }
          mgr.checkCancelled?.();
          verify(source, plan.source); verify(destination, plan.destination);
          record.attempted = new Date().toISOString();
          fs.writeFileSync(file, JSON.stringify(record, null, 2));
          const applied = [];
          let error, failed;
          for (const row of plan.rows) {
            try {
              mgr.checkCancelled?.();
              const params = row.kind === 'rename' ? { ea: row.destinationEA, new_name: row.after }
                : row.kind === 'comment' ? { ea: row.destinationEA, text: row.after }
                  : { ea: row.destinationEA, hex: row.after, expected: row.before };
              const result = await mgr.rpc(destination, row.kind, params);
              if (result?.ok === false) throw new Error(result.error || 'Engine rejected the change');
              applied.push({ ...row, result });
            } catch (failure) {
              error = failure.message;
              failed = { row };
              for (const field of ['code', 'committed', 'saved', 'recoveryRequired', 'stage', 'journalId', 'revision', 'durableRevision']) {
                if (failure[field] !== undefined) failed[field] = failure[field];
              }
              break;
            }
          }
          record.applied = applied; record.error = error; record.failed = failed; record.finishedAt = new Date().toISOString();
          fs.writeFileSync(file, JSON.stringify(record, null, 2));
          return { ok: !error, action: 'apply', plan_id: plan.id, applied, remaining: plan.rows.slice(applied.length),
            error, failed, destination: mgr.evidence(destination), _ig5: mgr.evidence(destination), atomic: false,
            note: 'Remaining rows are unconfirmed, not necessarily unchanged. A failed primitive may have committed; inspect failed.committed/saved/recoveryRequired and recover the destination before generating another plan.' };
        };
        // Both participating databases are locked, so another approved tool cannot mutate a source halfway through the plan.
        return mgr.withSessions([source, destination], apply);
      },
    },
  ];
}
