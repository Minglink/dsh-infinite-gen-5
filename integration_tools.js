import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { createAddressRef, convertAddress } from './source/address_ref.js';
import { KernelJobs } from './source/kernel_jobs.js';
import { TraceJobs } from './source/trace_jobs.js';
import { LiftJobs } from './source/lift_jobs.js';
import { runProjection, validateProjection } from './source/projection_jobs.js';
import { runComposition, validateComposition } from './source/composition_jobs.js';
import { runDiscovery, validateDiscovery } from './source/path_discovery_jobs.js';
import { jsonToolOutput } from './source/json_output.js';

const digest = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const renderDefault = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 1) }];
const fields = { rename: 'name', comment: 'comment', patch: 'hex' };
const compositionPath = { type: 'array', minItems: 1, maxItems: 128, uniqueItems: true,
  items: { type: 'string', pattern: '^0x[0-9a-fA-F]{1,16}$' } };

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
      description: 'Read-only IR/p-code (raw/high/kernel), trace replay, LLVM lift, discover, project, and compose.',
      parameters: { type: 'object', properties: { target: { type: 'string' }, ea: { type: 'string' }, name: { type: 'string' },
        level: { type: 'string', enum: ['raw', 'high', 'kernel', 'trace', 'lift', 'project', 'compose','discover'] }, action: { type: 'string', enum: ['info', 'analyze', 'vtables', 'decompile'] },
        follow_direct_calls: { type: 'boolean' },
        composition_plan: { type: 'object',
          properties: { strategy: { type: 'string', enum: ['sequence', 'constant-loop'] },
            representation: { type: 'string', enum: ['flat', 'transition-chain'] },
            template_mode: { type: 'string', enum: ['strict', 'opaque-effects', 'opaque-status'] },
            paths: { type: 'array', minItems: 1, maxItems: 64, items: compositionPath },
            prefix: compositionPath, body: compositionPath,
            suffix: { type: 'array', minItems: 1, maxItems: 63, items: compositionPath },
            indirect_mode: { type: 'string', enum: ['reject', 'guarded-target'] } },
          required: ['strategy'], additionalProperties: false },
        composition_plan_ref: { type: 'object',
          properties: { path: { type: 'string', maxLength: 4096 }, sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' } }, required: ['path', 'sha256'], additionalProperties: false },
        projection_mode: { type: 'string', enum: ['strict', 'guarded-path', 'opaque-effects', 'opaque-status'] },
        projection_decoder: { type: 'string', enum: ['native', 'java'] },
        projection_path: { type: 'array', minItems: 1, maxItems: 128, uniqueItems: true, items: { type: 'string', pattern: '^0x[0-9a-fA-F]{1,16}$' } },
        projection_registers: { type: 'array', minItems: 1, maxItems: 16, uniqueItems: true, items: { type: 'string', enum: ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15'] } },
        lift_inline: { type: 'array', maxItems: 16, uniqueItems: true, items: { type: 'string', pattern: '^0x[0-9a-fA-F]{1,16}$' } },
        traces: { type: 'array', minItems: 1, maxItems: 2, items: { type: 'object', properties: { path: { type: 'string' }, sha256: { type: 'string' }, trace_image: { type: 'object', properties: { report_path: { type: 'string' }, report_sha256: { type: 'string' } }, required: ['report_path', 'report_sha256'], additionalProperties: false }, recording: { type: 'object', properties: { entry: { type: 'string' }, exit: { type: 'string' }, runtimeBase: { type: 'string' }, initialFlags: { type: 'string' } }, required: ['entry', 'exit', 'runtimeBase', 'initialFlags'], additionalProperties: false } }, required: ['path', 'sha256'], additionalProperties: false } },
        trace_chunk_reports: { type: 'array', minItems: 1, maxItems: 256, items: { type: 'string' } },
        trace_entry: { type: 'string' }, trace_exit: { type: 'string' },
        trace_image: { type: 'object', properties: { report_path: { type: 'string' }, report_sha256: { type: 'string' } }, required: ['report_path', 'report_sha256'], additionalProperties: false },
        trace_image_only: { type: 'boolean' },
        trace_target_sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' },
        trace_inputs: { type: 'array', minItems: 2, maxItems: 2, items: { type: 'string', enum: ['dil', 'sil', 'di', 'si', 'edi', 'esi', 'rdi', 'rsi', 'cl', 'dl', 'cx', 'dx', 'ecx', 'edx', 'rcx', 'rdx'] } },
        trace_runtime_base: { type: 'string' },
        trace_output: { type: 'string', enum: ['al', 'ax', 'eax', 'rax'] }, initial_flags: { type: 'string' },
        optimize: { type: 'boolean' },
        max_code_bytes: { type: 'number' }, abi: { type: 'string', enum: ['auto', 'msvc', 'itanium'] }, offset: { type: 'number' },
        max_slots: { type: 'number' }, max_bases: { type: 'number' }, max_scan_bytes: { type: 'number' }, limit: { type: 'number' },
        max_blocks: { type: 'number' }, max_instructions: { type: 'number' } }, required: ['target'], additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: (args, value) => args?.level === 'trace' && value?.previewCompactJSON === true
        ? [{ type: 'text', text: JSON.stringify(jsonToolOutput(value)) }] : render(args, value) },
      execute(args) {
        if(args.level==='discover'){
          validateDiscovery(args);mgr.lifter ||=new LiftJobs(cfg);
          return runDiscovery(mgr.lifter,args,mgr.scope?.getStore()?.signal);
        }
        if(Object.hasOwn(args,'follow_direct_calls'))throw new Error('follow_direct_calls requires level=discover');
        if (args.level === 'compose') {
          validateComposition(args);
          mgr.lifter ||= new LiftJobs(cfg);
          return runComposition(mgr.lifter, args, mgr.scope?.getStore()?.signal);
        }
        if (['composition_plan','composition_plan_ref'].some(key => Object.hasOwn(args,key))) throw new Error('Composition plan parameters require level=compose');
        if (args.level === 'project') {
          validateProjection(args);
          mgr.lifter ||= new LiftJobs(cfg);
          return runProjection(mgr.lifter, args, mgr.scope?.getStore()?.signal);
        }
        if (['projection_path', 'projection_registers', 'projection_mode'].some(key => Object.hasOwn(args, key))) throw new Error('Projection parameters require level=project');
        if (Object.hasOwn(args, 'projection_decoder')) throw new Error('projection_decoder requires level=project or level=compose');
        if (args.level === 'lift') {
          mgr.lifter ||= new LiftJobs(cfg);
          return mgr.lifter.run(args, mgr.scope?.getStore()?.signal);
        }
        if (Object.hasOwn(args, 'lift_inline')) throw new Error('lift_inline requires level=lift');
        if (args.level === 'trace') {
          mgr.trace ||= new TraceJobs(cfg);
          return mgr.trace.run(args, mgr.scope?.getStore()?.signal);
        }
        if (['traces', 'trace_chunk_reports', 'trace_entry', 'trace_exit', 'trace_inputs', 'trace_output', 'initial_flags', 'trace_runtime_base', 'trace_image', 'trace_image_only', 'trace_target_sha256'].some(key => Object.hasOwn(args, key))) throw new Error('Trace-only parameters require level=trace');
        if (args.level === 'kernel') {
          if (args.name) throw new Error('Independent kernel currently requires explicit ea; symbol names are not synthesized');
          mgr.kernel ||= new KernelJobs(cfg);
          return mgr.kernel.run(args, mgr.scope?.getStore()?.signal);
        }
        const incompatible = ['action', 'optimize', 'max_code_bytes', 'abi', 'offset', 'max_slots', 'max_bases', 'max_scan_bytes', 'limit'].filter(key => Object.hasOwn(args, key));
        if (incompatible.length) throw new Error('Kernel-only parameters require level=kernel: ' + incompatible.join(', ') + '. For raw/high omit these properties; max_instructions and max_blocks are supported.');
        const engine = args.engine || (cfg.reverseProvider === 'bundled' ? cfg.defaultEngine : 'ghidra');
        if (engine === 'reverse' && cfg.reverseProvider !== 'bundled') throw new Error('Ghidra p-code requires engine=ghidra or the bundled Reverse core');
        const session = opened(mgr, args.target, engine);
        return mgr.rpc(session, 'ir', args);
      },
    },
    {
      name: 'ig5_sync',
      description: 'Preview/apply one-way RVA changeset (rename/comment/patch) between two DBs of the same binary (apply approval-gated).',
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
