import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { apply } from '../index.js';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { AnalysisJobs } from '../source/analysis_jobs.js';

const scratch = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-state-host-'));
const trace = (id, symbols, extra = {}) => ({ id, start: 'session-start', complete: true, events: symbols.map((symbol, index) => ({ direction: index % 2 ? 'server_to_client' : 'client_to_server', symbol, sourceId: `${id}:event:${index}`, complete: true })), ...extra });
const inline = value => ({ encoding: 'hex', data: Buffer.from(JSON.stringify({ version: 1, ...value })).toString('hex') });
function host() {
  const tools = new Map(), routes = new Map(), hooks = new Map(), effects = [];
  const services = { tools: { register(tool) { assert(!tools.has(tool.name)); tools.set(tool.name, tool); return () => tools.delete(tool.name); } }, webServer: { register(spec) { routes.set(spec.path, spec.handler); return () => routes.delete(spec.path); } } };
  const ctx = { tools: services.tools, get: name => services[name], on(name, callback) { hooks.set(name, callback); }, effect(body) { const clean = body(); if (typeof clean === 'function') effects.push(clean); },
    inject(names, callback) { const cleanup = names.every(name => services[name]) ? callback({ ...ctx, ...services }) : null; let live = true; const fiber = { async dispose() { if (live) { live = false; await cleanup?.(); } } }; effects.push(() => fiber.dispose()); return fiber; } };
  apply(ctx, { artifactDir: path.join(scratch, 'artifacts'), projectRoot: path.join(scratch, 'projects'), toolset: 'full', reverse: false });
  return { tools, hooks, call: (name, args = {}) => tools.get(name).execute(args, {}), async dispose() { for (const clean of effects.reverse()) await clean(); } };
}

test('public Full44/Core8 entry uses real state workers, bound manifests and full saved models', async () => {
  const fixture = host(), artifacts = new AnalysisArtifacts(path.join(scratch, 'artifacts', 'analysis-data'));
  try {
    assert.equal(fixture.tools.size, 44);
    const protocol = fixture.tools.get('ig5_protocol');
    assert(protocol.parameters.properties.action.enum.includes('state_infer'));
    assert(protocol.parameters.properties.action.enum.includes('state_validate'));
    assert(protocol.parameters.properties.state_model.properties.result_id);
    assert.equal(await fixture.hooks.get('tools/pre-execute')({ name: 'ig5_protocol', arguments: { action: 'state_infer' } }, () => 'read-only'), 'read-only');
    const training = [trace('source-a', Array.from({ length: 20 }, (_, index) => `event-${index}`))];
    const inputPath = path.join(scratch, 'explicit-traces.json');
    fs.writeFileSync(inputPath, JSON.stringify({ version: 1, traces: training }));
    const inferred = await fixture.call('ig5_protocol', { action: 'state_infer', input: { path: inputPath }, state_model: { merge: 'future-equivalent', merge_depth: 1 } });
    assert.equal(inferred.isError, undefined);
    assert.equal(inferred.value.state.coverage.observedEvents, 20);
    assert.equal(inferred.responseTruncated, true);
    const stored = artifacts.get(inferred.result_id);
    assert.equal(stored.result.state.observedModel.states.length, 21);
    assert.equal(stored.result.state.training[0].events.length, 20);
    assert.equal(stored.input.origin.kind, 'file');
    const holdout = [trace('independent-capture', Array.from({ length: 20 }, (_, index) => `event-${index}`)), trace('counterexample', ['event-0', 'new-event']), trace('incomplete', ['event-0'], { complete: false })];
    const validated = await fixture.call('ig5_protocol', { action: 'state_validate', input: inline({ traces: holdout }), state_model: { result_id: inferred.result_id } });
    assert.equal(validated.isError, undefined);
    assert.deepEqual(validated.value.state.holdout.traces.map(item => item.status), ['accepted', 'rejected', 'unknown']);
    assert.equal(validated.value.state.holdout.traces[0].consumedEvents, 20); // Never replay the eight-item compact view.
    assert.equal(validated.value.state.holdout.traces[0].independence.independent, null);
    assert.equal(validated.value.state.holdout.traces[0].independence.duplicateBehavior, true);
    assert.equal(validated.value.state.sourceResultId, inferred.result_id);
    const retrieved = await fixture.call('ig5_protocol', { action: 'result', result_id: validated.result_id, select: 'state.holdout.traces.1.counterexample' });
    assert.equal(retrieved.value.eventIndex, 1); assert.equal(retrieved.value.symbol, 'new-event');
    const reused = await fixture.call('ig5_protocol', { action: 'state_infer', input: { ref: stored.input.ref, result_id: inferred.result_id } });
    assert.equal(reused.value.state.modelDigest, inferred.value.state.modelDigest);
    assert.equal(reused.input.origin.derivedFrom.resultId, inferred.result_id);
    await fixture.call('ig5_profile', { toolset: 'core' }); assert.equal(fixture.tools.size, 8);
    await fixture.call('ig5_profile', { toolset: 'full' }); assert.equal(fixture.tools.size, 44);
    assert.equal((await fixture.call('ig5_status')).sessions.length, 0);
    fs.writeFileSync(path.join(scratch, 'acceptance.json'), JSON.stringify({ realDataWorker: true, nativeEngineExecuted: false, inference: inferred.result_id, validation: validated.result_id, fullModelStates: 21, verdicts: ['accepted', 'rejected', 'unknown'], tools: 40 }, null, 2));
  } finally { await fixture.dispose(); await artifacts.dispose(); }
});

test('public tool rejects wrong producer, action-option confusion and malformed manifests', async () => {
  const fixture = host();
  try {
    const inspected = await fixture.call('ig5_protocol', { action: 'inspect', input: { encoding: 'hex', data: '0001' } });
    await assert.rejects(fixture.call('ig5_protocol', { action: 'state_validate', input: inline({ traces: [] }), state_model: { result_id: inspected.result_id } }), error => error.code === 'INVALID_REF');
    await assert.rejects(fixture.call('ig5_protocol', { action: 'state_infer', input: inline({ traces: [] }), offset: 0 }), error => error.code === 'INVALID_INPUT');
    await assert.rejects(fixture.call('ig5_protocol', { action: 'state_infer', input: { encoding: 'hex', data: 'ff' } }), error => error.code === 'INVALID_PROTOCOL_STATE');
    await assert.rejects(fixture.call('ig5_protocol', { action: 'state_infer', input: inline({ traces: [trace('a', ['A', 'B'])] }), state_model: { max_states: 2 } }), error => error.code === 'PROTOCOL_STATE_LIMIT');
  } finally { await fixture.dispose(); }
});

test('real worker cancellation and subsequent state requests settle cleanly', async () => {
  const jobs = new AnalysisJobs();
  try {
    const controller = new AbortController();
    const bytes = inline({ traces: [trace('a', ['A', 'B'])] });
    const promise = jobs.run('protocol', { ...bytes, action: 'state_infer' }, controller.signal);
    controller.abort();
    await assert.rejects(promise, error => error.code === 'ABORT_ERR');
    const next = await jobs.run('protocol', { ...bytes, action: 'state_infer' });
    assert.equal(next.result.state.coverage.observedEvents, 2);
  } finally { await jobs.dispose(); }
});

console.log('State acceptance artifacts:', scratch);
