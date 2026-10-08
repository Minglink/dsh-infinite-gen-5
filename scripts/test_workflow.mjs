import assert from 'node:assert/strict';
import { CORE_TOOL_NAMES, installWorkflow } from '../workflow.js';

// These mocks follow the verified DSH registry contracts: each registration is
// a scope-owned effect with an exact idempotent disposer; injected services can
// appear, disappear, and reappear without disposing their waiting plugin fiber.
function createHost(initial = ['tools', 'skills', 'commands']) {
  const available = new Set(initial);
  const entries = { tools: new Map(), skills: new Map(), commands: new Map() };
  const watchers = new Set();
  let failTool;
  let toolChanges = 0;
  function makeScope() {
    const effects = [];
    let disposed = false;
    const own = (remove) => {
      let live = true;
      const dispose = () => { if (live) { live = false; return remove(); } };
      effects.push(dispose);
      return dispose;
    };
    const scope = {
      get(name) {
        if (!available.has(name)) return undefined;
        return { register(definition) {
          assert.equal(disposed, false, 'cannot register into a disposed scope');
          if (name === 'tools') {
            if (definition.name === failTool) throw new Error('fixture tool registration failed');
            assert.equal(typeof definition.execute, 'function');
            assert.equal(typeof definition.output.render, 'function');
            assert.ok(definition.output.schema);
            toolChanges++;
          } else if (name === 'skills') {
            assert.match(definition.name, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
            assert.ok(definition.description && definition.content && definition.source);
            if (entries.skills.has(definition.name)) return own(() => {}); // DSH runtime first-wins
          } else {
            assert.match(definition.name, /^[a-z][a-z0-9_-]*$/);
            assert.equal(typeof definition.handler, 'function');
          }
          assert.equal(entries[name].has(definition.name), false, 'duplicate ' + definition.name);
          entries[name].set(definition.name, definition);
          return own(() => { entries[name].delete(definition.name); if (name === 'tools') toolChanges++; });
        } };
      },
      get tools() { return scope.get('tools'); },
      effect(body) { return own(body() || (() => {})); },
      inject(names, callback) {
        let child;
        let fiberDisposed = false;
        const watcher = {
          async stop() { if (child) { const old = child; child = undefined; await old.dispose(); } },
          start() {
            if (fiberDisposed || child || !names.every((name) => available.has(name))) return;
            child = makeScope();
            const remove = callback(child);
            if (typeof remove === 'function') child.effect(() => remove);
          },
          async dispose() { fiberDisposed = true; watchers.delete(watcher); await watcher.stop(); },
          names,
        };
        watchers.add(watcher);
        own(() => watcher.dispose());
        watcher.start();
        return watcher;
      },
      async dispose() {
        disposed = true;
        for (const remove of effects.reverse()) await remove();
      },
    };
    return scope;
  }
  return {
    ctx: makeScope(), entries,
    async add(name) { available.add(name); for (const watcher of watchers) watcher.start(); },
    async remove(name) { available.delete(name); for (const watcher of watchers) if (watcher.names.includes(name)) await watcher.stop(); },
    fail(name) { failTool = name; },
    toolChanges: () => toolChanges,
  };
}

function fixtures() {
  const calls = [];
  const names = [...CORE_TOOL_NAMES, 'ig5_xrefs', 'ig5_export_diff', 'ig5_patch_bytes', 'ig5_future_read'];
  const definitions = names.map((name) => ({
    name,
    description: 'fixture ' + name,
    parameters: { type: 'object', properties: { target: { type: 'string' } }, required: [], additionalProperties: false },
    output: { schema: { type: 'object' }, render: (_args, result) => [{ type: 'text', text: JSON.stringify(result) }] },
    execute(args, exec) {
      assert.notEqual(name, 'ig5_patch_bytes', 'command must never execute a write tool directly');
      calls.push({ name, args, exec });
      return { name, args };
    },
  }));
  const session = { target: 'C:\\fixtures\\sample one.exe', alive: true };
  const mgr = { sessions: new Map([['one', session]]), alive: (value) => value.alive };
  return { definitions, mgr, calls, session };
}

function names(map) { return [...map.keys()].sort(); }
function assertSchemas(map) {
  for (const definition of map.values()) {
    assert.equal(definition.parameters.type, 'object');
    assert.ok(Array.isArray(definition.parameters.required));
    for (const property of Object.values(definition.parameters.properties)) assert.equal('required' in property, false);
  }
}
const host = createHost();
const fixture = fixtures();
const controller = installWorkflow(host.ctx, { cfg: {}, mgr: fixture.mgr, definitions: fixture.definitions });
assert.equal(controller.getToolset(), 'core');
assert.deepEqual(names(host.entries.tools), [...CORE_TOOL_NAMES].sort());
assert.equal(controller.snapshot().toolsetScope, 'plugin-instance');
assert.equal(controller.snapshot().toolsetPersistent, false);
assert.equal(host.entries.skills.size, 5);
assert.equal(host.entries.commands.size, 1);
assertSchemas(host.entries.tools);
for (const skill of host.entries.skills.values()) {
  assert.deepEqual(skill.invocation, { modelInvocable: true, userInvocable: true });
  assert.equal(skill.resourceBase.kind, 'directory');
  assert.equal(skill.source, 'bundled');
  assert.doesNotMatch(skill.content, /\bIDA\b|idalib|Hex-Rays|9\.2/);
  assert.doesNotMatch(skill.content, /^---\r?\n/, 'registered body omits YAML metadata');
}

controller.setToolset('full');
assert.equal(host.entries.tools.size, fixture.definitions.length);
assert.ok(host.entries.tools.has('ig5_future_read'), 'full uses every supplied definition');
assertSchemas(host.entries.tools);
const changes = host.toolChanges();
controller.setToolset('full');
assert.equal(host.toolChanges(), changes, 'same-mode selection must not churn schemas');
controller.setToolset('core');
assert.deepEqual(names(host.entries.tools), [...CORE_TOOL_NAMES].sort());
assert.throws(() => controller.setToolset('invalid'), /core.*full/);
host.fail('ig5_patch_bytes');
assert.throws(() => controller.setToolset('full'), /registration failed/);
assert.equal(controller.getToolset(), 'core');
assert.deepEqual(names(host.entries.tools), [...CORE_TOOL_NAMES].sort(), 'failed expansion rolls back every new registration');
host.fail(undefined);

const command = host.entries.commands.get('ig5');
const agent = { id: 'test-agent' };
const signal = new AbortController().signal;
const invoke = (rawInput, invocation = {}) => command.handler({ agent, signal, rawInput, ...invocation });
assert.equal((await invoke('')).kind, 'success');
assert.equal(fixture.calls.at(-1).name, 'ig5_status');
assert.equal(fixture.calls.at(-1).exec.agent, agent);
assert.equal(fixture.calls.at(-1).exec.signal, signal);
await invoke(' open "C:\\fixtures\\sample one.exe"');
assert.deepEqual(fixture.calls.at(-1).args, { path: fixture.session.target });
await invoke("open 'C:\\fixtures\\sample one.exe'");
assert.equal(fixture.calls.at(-1).args.path, fixture.session.target);
await invoke('open C:\\fixtures\\sample one.exe');
assert.equal(fixture.calls.at(-1).args.path, fixture.session.target);
assert.equal((await invoke('open')).kind, 'error');
assert.equal((await invoke('open "missing')).kind, 'error');
await invoke('export');
assert.equal(fixture.calls.at(-1).name, 'ig5_export_diff');
assert.equal(fixture.calls.at(-1).args.target, fixture.session.target);
await invoke('export "C:\\other sample.exe"');
assert.equal(fixture.calls.at(-1).args.target, 'C:\\other sample.exe');
fixture.mgr.sessions.set('two', { target: 'C:\\other.exe', alive: true });
assert.equal((await invoke('export')).kind, 'error');
fixture.mgr.sessions.clear();
assert.equal((await invoke('export')).kind, 'error');
fixture.mgr.sessions.set('one', fixture.session);
const beforeDenied = fixture.calls.length;
for (const action of ['patch_bytes 0x1000 90', 'ig5_patch_bytes {}', 'rename', 'dbg', 'status extra']) {
  assert.equal((await invoke(action)).kind, 'error');
}
assert.equal(fixture.calls.length, beforeDenied, 'unsupported commands cannot execute tools');
assert.equal((await invoke('toolset full')).kind, 'success');
assert.equal(controller.getToolset(), 'full');
assert.equal((await invoke('toolset')).kind, 'success');
assert.equal((await invoke('toolset core')).kind, 'success');
assert.equal((await invoke('toolset broken')).kind, 'error');
const abort = new AbortController(); abort.abort();
assert.equal((await invoke('toolset full', { signal: abort.signal })).kind, 'error');
assert.equal(controller.getToolset(), 'core');

await host.remove('skills');
assert.equal(host.entries.skills.size, 0);
assert.deepEqual(controller.snapshot().skills, []);
await host.add('skills');
assert.equal(host.entries.skills.size, 5, 'skills remount after a service restart');
await host.remove('commands');
assert.equal(host.entries.commands.size, 0);
await host.add('commands');
assert.equal(host.entries.commands.size, 1);
await controller.dispose();
await controller.dispose();
for (const map of Object.values(host.entries)) assert.equal(map.size, 0, 'explicit workflow disposal removes contributions');
assert.throws(() => controller.setToolset('full'), /disposed/);
assert.equal((await invoke('status')).kind, 'error', 'stale command handlers reject after disposal');
await host.ctx.dispose();

const late = createHost(['tools']);
const lateFixture = fixtures();
const lateController = installWorkflow(late.ctx, { cfg: { toolset: 'full' }, mgr: lateFixture.mgr, definitions: lateFixture.definitions });
assert.equal(late.entries.tools.size, lateFixture.definitions.length);
assert.equal(late.entries.skills.size, 0);
assert.equal(late.entries.commands.size, 0);
await late.add('skills'); await late.add('commands');
assert.equal(late.entries.skills.size, 5);
assert.equal(late.entries.commands.size, 1);
await late.ctx.dispose();
for (const map of Object.values(late.entries)) assert.equal(map.size, 0, 'owner-fiber disposal removes registrations without explicit controller disposal');
await lateController.dispose();

const failure = createHost();
const failureFixture = fixtures();
assert.throws(() => installWorkflow(failure.ctx, { cfg: { toolset: 'broken' }, mgr: failureFixture.mgr, definitions: failureFixture.definitions }), /core.*full/);
assert.equal(failure.entries.tools.size, 0);
assert.throws(() => installWorkflow(failure.ctx, { cfg: {}, mgr: failureFixture.mgr, definitions: failureFixture.definitions.slice(1) }), /Missing core/);
await failure.ctx.dispose();

console.log('IG5 workflow: Core8/Full schemas, safe native commands, five bundled skills, late services, rollback, and disposal passed.');
