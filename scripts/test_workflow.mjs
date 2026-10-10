import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { builtinModules } from 'node:module';
import { pathToFileURL } from 'node:url';
import { CORE_TOOL_NAMES, installWorkflow } from '../workflow.js';

// These mocks follow the verified DSH registry contracts: each registration is
// a scope-owned effect with an exact idempotent disposer; injected services can
// appear, disappear, and reappear without disposing their waiting plugin fiber.
function createHost(initial = ['tools', 'skills', 'commands']) {
  const available = new Set(initial);
  const entries = { tools: new Map(), skills: new Map(), commands: new Map() };
  const watchers = new Set();
  let failTool;
  let failSkill;
  let failCommand;
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
            if (definition.name === failSkill) throw new Error('fixture skill registration failed');
            assert.match(definition.name, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
            assert.ok(definition.description && definition.content && definition.source);
            if (entries.skills.has(definition.name)) return own(() => {}); // DSH runtime first-wins
          } else {
            if (definition.name === failCommand) throw new Error('fixture command registration failed');
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
    fail(name, service = 'tools') {
      if (service === 'tools') failTool = name;
      else if (service === 'skills') failSkill = name;
      else if (service === 'commands') failCommand = name;
      else throw new Error('unknown fixture service');
    },
    toolChanges: () => toolChanges,
  };
}

function fixtures() {
  const calls = [];
  const names = [...CORE_TOOL_NAMES,
    'ig5_xrefs', 'ig5_calls', 'ig5_bytes', 'ig5_search', 'ig5_listing', 'ig5_scan',
    'ig5_export_diff', 'ig5_cfg', 'ig5_slice', 'ig5_fingerprint', 'ig5_stack',
    'ig5_switches', 'ig5_vtables', 'ig5_microcode', 'ig5_bindiff', 'ig5_ir',
    'ig5_crypto', 'ig5_protocol',
    'ig5_rename', 'ig5_patch_bytes', 'ig5_comment', 'ig5_analyze', 'ig5_set_type',
    'ig5_undo', 'ig5_run_idapython', 'ig5_dbg', 'ig5_struct', 'ig5_switch_repair',
    'ig5_emulate', 'ig5_sync',
  ];
  assert.equal(names.length, 38, 'fixture mirrors the full product catalog');
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
assert.equal(host.entries.skills.size, 7);
assert.deepEqual(names(host.entries.skills), ['ig5-crypto', 'ig5-debug-live', 'ig5-deep-dive', 'ig5-diff', 'ig5-patch-and-sign', 'ig5-protocol', 'ig5-triage']);
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
assert.equal(host.entries.tools.size, 38);
assert.ok(host.entries.tools.has('ig5_crypto') && host.entries.tools.has('ig5_protocol'), 'full includes both data analysis lanes');
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
for (const action of ['patch_bytes 0x1000 90', 'ig5_patch_bytes {}', 'rename', 'dbg', 'crypto {}', 'protocol {}', 'status extra']) {
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
assert.equal(host.entries.skills.size, 7, 'skills remount after a service restart');
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
assert.equal(late.entries.skills.size, 7);
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

// Registration failure in either of the newly added runbooks rolls back every
// earlier skill and tool contribution instead of leaving a partly loaded plugin.
for (const failedSkill of ['ig5-crypto', 'ig5-protocol']) {
  const failed = createHost();
  failed.fail(failedSkill, 'skills');
  const data = fixtures();
  assert.throws(() => installWorkflow(failed.ctx, { cfg: { toolset: 'full' }, mgr: data.mgr, definitions: data.definitions }), /skill registration failed/);
  await new Promise(resolve => setImmediate(resolve));
  for (const map of Object.values(failed.entries)) assert.equal(map.size, 0, 'failed new skill registration rolls back all contributions');
  await failed.ctx.dispose();
}

const commandFailure = createHost();
commandFailure.fail('ig5', 'commands');
const commandFixture = fixtures();
assert.throws(() => installWorkflow(commandFailure.ctx, { cfg: { toolset: 'full' }, mgr: commandFixture.mgr, definitions: commandFixture.definitions }), /command registration failed/);
await new Promise(resolve => setImmediate(resolve));
for (const map of Object.values(commandFailure.entries)) assert.equal(map.size, 0, 'command failure also removes all seven skills');
await commandFailure.ctx.dispose();

const future = createHost();
const futureFixture = fixtures();
const extension = { ...futureFixture.definitions[0], name: 'ig5_future_read' };
const futureController = installWorkflow(future.ctx, { cfg: { toolset: 'full' }, mgr: futureFixture.mgr, definitions: [...futureFixture.definitions, extension] });
assert.equal(future.entries.tools.size, 39, 'full remains catalog-driven rather than hard-coding the current count');
assert.ok(future.entries.tools.has(extension.name));
await futureController.dispose();
await future.ctx.dispose();

// Scope-aware fixture resolves schemas, lookups and executions from one view,
// matching the installed DSH registry instead of just counting registrations.
function scopedHost(existing = []) {
  const host = createHost(), events = new Map(), locals = new Map(); let rejected;
  const global = host.ctx.tools, inject = host.ctx.inject.bind(host.ctx);
  global.restrict = () => { throw new Error('requires a scoped context'); };
  const view = agent => new Map([...host.entries.tools, ...(locals.get(agent?.ctx) || [])]);
  global.schemas = agent => [...view(agent).values()].map(tool => ({ name: tool.name }));
  global.get = (name, agent) => view(agent).get(name);
  global.execute = async execution => {
    const tool = global.get(execution.name, execution.agent);
    if (!tool) return { content: [{ type: 'text', text: 'Error: unknown tool ' + execution.name }], isError: true };
    return { content: tool.output.render(execution.arguments, await tool.execute(execution.arguments, execution)) };
  };
  Object.defineProperty(host.ctx, 'tools', { value: global });
  host.ctx.on = (name, handler) => {
    const handlers = events.get(name) || new Set(); events.set(name, handlers); handlers.add(handler);
    let live = true; return () => { if (live) { live = false; handlers.delete(handler); } };
  };
  host.ctx.inject = (names, callback) => names.length === 1 && names[0] === 'agents'
    ? (callback({ get: () => ({ list: () => existing }) }), { dispose() {} }) : inject(names, callback);
  host.agent = id => {
    const owned = new Map(), effects = []; let disposed = false;
    const agent = { id, ctx: { tools: {
      register(tool) {
        assert(!disposed); if (tool.name === rejected) throw new Error('scoped registration failed');
        assert(!owned.has(tool.name)); owned.set(tool.name, tool); let live = true;
        const remove = () => { if (live) { live = false; owned.delete(tool.name); } }; effects.push(remove); return remove;
      },
      restrict(filter) { assert(!disposed); assert.deepEqual(filter, { deny: [] }); return () => {}; },
    } } };
    locals.set(agent.ctx, owned);
    agent.dispose = async () => { await host.emit('agent/disposed', { agent }); disposed = true; for (const remove of effects.reverse()) remove(); };
    return agent;
  };
  host.emit = async (name, payload) => { for (const handler of events.get(name) || []) await handler(payload); };
  host.failScoped = name => { rejected = name; };
  host.locals = locals; host.registry = global; host.listeners = events;
  return host;
}

{
  const host = scopedHost(), data = fixtures(), a = host.agent('agent-A'), b = host.agent('agent-B');
  const controller = installWorkflow(host.ctx, { cfg: {}, mgr: data.mgr, definitions: data.definitions });
  await host.emit('agent/created', { agent: a }); await host.emit('agent/created', { agent: b });
  assert.equal(controller.snapshot({ agent: a }).toolsetScope, 'agent'); assert.equal(controller.getToolset(a), 'core');
  assert.throws(() => controller.setToolset('full'), { code: 'AGENT_SCOPE_REQUIRED' });
  controller.setToolset('full', { agent: a });
  assert.equal(host.registry.schemas(a).length, 38); assert.equal(host.registry.schemas(b).length, 8); assert.equal(host.registry.schemas().length, 8);
  assert(host.registry.get('ig5_crypto', a)); assert.equal(host.registry.get('ig5_crypto', b), undefined);
  assert.equal((await host.registry.execute({ name: 'ig5_crypto', agent: a, arguments: {} })).isError, undefined);
  assert.equal((await host.registry.execute({ name: 'ig5_crypto', agent: b, arguments: {} })).isError, true);
  controller.setToolset('full', b); controller.setToolset('core', a.ctx);
  assert.equal(host.registry.schemas(a).length, 8); assert.equal(host.registry.schemas(b).length, 38);
  host.failScoped('ig5_patch_bytes'); assert.throws(() => controller.setToolset('full', a), /registration failed/);
  assert.equal(host.registry.schemas(a).length, 8); assert.equal(host.registry.schemas(b).length, 38); assert.equal(controller.getToolset(a), 'core'); host.failScoped();
  const command = host.entries.commands.get('ig5');
  assert.equal((await command.handler({ rawInput: 'toolset full', agent: a })).kind, 'success');
  assert.equal((await command.handler({ rawInput: 'toolset core', agent: a })).kind, 'success'); assert.equal(controller.getToolset(b), 'full');
  const fake = { id: 'unscoped-proxy', ctx: { tools: host.registry } };
  assert.throws(() => controller.setToolset('full', fake), /scoped context/); assert.equal(host.entries.tools.size, 8);
  await a.dispose(); assert.throws(() => controller.setToolset('full', a), /disposed/);
  const replacement = host.agent('agent-A'); await host.emit('agent/created', { agent: replacement }); controller.setToolset('full', replacement);
  await host.emit('agent/disposed', { agent: a }); assert.equal(host.registry.schemas(replacement).length, 38, 'same-id stale disposal cannot affect replacement');
  await controller.dispose(); assert.equal(host.registry.schemas(b).length, 0); assert.equal(host.registry.schemas(replacement).length, 0);
  for (const handlers of host.listeners.values()) assert.equal(handlers.size, 0);
  await host.ctx.dispose();
  console.log('PASS scoped agents isolate schema/get/execute, command switching, failed expansions and same-id lifecycle replacement');
}
{
  const existing = [], host = scopedHost(existing), data = fixtures(), a = host.agent('existing'); existing.push(a);
  const controller = installWorkflow(host.ctx, { cfg: { toolset: 'full' }, mgr: data.mgr, definitions: data.definitions });
  assert.equal(host.registry.schemas().length, 8); assert.equal(host.registry.schemas(a).length, 38);
  const b = host.agent('late'); await host.emit('agent/created', { agent: b }); assert.equal(host.registry.schemas(b).length, 38);
  controller.setToolset('core', a); await host.emit('agent/created', { agent: a }); assert.equal(controller.getToolset(a), 'core');
  await host.ctx.dispose(); assert.equal(host.locals.get(a.ctx).size, 0); assert.equal(host.locals.get(b.ctx).size, 0);
  await controller.dispose(); console.log('PASS full defaults initialize existing/new agents and owner unload removes agent-owned schemas');
}

// Read the installed archive without changing the host. Only pure JS/JSON
// dependency files are copied to a bounded temporary tree for real registry tests.
async function installedRegistry() {
  const asar = process.env.IG5_DSH_ASAR || (process.platform === 'win32' ? path.join(process.env.LOCALAPPDATA || '', 'Programs', 'DeepSeek Harness', 'resources', 'app.asar') : '');
  if (!asar || !fs.existsSync(asar)) { console.log('SKIP real DSH registry: installed app archive unavailable (set IG5_DSH_ASAR)'); return; }
  const fd = fs.openSync(asar, 'r'), first = Buffer.alloc(8); fs.readSync(fd, first, 0, 8, 0);
  const headerSize = first.readUInt32LE(4); assert(headerSize > 8 && headerSize <= 16 * 1024 * 1024);
  const header = Buffer.alloc(headerSize); fs.readSync(fd, header, 0, header.length, 8);
  const manifest = JSON.parse(header.subarray(8, 8 + header.readUInt32LE(4)).toString());
  const temporary = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-dsh-registry-'));
  const copied = new Set(), natives = new Set(builtinModules.flatMap(name => [name, 'node:' + name])); let totalBytes = 0, totalFiles = 0;
  const entry = filename => filename.split('/').reduce((node, part) => node?.files?.[part], manifest);
  const read = filename => {
    const info = entry(filename); assert(info && !info.unpacked && Number.isSafeInteger(info.size));
    totalBytes += info.size; totalFiles++; assert(totalBytes <= 32 * 1024 * 1024 && totalFiles <= 4096, 'DSH test extraction budget');
    const bytes = Buffer.alloc(info.size); fs.readSync(fd, bytes, 0, bytes.length, 8 + headerSize + Number(info.offset)); return bytes;
  };
  function copyPackage(name) {
    if (copied.has(name) || natives.has(name) || name.startsWith('node:')) return;
    copied.add(name); const source = 'dsh/node_modules/' + name, root = entry(source); assert(root?.files, 'Installed dependency is absent: ' + name);
    const imports = new Set();
    function walk(node, relative = '') {
      for (const [namePart, info] of Object.entries(node.files || {})) {
        const filename = relative + namePart;
        if (info.files) walk(info, filename + '/');
        else if (/\.(?:js|mjs|cjs|json)$/.test(filename)) {
          const bytes = read(source + '/' + filename), destination = path.join(temporary, 'node_modules', name, filename);
          assert(destination.startsWith(temporary + path.sep)); fs.mkdirSync(path.dirname(destination), { recursive: true }); fs.writeFileSync(destination, bytes);
          if (/\.(?:js|mjs|cjs)$/.test(filename)) {
            const code = bytes.toString();
            for (const match of code.matchAll(/(?:^|\n)\s*(?:import|export)[^;\n]*?\bfrom\s*["']([^"']+)["']|(?:^|\n)\s*import\s*["']([^"']+)["']|\brequire\(["']([^"']+)["']\)/g)) {
              const dependency = match[1] || match[2] || match[3];
              if (!dependency.startsWith('.') && !dependency.startsWith('/') && !natives.has(dependency) && !dependency.startsWith('node:')) imports.add(dependency.startsWith('@') ? dependency.split('/').slice(0, 2).join('/') : dependency.split('/')[0]);
            }
          }
        }
      }
    }
    walk(root); for (const dependency of imports) copyPackage(dependency);
  }
  let context, controller;
  try {
    for (const name of ['@deepseek-ai/cordis', '@deepseek-ai/dsh-tools', '@deepseek-ai/dsh-system-prompt', '@deepseek-ai/dsh-scope']) copyPackage(name);
    const load = name => import(pathToFileURL(path.join(temporary, 'node_modules', name, 'lib', 'index.js')).href);
    const [{ Context }, { default: Tools }, { default: SystemPrompt }, { createScope }] = await Promise.all(['@deepseek-ai/cordis', '@deepseek-ai/dsh-tools', '@deepseek-ai/dsh-system-prompt', '@deepseek-ai/dsh-scope'].map(load));
    context = new Context(); await context.plugin(SystemPrompt, {}); await context.plugin(Tools);
    const agents = [];
    await context.plugin(Object.assign(inner => {
      for (const id of ['real-A', 'real-B']) { const agent = { id }, scope = createScope(inner, agent); agent.ctx = scope.ctx; agents.push(agent); }
    }, { inject: ['tools', 'systemPrompt'] }));
    const data = fixtures();
    const owner = context.plugin(Object.assign(inner => { controller = installWorkflow(inner, { cfg: {}, mgr: data.mgr, definitions: data.definitions }); }, { inject: ['tools'] }));
    await owner;
    const [a, b] = agents; controller.setToolset('full', a);
    assert.equal(context.tools.schemas().length, 8); assert.equal(context.tools.schemas(a).length, 38); assert.equal(context.tools.schemas(b).length, 8);
    assert(context.tools.get('ig5_crypto', a)); assert.equal(context.tools.get('ig5_crypto', b), undefined);
    const run = agent => context.tools.execute({ name: 'ig5_crypto', arguments: {}, agent, signal: new AbortController().signal, callId: 'scope-test-call' });
    assert.equal((await run(a)).isError, false); assert.match((await run(b)).content[0].text, /unknown tool/);
    controller.setToolset('full', b); controller.setToolset('core', a);
    assert.equal(context.tools.schemas(a).length, 8); assert.equal(context.tools.schemas(b).length, 38);
    const collision = a.ctx.tools.register(data.definitions.find(tool => tool.name === 'ig5_patch_bytes'));
    assert.throws(() => controller.setToolset('full', a), /already registered/);
    assert.equal(context.tools.schemas(a).length, 9); assert.equal(context.tools.get('ig5_crypto', a), undefined); assert.equal(context.tools.schemas(b).length, 38);
    collision();
    await owner.dispose(); assert.equal(context.tools.schemas(a).length, 0); assert.equal(context.tools.schemas(b).length, 0);
    let reloaded;
    const nextOwner = context.plugin(Object.assign(inner => { reloaded = installWorkflow(inner, { cfg: {}, mgr: data.mgr, definitions: data.definitions }); }, { inject: ['tools'] })); await nextOwner;
    reloaded.setToolset('full', b); assert.equal(context.tools.schemas(b).length, 38); assert.equal(context.tools.schemas(a).length, 8);
    await nextOwner.dispose(); assert.equal(context.tools.schemas(b).length, 0);
    console.log('PASS installed DSH Tools actual schema/get/execute isolation, duplicate rollback and owner reload (' + copied.size + ' dependency packages)');
  } finally {
    await controller?.dispose(); await context?.fiber?.dispose(); fs.closeSync(fd);
    const resolved = path.resolve(temporary); assert(resolved.startsWith(fs.realpathSync(os.tmpdir()) + path.sep)); fs.rmSync(resolved, { recursive: true, force: true });
  }
}
await installedRegistry();
console.log('IG5 workflow: Core8/Full38, legacy compatibility, agent scope isolation, safe commands, seven skills, registration rollback, and disposal passed.');
