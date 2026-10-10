// Pure configuration/transport checks: no executable, JVM or native engine starts.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runtimeConfiguration } from '../engine_runtime.js';
import { workerLaunch, spawnWorker } from '../source/worker_transport.js';

test('Reverse defaults to the bundled provider regardless of obsolete commercial discovery options', () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-provider-'));
  try {
    for (const overrides of [{}, { reverse: false }, { idaDir: 'an optional installation' }, { reverse: false, idaDir: 'an optional installation' }]) {
      const cfg = runtimeConfiguration({ runtimeRoot: scratch, home: scratch, ...overrides });
      assert.equal(cfg.reverseProvider, 'bundled'); assert.equal(cfg.ghidra.available, false);
    }
    assert.equal(runtimeConfiguration({ runtimeRoot: scratch, home: scratch, reverseProvider: 'commercial' }).reverseProvider, 'commercial');
    for (const reverseProvider of ['', null, false, 'auto', 'ghidra', {}, ['bundled']]) {
      assert.throws(() => runtimeConfiguration({ reverseProvider }), /reverseProvider must be bundled or commercial/);
    }
  } finally {
    assert.equal(path.dirname(scratch), path.resolve(os.tmpdir()));
    assert.ok(path.basename(scratch).startsWith('ig5-provider-'));
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});

const windowsConfig = () => ({ reverseProvider: 'bundled', reverseAvailable: true, reverse: false,
  pythonExe: 'commercial-python-must-not-run', idaDir: 'commercial-path-must-not-be-used',
  home: 'C:\\移动 用户\\home', projectRoot: 'C:\\移动 用户\\projects', host: { platform: 'win32' },
  ghidra: { available: true, pythonExe: 'C:\\插件\\runtimes\\ghidra\\python\\python.exe', ghidraHome: 'C:\\插件\\ghidra', javaHome: 'C:\\插件\\jdk' },
});

test('builtin Reverse and direct Ghidra use the same shipped provider with separate native project roots', () => {
  const cfg = windowsConfig(), root = 'C:\\插件 中文\\plugin';
  const reverse = workerLaunch(cfg, 'reverse', root), ghidra = workerLaunch(cfg, 'ghidra', root);
  assert.equal(reverse.executable, cfg.ghidra.pythonExe); assert.equal(ghidra.executable, cfg.ghidra.pythonExe);
  assert.deepEqual(reverse.args, ['-I', '-B', path.join(root, 'adapters', 'ghidra', 'worker.py')]);
  assert.deepEqual(reverse.args, ghidra.args); assert.ok(!reverse.args.includes('--ida-dir'));
  assert.equal(reverse.options.env.IG5_GHIDRA_ROUTE, 'reverse'); assert.equal(ghidra.options.env.IG5_GHIDRA_ROUTE, 'ghidra');
  assert.equal(reverse.options.env.IG5_GHIDRA_PROJECT_ROOT, path.join(cfg.projectRoot, 'reverse-databases'));
  assert.equal(ghidra.options.env.IG5_GHIDRA_PROJECT_ROOT, path.join(cfg.projectRoot, 'ghidra-databases'));
  assert.notEqual(reverse.options.env.IG5_GHIDRA_PROJECT_ROOT, ghidra.options.env.IG5_GHIDRA_PROJECT_ROOT);
  assert.equal(reverse.options.env.IG5_GHIDRA_HOME, cfg.ghidra.ghidraHome); assert.equal(reverse.options.env.IG5_JAVA_HOME, cfg.ghidra.javaHome);
  assert.deepEqual(reverse.options.stdio, ['pipe', 'pipe', 'pipe']); assert.equal(reverse.options.windowsHide, true);
});

test('builtin routing rejects missing or broken shipped runtimes without falling back to a commercial installation', () => {
  for (const ghidra of [undefined, { available: false, reason: 'runtime metadata missing' }]) {
    assert.throws(() => workerLaunch({ ...windowsConfig(), ghidra }, 'reverse', 'C:\\plugin'), /Bundled Reverse runtime is unavailable/);
  }
  const cfg = windowsConfig(); cfg.reverseAvailable = false;
  assert.equal(workerLaunch(cfg, 'reverse', 'C:\\plugin').executable, cfg.ghidra.pythonExe,
    'bundled routing availability is checked against its own runtime, not obsolete commercial discovery');
});

test('explicit commercial and legacy injected transport configurations preserve the optional worker', () => {
  const cfg = { ...windowsConfig(), reverseProvider: 'commercial' }, root = 'C:\\plugin';
  for (const configuration of [cfg, { ...cfg, reverseProvider: undefined }]) {
    const launch = workerLaunch(configuration, 'reverse', root);
    assert.equal(launch.executable, cfg.pythonExe);
    assert.deepEqual(launch.args, ['-X', 'utf8', path.join(root, 'worker', 'ig5_worker.py'), '--ida-dir', cfg.idaDir]);
  }
  assert.throws(() => workerLaunch({ ...cfg, reverseAvailable: false }, 'reverse', root), /Reverse runtime is unavailable/);
});

test('Linux builtin routing isolates both project roots and owns a process group', () => {
  const cfg = { ...windowsConfig(), host: { platform: 'linux' }, projectRoot: '/home/用户/projects',
    ghidra: { available: true, pythonExe: '/plugin/python/bin/python3', ghidraHome: '/plugin/ghidra', javaHome: '/plugin/jdk' } };
  const previous = process.env.IG5_GHIDRA_ROUTE; process.env.IG5_GHIDRA_ROUTE = 'untrusted inherited route';
  try {
    const reverse = workerLaunch(cfg, 'reverse', '/plugin'), ghidra = workerLaunch(cfg, 'ghidra', '/plugin');
    assert.equal(reverse.args[2], '/plugin/adapters/ghidra/worker.py');
    assert.equal(reverse.options.env.IG5_GHIDRA_PROJECT_ROOT, '/home/用户/projects/reverse-databases');
    assert.equal(ghidra.options.env.IG5_GHIDRA_PROJECT_ROOT, '/home/用户/projects/ghidra-databases');
    assert.equal(reverse.options.env.IG5_GHIDRA_ROUTE, 'reverse'); assert.equal(ghidra.options.env.IG5_GHIDRA_ROUTE, 'ghidra');
    assert.equal(reverse.options.detached, true); assert.equal(ghidra.options.detached, true);
  } finally {
    if (previous === undefined) delete process.env.IG5_GHIDRA_ROUTE; else process.env.IG5_GHIDRA_ROUTE = previous;
  }
});

test('spawned bundled transport retains actual provider readiness without rewriting its native identity', async () => {
  const cfg = windowsConfig(); let captured;
  const child = spawnWorker(cfg, 'reverse', 'C:\\plugin', { spawnProcess(executable, args, options) {
    captured = { executable, args, options };
    const fake = new EventEmitter(); fake.stdout = new EventEmitter(); fake.stderr = new EventEmitter(); fake.stdin = new EventEmitter();
    fake.stdin.write = () => true; fake.exitCode = null;
    queueMicrotask(() => fake.stdout.emit('data', Buffer.from(JSON.stringify({ ig5: 'ready', engine: 'ghidra', capabilities: ['microcode', 'idapython'] }) + '\n')));
    return fake;
  } });
  const client = child.__ig5Client;
  try {
    await client.waitReady(100);
    assert.equal(captured.executable, cfg.ghidra.pythonExe); assert.equal(captured.options.env.IG5_GHIDRA_ROUTE, 'reverse');
    assert.equal(client.readyMessage.engine, 'ghidra'); assert.deepEqual(client.readyMessage.capabilities, ['microcode', 'idapython']);
  } finally { client.dispose(); }
});
