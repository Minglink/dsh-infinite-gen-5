import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const source = fs.readFileSync(new URL('../client.js', import.meta.url), 'utf8');
let currentHarness;
const React = {
  createElement: (type, props, ...children) => ({ type, props: props || {}, children: children.flat(Infinity).filter(x => x !== null && x !== undefined && x !== false) }),
  useState(initial) {
    const h = currentHarness, i = h.cursor++;
    if (!(i in h.cells)) h.cells[i] = typeof initial === 'function' ? initial() : initial;
    return [h.cells[i], value => { h.cells[i] = typeof value === 'function' ? value(h.cells[i]) : value; }];
  },
  useRef(initial) { const h = currentHarness, i = h.cursor++; return h.cells[i] ||= { current: initial }; },
  useMemo(fn, deps) {
    const h = currentHarness, i = h.cursor++, old = h.cells[i];
    if (!old || !same(old.deps, deps)) h.cells[i] = { deps, value: fn() };
    return h.cells[i].value;
  },
  useEffect(fn, deps) {
    const h = currentHarness, i = h.cursor++, old = h.effects[i];
    if (!old || !same(old.deps, deps)) h.pending.push(() => { old?.cleanup?.(); h.effects[i] = { deps, cleanup: fn() }; });
  },
};
const same = (a, b) => !!a && !!b && a.length === b.length && a.every((x, i) => Object.is(x, b[i]));
let request = () => { throw new Error('unexpected network call'); };
let api;
const sandbox = { window: { __ModuleLoader__: { load: value => { api = value.factory(name => { assert.equal(name, 'react'); return React; }); } } }, console, URLSearchParams, fetch: (...args) => request(...args), setTimeout, clearTimeout, location: { href: 'http://localhost/test' }, navigator: {} };
vm.runInNewContext(source, sandbox, { filename: 'client.js' });
const ui = api.__test;
const plain = value => JSON.parse(JSON.stringify(value));
function harness(component, props = {}) {
  return { component, props, cells: [], effects: [], pending: [], cursor: 0, tree: null,
    render(nextProps) { if (nextProps) this.props = nextProps; this.cursor = 0; currentHarness = this; this.tree = component(this.props); currentHarness = null; this.pending.splice(0).forEach(fn => fn()); return this.tree; },
    unmount() { this.effects.forEach(e => e?.cleanup?.()); },
  };
}
function nodes(node, predicate) { if (!node || typeof node !== 'object') return []; return (predicate(node) ? [node] : []).concat((node.children || []).flatMap(x => nodes(x, predicate))); }
function text(node) { return typeof node === 'string' || typeof node === 'number' ? String(node) : (node?.children || []).map(text).join(''); }
function button(tree, label) { const found = nodes(tree, n => n.type === 'button' && text(n) === label)[0]; assert.ok(found, `button ${label}`); return found; }
function row(tree, label) { const found = nodes(tree, n => n.type === 'tr' && text(n).includes(label) && typeof n.props.onClick === 'function')[0]; assert.ok(found, `row ${label}`); return found; }
const response = data => ({ ok: true, status: 200, json: async () => ({ data }) });
const settle = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function markup(node) {
  const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  if (typeof node === 'string' || typeof node === 'number') return escape(node);
  if (!node) return '';
  assert.equal(node.props.dangerouslySetInnerHTML, undefined, 'renderer must not inject HTML');
  return `<${typeof node.type === 'string' ? node.type : 'component'}>${(node.children || []).map(markup).join('')}</${typeof node.type === 'string' ? node.type : 'component'}>`;
}

test('CFG layout preserves branches, loops and disconnected blocks without invalid edges', () => {
  const graph = ui.layoutCfg({ blocks: [{ id: 0, succs: [1, 2] }, { id: 1, succs: [0] }, { id: 2, succs: [] }, { id: 9, succs: [] }], edges: [{ from: 0, to: 1 }, { from: 0, to: 2 }, { from: 1, to: 0 }, { from: 0, to: 1 }, { from: 0, to: 99 }] });
  assert.equal(graph.nodes.length, 4); assert.equal(graph.edges.length, 3);
  assert.equal(graph.edges[0].label, '分支 1'); assert.equal(graph.edges[1].label, '分支 2'); assert.equal(graph.edges[2].label, '回边');
  assert.ok(graph.edges.every(e => !/NaN|undefined/.test(e.path)));
  assert.equal(new Set(graph.nodes.map(n => `${n.x},${n.y}`)).size, 4);
});

test('large CFG is bounded and truthfully marks truncation', () => {
  const graph = ui.layoutCfg({ blocks: Array.from({ length: 310 }, (_, id) => ({ id, succs: [id + 1] })) });
  assert.equal(graph.nodes.length, 300); assert.equal(graph.truncated, true); assert.equal(graph.edges.length, 299);
});

test('variable highlighting respects identifiers and never interprets source as HTML', () => {
  const parts = plain(ui.highlightParts('key = monkey + key2 + key; // <script>x</script>', 'key'));
  assert.deepEqual(parts.filter(p => p.match).map(p => p.text), ['key', 'key']);
  const tree = { type: 'pre', props: {}, children: ui.renderCodeLines([{ line_no: 19, code: '<img src=x onerror=alert(1)> key' }], 'key') };
  assert.ok(markup(tree).includes('&lt;img')); assert.ok(!markup(tree).includes('<img'));
  assert.equal(ui.highlightParts('a.b + aXb', 'a.b').filter(p => p.match).length, 1);
});

test('audit normalization uses actual nested journal fields and preserves offset zero', () => {
  const item = ui.normalizeAudit({ ts: '2026-10-09T00:00:00Z', tool: 'ig5_patch_bytes', args: { target: 'C:/sample.exe', ea: '0x401000' }, detail: { before: '90', after: 'cc', fileOffset: 0 }, isError: false });
  assert.equal(item.target, 'C:/sample.exe'); assert.equal(item.ea, '0x401000'); assert.equal(item.fileOffset, 0); assert.equal(item.before, '90');
  assert.equal(ui.normalizedTarget('C:/A/B.EXE'), ui.normalizedTarget('c:\\a\\b.exe'));
  assert.equal(ui.normalizeAudit({ result: { isError: true, value: 'failed' } }).isError, true);
});

test('structure draft serializes target and C declaration without executing a write', () => {
  const declaration = 'struct Packet { char value[32]; };\n// "quoted"';
  const draft = ui.buildStructDraft('C:\\samples\\a.exe', declaration);
  const args = JSON.parse(draft.slice(draft.indexOf('{')));
  assert.equal(args.action, 'define'); assert.equal(args.decl, declaration); assert.equal(args.target, 'C:\\samples\\a.exe'); assert.equal(args.op, undefined);
});

test('structure editor inserts an editable draft through native selection APIs without submit/fetch', () => {
  const calls = [], span = { revision: 4, start: 7, end: 7 };
  const h = harness(ui.StructEditor, { target: 'sample.exe', inputActions: { captureInsertion: () => span, insertText: (...args) => { calls.push(['insert', ...args]); return true; }, persistDraft: () => calls.push(['persist']), submit: () => { throw new Error('must not submit'); } } });
  h.render(); button(h.tree, '生成审批草稿').props.onClick(); h.render();
  const draft = nodes(h.tree, n => n.type === 'textarea' && n.props['aria-label'] === '待发送工具调用草稿')[0];
  draft.props.onChange({ target: { value: draft.props.value + '\n请先核查类型名。' } }); h.render();
  button(h.tree, '插入会话草稿（待发送）').props.onClick(); h.render();
  assert.equal(calls[0][0], 'insert'); assert.equal(calls[0][2], span); assert.ok(calls[0][1].includes('请先核查类型名。')); assert.equal(calls[1][0], 'persist'); assert.match(text(h.tree), /尚未发送或执行/);
});

test('structure editor retains draft when composer is unavailable or refuses stale insertion', () => {
  const h = harness(ui.StructEditor, { target: 'sample.exe' }); h.render(); button(h.tree, '生成审批草稿').props.onClick(); h.render(); button(h.tree, '插入会话草稿（待发送）').props.onClick(); h.render();
  assert.match(text(h.tree), /复制下方草稿/);
  assert.ok(nodes(h.tree, n => n.type === 'textarea' && n.props['aria-label'] === '待发送工具调用草稿')[0].props.value.includes('ig5_struct'));
  const locked = harness(ui.StructEditor, { target: 'sample.exe', inputActions: { captureInsertion: () => ({}), insertText: () => false, persistDraft: () => assert.fail('must not persist rejected insertion') } });
  locked.render(); button(locked.tree, '生成审批草稿').props.onClick(); locked.render(); button(locked.tree, '插入会话草稿（待发送）').props.onClick(); locked.render(); assert.match(text(locked.tree), /暂不可用/);
});

test('CFG nodes retain double-click and keyboard actions instead of being captured by canvas pan', () => {
  const opened = [], h = harness(ui.CfgGraph, { cfg: { blocks: [{ id: 0, start: '0x1000', end: '0x1004', insns: 1, succs: [] }] }, onOpen: block => opened.push(block.start) });
  h.render(); h.render(); const svg = nodes(h.tree, n => n.type === 'svg')[0], block = nodes(h.tree, n => n.type === 'g' && n.props.role === 'button')[0];
  let captured = false;
  svg.props.onPointerDown({ button: 0, target: { closest: () => true }, currentTarget: { setPointerCapture: () => { captured = true; } } });
  assert.equal(captured, false); block.props.onDoubleClick(); block.props.onKeyDown({ key: 'Enter' }); assert.deepEqual(opened, ['0x1000', '0x1000']);
});

test('request generations reject old selections', () => {
  const gate = ui.makeRequestGate(), first = gate.next(), second = gate.next();
  assert.equal(gate.isCurrent(first), false); assert.equal(gate.isCurrent(second), true); gate.next(); assert.equal(gate.isCurrent(second), false);
});

test('POSIX sample identities remain case-sensitive while Windows spellings match', () => {
  assert.notEqual(ui.normalizedTarget('/home/user/A.exe'), ui.normalizedTarget('/home/user/a.exe'));
  assert.equal(ui.normalizedTarget('C:/A/B.EXE'), ui.normalizedTarget('c:\\a\\b.exe'));
});

test('touch pinch preserves its focal point and clamps zoom; touch blocks open read-only', () => {
  for (const viewport of [{ width: 329, height: 360 }, { width: 900, height: 440 }]) {
    const graph = { width: 624, height: 700 }, fit = ui.cfgFitCamera(graph, viewport.width, viewport.height);
    assert.ok(fit.x >= 11.99 && fit.y >= 11.99);
    assert.ok(fit.x + graph.width * fit.scale <= viewport.width - 11.99);
    assert.ok(fit.y + graph.height * fit.scale <= viewport.height - 11.99);
  }
  const start = ui.cfgPinchStart([{ x: 100, y: 100 }, { x: 200, y: 100 }], { scale: 1, x: 0, y: 0 });
  const camera = ui.cfgPinchCamera(start, [{ x: 50, y: 100 }, { x: 250, y: 100 }]);
  assert.equal(camera.scale, 2); assert.equal(camera.x, -150); assert.equal(camera.y, -100);
  assert.equal(ui.cfgPinchCamera(start, [{ x: -10000, y: 100 }, { x: 10000, y: 100 }]).scale, 4);
  const opened = [], h = harness(ui.CfgGraph, { cfg: { blocks: [{ id: 0, start: '0x1000', succs: [] }] }, onOpen: n => opened.push(n.start) });
  h.render(); const svg = nodes(h.tree, n => n.type === 'svg')[0];
  const event = (id, x, y) => ({pointerType: 'touch',pointerId:id,clientX:x,clientY:y,target:{closest:()=>({getAttribute:()=> '0'})},currentTarget:{setPointerCapture(){},getBoundingClientRect:()=>({width:800,left:0,top:0})}});
  svg.props.onPointerDown(event(1,100,100)); svg.props.onPointerUp(event(1,100,100)); assert.deepEqual(opened, ['0x1000']);
  svg.props.onPointerDown(event(2,100,100)); svg.props.onPointerMove(event(2,130,100)); svg.props.onPointerUp(event(2,130,100)); assert.equal(opened.length,1);
  svg.props.onPointerDown(event(3,100,100)); svg.props.onPointerDown(event(4,200,100));
  svg.props.onPointerMove(event(3,50,100)); svg.props.onPointerMove(event(4,250,100));
  svg.props.onPointerUp(event(3,50,100)); svg.props.onPointerUp(event(4,250,100)); assert.equal(opened.length,1);
  for (const id of [5,6,7]) svg.props.onPointerDown(event(id,100,100));
  for (const id of [5,6,7]) svg.props.onPointerUp(event(id,100,100));
  assert.equal(opened.length,1); h.unmount();
});

test('environment view reports missing local runtime and never assumes mobile execution', () => {
  const h = harness(ui.EnvironmentCard, { config: { host: { id: 'linux-arm64', supported: true }, engines: [{ id: 'ghidra', available: false, source: 'bundled', reason: '<missing ARM64 runtime>' }] } });
  h.render(); assert.match(text(h.tree), /Ghidra · 不可用/); assert.ok(markup(h.tree).includes('&lt;missing ARM64 runtime&gt;'));
  h.render({ config: { host: { id: 'ios-arm64', supported: false }, engines: [] } }); assert.match(text(h.tree), /移动界面可用不代表引擎已移植/); h.unmount();
});

test('pending lazy CFG reads cannot replace a newer function or survive same-function reload', async () => {
  const cfgReads = [];
  request = url => {
    const q = new URL(url, 'http://test').searchParams, type = q.get('type'), ea = q.get('ea');
    if (type === 'cfg') { const d = deferred(); cfgReads.push({ ea, d }); return d.promise; }
    return Promise.resolve(response(type === 'funcs' ? { funcs: [{ ea: '0x1000', name: 'one' }, { ea: '0x2000', name: 'two' }], total: 2 } : type === 'decompile' ? { ea, code: 'return 0;' } : { rows: [] }));
  };
  const h = harness(ui.FunctionsView, { target: '/home/sample.exe' }); h.render(); await settle(); h.render();
  row(h.tree, 'one').props.onClick(); h.render(); button(h.tree, '控制流 (CFG)').props.onClick(); h.render();
  row(h.tree, 'two').props.onClick(); h.render(); row(h.tree, 'two').props.onClick(); h.render();
  assert.equal(cfgReads.length, 3);
  cfgReads[2].d.resolve(response({ blocks: [], marker: 'current' })); await settle(); h.render();
  for (const old of cfgReads.slice(0, 2)) old.d.resolve(response({ blocks: [], marker: 'stale' }));
  await settle(); h.render(); assert.equal(nodes(h.tree, n => n.type === ui.CfgGraph)[0].props.cfg.marker, 'current'); h.unmount();
});

test('rapid function selections keep newest code, CFG and variable data', async () => {
  const pending = new Map();
  request = url => {
    const q = new URL(url, 'http://test').searchParams, type = q.get('type'), ea = q.get('ea');
    if (type === 'funcs') return Promise.resolve(response({ funcs: [{ ea: '0x1000', name: 'first', size: 4 }, { ea: '0x2000', name: 'second', size: 4 }], total: 2 }));
    const d = deferred(); pending.set(`${type}:${ea}`, d); return d.promise;
  };
  const h = harness(ui.FunctionsView, { target: 'sample.exe' }); h.render(); await settle(); h.render();
  row(h.tree, 'first').props.onClick(); h.render(); row(h.tree, 'second').props.onClick();
  assert.ok(!pending.has('cfg:0x2000') && !pending.has('slice:0x2000'), 'heavy views are requested on selection of that view');
  for (const ea of ['0x2000', '0x1000']) for (const type of ['decompile', 'xrefs', 'calls']) pending.get(`${type}:${ea}`).resolve(response(type === 'decompile' ? { ea, name: ea === '0x2000' ? 'second' : 'first', code: `code-${ea}` } : { rows: [] }));
  await settle(); h.render(); assert.match(text(h.tree), /code-0x2000/); assert.ok(!text(h.tree).includes('code-0x1000'));
  button(h.tree, '控制流 (CFG)').props.onClick(); h.render(); pending.get('cfg:0x2000').resolve(response({ blocks: [], edges: [], marker: '0x2000' })); await settle(); h.render(); assert.equal(nodes(h.tree, n => n.type === ui.CfgGraph)[0].props.cfg.marker, '0x2000');
  button(h.tree, '变量与切片').props.onClick(); h.render(); pending.get('slice:0x2000').resolve(response({ variables: [{ name: 'v-0x2000' }] })); await settle(); h.render(); assert.match(text(h.tree), /v-0x2000/); assert.ok(!text(h.tree).includes('v-0x1000')); h.unmount();
});

test('focused variable click requests var and highlights returned source line', async () => {
  const urls = [];
  request = url => {
    urls.push(url); const q = new URL(url, 'http://test').searchParams, type = q.get('type');
    return Promise.resolve(response(type === 'funcs' ? { funcs: [{ ea: '0x1000', name: 'main', size: 4 }], total: 1 } : type === 'decompile' ? { ea: '0x1000', name: 'main', code: 'key = 2;' } : type === 'slice' ? { variables: [{ name: 'key', type: 'int', size: 4 }], slice_lines: q.get('var') ? [{ line_no: 4, code: 'key = 2;' }] : [] } : type === 'cfg' ? { blocks: [], edges: [] } : { rows: [] }));
  };
  const h = harness(ui.FunctionsView, { target: 'sample.exe' }); h.render(); await settle(); h.render(); row(h.tree, 'main').props.onClick(); await settle(); h.render(); button(h.tree, '变量与切片').props.onClick(); h.render(); await settle(); h.render(); row(h.tree, 'key').props.onClick(); await settle(); h.render();
  assert.ok(urls.some(url => new URL(url, 'http://test').searchParams.get('var') === 'key')); assert.equal(nodes(h.tree, n => n.type === 'mark').map(text).join(''), 'key'); h.unmount();
});

test('switching target invalidates pending function reads and removes old code', async () => {
  const pending = [];
  request = url => {
    const q = new URL(url, 'http://test').searchParams;
    if (q.get('type') === 'funcs') return Promise.resolve(response({ funcs: [{ ea: '0x1000', name: q.get('target'), size: 4 }], total: 1 }));
    const d = deferred(); pending.push({ d, type: q.get('type') }); return d.promise;
  };
  const h = harness(ui.FunctionsView, { target: 'old.exe' }); h.render(); await settle(); h.render(); row(h.tree, 'old.exe').props.onClick(); h.render(); h.render({ target: 'new.exe' });
  for (const { d, type } of pending) d.resolve(response(type === 'decompile' ? { ea: '0x1000', name: 'old', code: 'STALE_CODE' } : type === 'cfg' ? { blocks: [], edges: [] } : type === 'slice' ? { variables: [] } : { rows: [] }));
  await settle(); h.render(); assert.ok(!text(h.tree).includes('STALE_CODE')); assert.match(text(h.tree), /new.exe/); assert.match(text(h.tree), /选择函数，查看当前静态引擎/); h.unmount();
});

test('CFG block jump uses only read-only disassembly and displays instructions', async () => {
  const urls = [], block = { id: 0, start: '0x1000', end: '0x1004', succs: [], insns: 1 };
  request = url => { urls.push(url); const q = new URL(url, 'http://test').searchParams, type = q.get('type'); return Promise.resolve(response(type === 'funcs' ? { funcs: [{ ea: '0x1000', name: 'main', size: 4 }], total: 1 } : type === 'decompile' ? { ea: '0x1000', name: 'main', code: 'return 0;' } : type === 'cfg' ? { blocks: [block], edges: [] } : type === 'slice' ? { variables: [] } : type === 'disasm' ? { rows: [{ ea: '0x1000', bytes: '90', text: 'nop' }] } : { rows: [] })); };
  const h = harness(ui.FunctionsView, { target: 'sample.exe' }); h.render(); await settle(); h.render(); row(h.tree, 'main').props.onClick(); await settle(); h.render(); button(h.tree, '控制流 (CFG)').props.onClick(); h.render(); await settle(); h.render(); nodes(h.tree, n => n.type === ui.CfgGraph)[0].props.onOpen(block); await settle(); h.render();
  assert.match(text(h.tree), /反汇编（只读）/); assert.match(text(h.tree), /nop/); assert.ok(urls.some(url => url.includes('type=disasm'))); h.unmount();
});

test('audit renderer filters targets, escapes malicious text, paginates and refreshes', async () => {
  const urls = [];
  request = url => { urls.push(url); return Promise.resolve(response({ rows: [{ tool: '<script>alert(1)</script>', args: { target: 'C:/a.exe', ea: '0x1000' }, ts: 'now', detail: { before: '90', after: 'cc', fileOffset: 0 } }, { tool: 'other-target', args: { target: 'C:/b.exe' } }], total: 25, offset: 0, limit: 20 })); };
  const h = harness(ui.PatchesView, { target: 'C:/a.exe' }); h.render(); await settle(); h.render(); assert.ok(!text(h.tree).includes('other-target')); assert.match(text(h.tree), /文件偏移: 0/); assert.ok(markup(h.tree).includes('&lt;script&gt;')); assert.ok(!markup(h.tree).includes('<script>'));
  button(h.tree, '下一页').props.onClick(); h.render(); await settle(); h.render(); assert.ok(urls.some(url => url.includes('offset=20')));
  const before = urls.length; button(h.tree, '刷新记录').props.onClick(); h.render(); await settle(); assert.ok(urls.length > before); h.unmount();
});

test('same target in different engines has a distinct selection and explicit draft engine', () => {
  const reverse = { key: 'same', target: 'C:/a.exe', engine: 'reverse' }, ghidra = { ...reverse, engine: 'ghidra' };
  assert.notEqual(ui.sessionIdentity(reverse), ui.sessionIdentity(ghidra));
  const draft = ui.buildStructDraft('C:/a.exe', 'struct A { int x; };', 'ghidra');
  assert.equal(JSON.parse(draft.slice(draft.indexOf('{'))).engine, 'ghidra');
  assert.equal(ui.parseWorkbenchFocus(JSON.stringify({ v: 1, target: 'a.exe', engine: 'ghidra', ea: '0xfffff80000000001' })).ea, '0xfffff80000000001');
  assert.equal(ui.parseWorkbenchFocus(JSON.stringify({ v: 1, target: 'a.exe', engine: 'x64dbg', ea: '0x1' })), null);
  assert.equal(ui.parseWorkbenchFocus(JSON.stringify({ v: 1, target: 'a.exe', engine: 'reverse', ea: 9007199254740992 })), null);
});

test('switching only engine invalidates pending function reads at the same target', async () => {
  const pending = [];
  request = url => {
    const q = new URL(url, 'http://test').searchParams, engine = q.get('engine'), type = q.get('type');
    assert.ok(['reverse', 'ghidra'].includes(engine));
    if (type === 'funcs') return Promise.resolve(response({ funcs: [{ ea: '0x1000', name: `${engine}-main`, size: 4 }], total: 1 }));
    const d = deferred(); pending.push({ d, type, engine }); return d.promise;
  };
  const h = harness(ui.FunctionsView, { target: 'same.exe', engine: 'reverse' }); h.render(); await settle(); h.render(); row(h.tree, 'reverse-main').props.onClick();
  h.render({ target: 'same.exe', engine: 'ghidra' }); await settle(); h.render(); row(h.tree, 'ghidra-main').props.onClick();
  for (const engine of ['ghidra', 'reverse']) for (const item of pending.filter(x => x.engine === engine)) item.d.resolve(response(item.type === 'decompile' ? { ea: '0x1000', name: engine, code: `${engine}-CODE` } : item.type === 'cfg' ? { blocks: [], edges: [] } : item.type === 'slice' ? { variables: [] } : { rows: [] }));
  await settle(); h.render(); assert.match(text(h.tree), /ghidra-CODE/); assert.ok(!text(h.tree).includes('reverse-CODE')); h.unmount();
});

test('workbench excludes dynamic sessions and validates native focus artifact identity', async () => {
  const sessions = [
    { key: 'r', target: 'same.exe', engine: 'reverse', alive: true, projectId: 'p', artifactId: 'a', dbRevision: 2 },
    { key: 'g', target: 'same.exe', engine: 'ghidra', alive: true, projectId: 'p', artifactId: 'a', dbRevision: 3 },
    { key: 'x', target: 'same.exe', engine: 'x64dbg', alive: true },
  ];
  request = () => Promise.resolve({ ok: true, json: async () => ({ sessions, jobs: [] }) });
  let acknowledgements = 0;
  const focus = { v: 1, target: 'same.exe', engine: 'ghidra', artifactId: 'a', projectId: 'p', ea: '0x1000' };
  const props = { viewRequest: { view: 'ig5', focus: JSON.stringify(focus) }, completeViewRequest: () => acknowledgements++ };
  const h = harness(ui.Workbench, props); h.render(); await settle(); h.render(); h.render();
  const overview = nodes(h.tree, node => node.type === ui.OverviewCard)[0];
  assert.equal(overview.props.sessions.length, 2); assert.equal(overview.props.currentSession.engine, 'ghidra');
  assert.equal(nodes(h.tree, node => node.type === ui.FunctionsView)[0].props.focus.ea, '0x1000'); assert.equal(acknowledgements, 1);
  h.render({ ...props, viewRequest: { view: 'ig5', focus: JSON.stringify({ ...focus, artifactId: 'replaced' }) } }); h.render();
  assert.match(text(h.tree), /身份不匹配/); h.unmount();
});

test('function navigation calls the host openView contract with a target-owned focus', async () => {
  request = () => Promise.resolve({ ok: true, json: async () => ({ sessions: [{ key: 'g', target: 'same.exe', engine: 'ghidra', alive: true, artifactId: 'a' }], jobs: [] }) });
  const calls = [], h = harness(ui.Workbench, { openView: (...args) => calls.push(args) }); h.render(); await settle(); h.render();
  nodes(h.tree, node => node.type === ui.FunctionsView)[0].props.onNavigate({ ea: '0x1000', name: 'main' });
  assert.equal(calls.length, 1); assert.equal(calls[0][0], 'ig5');
  const focus = JSON.parse(calls[0][1]); assert.equal(focus.engine, 'ghidra'); assert.equal(focus.target, 'same.exe'); assert.equal(focus.artifactId, 'a'); h.unmount();
});

test('runtime view reads cached debug_state only and escapes register values', async () => {
  const urls = [];
  request = (url, options) => { urls.push(url); assert.equal(options, undefined); return Promise.resolve(response({ state: 'paused', runId: 'run_A', stopSeq: 3, regs: { rax: '<script>unsafe</script>' } })); };
  const h = harness(ui.RuntimeView, { sessions: [{ key: 'x', target: 'a.exe', engine: 'x64dbg' }], refresh: 1 }); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /run_A/); assert.match(text(h.tree), /只读缓存/); assert.ok(markup(h.tree).includes('&lt;script&gt;')); assert.ok(!markup(h.tree).includes('<script>'));
  assert.ok(urls.every(url => { const q = new URL(url, 'http://test').searchParams; return q.get('type') === 'debug_state' && q.get('engine') === 'x64dbg'; })); h.unmount();
});

test('Ghidra IR selection requests explicit level and keeps source distinct', async () => {
  const urls = [];
  request = url => { urls.push(url); return Promise.resolve(response({ kind: 'pcode', operations: ['COPY r0, 1'] })); };
  const h = harness(ui.IrView, { target: 'a.exe', engine: 'ghidra', ea: '0x1000' }); h.render(); await settle(); h.render();
  nodes(h.tree, node => node.type === 'select')[0].props.onChange({ target: { value: 'raw' } }); h.render(); await settle(); h.render();
  assert.ok(urls.some(url => { const q = new URL(url, 'http://test').searchParams; return q.get('type') === 'ir' && q.get('engine') === 'ghidra' && q.get('level') === 'raw' && q.get('limit') === '120'; }));
  assert.match(text(h.tree), /不对应 Reverse/); assert.match(text(h.tree), /COPY r0/); h.unmount();
});

test('audit view includes only selected engine at the same target', async () => {
  request = url => { assert.equal(new URL(url, 'http://test').searchParams.get('engine'), 'ghidra'); return Promise.resolve(response({ rows: [{ tool: 'ghidra-note', args: { target: 'a.exe', engine: 'ghidra' } }, { tool: 'ig5_sync', args: { target: 'a.exe' }, detail: { destination: { engine: 'ghidra' }, note: 'sync destination evidence' } }, { tool: 'reverse-note', args: { target: 'a.exe' } }], total: 1 })); };
  const h = harness(ui.PatchesView, { target: 'a.exe', engine: 'ghidra' }); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /ghidra-note/); assert.match(text(h.tree), /sync destination evidence/); assert.ok(!text(h.tree).includes('reverse-note')); h.unmount();
});

test('overview preserves partial analysis status instead of presenting completion', () => {
  const h = harness(ui.OverviewCard, { currentSession: { target: 'a.exe', engine: 'ghidra', partial: true, n_funcs: 17 }, sessions: [], runningCount: 0 });
  h.render(); assert.match(text(h.tree), /部分分析结果/); assert.ok(!text(h.tree).includes('分析会话就绪'));
  assert.ok(nodes(h.tree, node => node.props?.className === 'ig5-chip warn').length); h.unmount();
});

test('runtime target switch never labels the previous target snapshot as the new target', async () => {
  const a = { key: 'a', target: 'A.exe', engine: 'x64dbg', artifactId: 'artifact-A' };
  const b = { key: 'b', target: 'B.exe', engine: 'x64dbg', artifactId: 'artifact-B' };
  const oldRefresh = deferred(), nextTarget = deferred(); let aReads = 0;
  request = url => new URL(url, 'http://test').searchParams.get('target') === 'A.exe'
    ? (++aReads === 1 ? Promise.resolve(response({ state: 'paused', runId: 'run-A', regs: { rip: '0xAAA' } })) : oldRefresh.promise)
    : nextTarget.promise;
  const h = harness(ui.RuntimeView, { sessions: [a, b], refresh: 1 }); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /run-A/);
  h.render({ sessions: [a, b], refresh: 2 });
  nodes(h.tree, node => node.type === 'select')[0].props.onChange({ target: { value: ui.sessionIdentity(b) } });
  h.render(); h.render();
  assert.match(text(h.tree), /B.exe/); assert.ok(!text(h.tree).includes('run-A')); assert.ok(!text(h.tree).includes('0xAAA'));
  oldRefresh.resolve(response({ state: 'paused', runId: 'late-A', regs: { rip: '0xAAA' } })); await settle(); h.render();
  assert.ok(!text(h.tree).includes('late-A'));
  nextTarget.resolve(response({ state: 'paused', runId: 'run-B', regs: { rip: '0xBBB' } })); await settle(); h.render();
  assert.match(text(h.tree), /run-B/); assert.ok(!text(h.tree).includes('0xAAA')); h.unmount();
});

test('runtime replacement at the same path hides the old artifact snapshot', async () => {
  const session = { key: 'same', target: 'same.exe', engine: 'x64dbg', artifactId: 'old', attachmentId: 'old-attachment' };
  const next = deferred(); let reads = 0;
  request = () => ++reads === 1 ? Promise.resolve(response({ runId: 'old-run', regs: { rip: '0xAAA' } })) : next.promise;
  const h = harness(ui.RuntimeView, { sessions: [session], refresh: 1 }); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /old-run/);
  h.render({ sessions: [{ ...session, artifactId: 'new', attachmentId: 'new-attachment' }], refresh: 1 }); h.render();
  assert.ok(!text(h.tree).includes('old-run')); assert.ok(!text(h.tree).includes('0xAAA'));
  next.resolve(response({ runId: 'new-run' })); await settle(); h.render(); assert.match(text(h.tree), /new-run/); h.unmount();
});
