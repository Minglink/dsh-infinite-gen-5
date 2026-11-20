import { compareSemanticsAsync } from './semantic_diff_async.js';
import { captureCffStateSource, admitCffStateSource } from './source/cff_state_workflow.js';

export function defineAdvancedTools(mgr, cfg, render) {
  const targetProperty = { type: 'string' };
  const ea = { type: 'string' };
  const name = { type: 'string' };
  function session(args) {
    const engine = mgr.scope?.getStore()?.engine;
    const live = [...mgr.sessions.values()].filter((value) => mgr.alive(value) && value.engine !== 'x64dbg' && (!engine || !value.engine || value.engine === engine));
    if (!args.target && live.length !== 1) throw new Error('Specify target when there are zero or multiple active sessions');
    const selected = args.target ? mgr.get(args.target) : live[0];
    if (!mgr.alive(selected)) throw new Error('Target is not open; call ig5_open first');
    return selected;
  }
  function rpcTool(name, method, description, properties, required = []) {
    return {
      name, description,
      parameters: { type: 'object', properties: { target: targetProperty, ...properties }, required, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render },
      execute(args = {}, execution) {
        const selected = session(args);
        if (name === 'ig5_microcode' && args.action === 'deobfuscate' && selected.engine !== 'ghidra' && !(selected.engine === 'reverse' && cfg.reverseProvider !== 'commercial')) {
          throw new Error('deobfuscate requires the bundled Reverse or Ghidra provider');
        }
        if (name === 'ig5_microcode' && args.task_id !== undefined) {
          if(typeof args.task_id!=='string'||args.task_id.length>64||args.action!=='deobfuscate')throw new Error('task_id capture requires an exact current task and action=deobfuscate');
          if(!execution?.agent?.id)throw Object.assign(new Error('Source capture requires actual executing agent'),{code:'AGENT_SCOPE_REQUIRED'});
          const before=admitCffStateSource(mgr,cfg,selected,args,execution),{task_id,...params}=args;
          return Promise.resolve(mgr.rpc(selected,method,params,cfg.requestTimeoutMs)).then(result=>captureCffStateSource(mgr,cfg,selected,args,result,execution,before));
        }
        return mgr.rpc(selected, method, args, cfg.requestTimeoutMs);
      },
    };
  }
  return [
    rpcTool('ig5_stack', 'stack', 'Read-only stack frame members, offsets, args, and saved registers.',
      { ea, name, limit: { type: 'number' } }),
    rpcTool('ig5_switches', 'switches', 'Read-only switch/jump-table metadata, cases, targets, and default branches.',
      { ea, name, exact: { type: 'boolean' }, limit: { type: 'number' }, max_cases: { type: 'number' } }),
    rpcTool('ig5_switch_repair', 'switch_repair', 'Preview or rebuild/define switch table (apply=true mutates DB; approval-gated).',
      { ea, action: { type: 'string', enum: ['rebuild', 'define'] }, apply: { type: 'boolean' },
        table: ea, ncases: { type: 'number' }, element_size: { type: 'number', enum: [1, 2, 4, 8] },
        lowcase: { type: 'number' }, default: ea, relative: { type: 'boolean' }, signed: { type: 'boolean' },
        elbase: ea, shift: { type: 'number' }, create_instructions: { type: 'boolean' } }, ['ea']),
    rpcTool('ig5_vtables', 'vtables', 'Read-only MSVC/Itanium vtables, RTTI classes, and explicit slot resolution.',
      { ea, abi: { type: 'string', enum: ['auto', 'msvc', 'itanium'] }, offset: { type: 'number' },
        max_slots: { type: 'number' }, limit: { type: 'number' }, max_scan_bytes: { type: 'number' }, max_bases: { type: 'number' } }),
    rpcTool('ig5_microcode', 'microcode', 'Read-only IR/CFG inspect, optimize, or bounded SSA/MBA/CFF deobfuscation.',
      { ea, name, action: { type: 'string', enum: ['inspect', 'optimize', 'deobfuscate'] }, maturity: { type: 'string', enum: ['generated', 'preoptimized', 'locopt', 'calls', 'glbopt1', 'glbopt2', 'glbopt3', 'lvars'] },
        max_blocks: { type: 'number' }, max_instructions: { type: 'number' },
        max_steps: { type: 'integer', minimum: 1, maximum: 250000 },
        max_evidence: { type: 'integer', minimum: 1, maximum: 512 },
        rules: { type: 'array', items: { type: 'string', enum: ['xor-self', 'sub-self'] } },
        task_id: { type: 'string' } }),
    {
      name: 'ig5_bindiff',
      description: 'Read-only CFG/structural diff between two opened binaries.',
      parameters: { type: 'object', properties: { left: targetProperty, right: targetProperty,
        filter: { type: 'string' }, user_only: { type: 'boolean' }, limit_functions: { type: 'number' },
        threshold: { type: 'number' }, limit: { type: 'number' } },
      required: ['left', 'right'], additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render },
      async execute(args) {
        if (!args?.left || !args?.right) throw new Error('left and right opened targets are required');
        if (mgr.sessionKey(args.left) === mgr.sessionKey(args.right)) throw new Error('Open two different target paths for a version comparison');
        const params = { limit: args.limit_functions || 500, filter: args.filter || '', user_only: args.user_only !== false };
        const [left, right] = await Promise.all([
          mgr.rpc(session({ target: args.left }), 'semantics', params, cfg.requestTimeoutMs),
          mgr.rpc(session({ target: args.right }), 'semantics', params, cfg.requestTimeoutMs),
        ]);
        return { left: args.left, right: args.right, ...await compareSemanticsAsync(left, right, args, mgr.scope?.getStore()?.signal) };
      },
    },
    rpcTool('ig5_emulate', 'emulate', 'APPROVAL REQUIRED. Isolated x86/x64/ARM64 CPU function or x86-64 string-decoder emulation (no OS calls).',
      { mode: { type: 'string', enum: ['function', 'decode_strings'] },
        min_calls: { type: 'number' },
        max_decoders: { type: 'number' },
        max_runs: { type: 'number' },
        max_runs_per_decoder: { type: 'number' },
        time_budget_ms: { type: 'number' },
        max_strings: { type: 'number' },
        min_text: { type: 'number' },
        max_size: { type: 'number' },
        ea, name, abi: { type: 'string', enum: ['win64', 'sysv64', 'cdecl', 'stdcall', 'aapcs64'] },
        args: { type: 'array', items: { type: 'string' } },
        registers: { type: 'object', additionalProperties: { type: 'string' } },
        memory: { type: 'array', items: { type: 'object', properties: { ea, hex: { type: 'string' } }, required: ['ea', 'hex'], additionalProperties: false } },
        capture: { type: 'array', items: { type: 'object', properties: { ea, size: { type: 'number' } }, required: ['ea'], additionalProperties: false } },
        max_instructions: { type: 'number' }, timeout_ms: { type: 'number' } }),
  ];
}
