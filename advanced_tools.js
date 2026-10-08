import { compareSemantics } from './semantic_diff.js';

export function defineAdvancedTools(mgr, cfg, render) {
  const targetProperty = { type: 'string', description: 'Opened target path; omit only when one active target is selected' };
  const ea = { type: 'string', description: 'Address, for example 0x140001000' };
  const name = { type: 'string', description: 'Exact function or type name' };
  function session(args) {
    const live = [...mgr.sessions.values()].filter((value) => mgr.alive(value));
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
      execute(args = {}) { return mgr.rpc(session(args), method, args, cfg.requestTimeoutMs); },
    };
  }
  return [
    rpcTool('ig5_stack', 'stack', 'Read assembly-level stack frame members, stack offsets, arguments, saved registers and return-address regions without depending on decompilation.',
      { ea, name, limit: { type: 'number', description: 'Maximum frame fields, default 200' } }),
    rpcTool('ig5_switches', 'switches', 'Recover recognized switch/jump-table metadata, case-value groups, target addresses and default branches. Can enumerate a function or inspect an exact jump address. Read-only.',
      { ea, name, exact: { type: 'boolean' }, limit: { type: 'number' }, max_cases: { type: 'number' } }),
    rpcTool('ig5_switch_repair', 'switch_repair', 'Preview or rebuild a switch table from existing metadata or an explicit direct table definition. apply=true changes the analysis database and branch xrefs. Approval-gated; verify every target before applying.',
      { ea, action: { type: 'string', enum: ['rebuild', 'define'] }, apply: { type: 'boolean' },
        table: ea, ncases: { type: 'number' }, element_size: { type: 'number', enum: [1, 2, 4, 8] },
        lowcase: { type: 'number' }, default: ea, relative: { type: 'boolean' }, signed: { type: 'boolean' },
        elbase: ea, shift: { type: 'number' }, create_instructions: { type: 'boolean' } }, ['ea']),
    rpcTool('ig5_vtables', 'vtables', 'Inspect MSVC and Itanium virtual tables, RTTI class names and inheritance evidence. Returns virtual slots and a reviewable structure declaration. Given a table EA and byte offset, resolve that explicit virtual slot; register provenance is not inferred.',
      { ea, abi: { type: 'string', enum: ['auto', 'msvc', 'itanium'] }, offset: { type: 'number' },
        max_slots: { type: 'number' }, limit: { type: 'number' }, max_scan_bytes: { type: 'number' }, max_bases: { type: 'number' } }),
    rpcTool('ig5_microcode', 'microcode', 'Generate real intermediate microcode at a selected optimization maturity. Inspect blocks and instructions, or optimize a temporary early-stage IR with optional restricted xor-self/sub-self filters and inspect rule hits and before/after evidence. Does not persist IR changes or automatically remove control-flow flattening.',
      { ea, name, action: { type: 'string', enum: ['inspect', 'optimize'] }, maturity: { type: 'string', enum: ['generated', 'preoptimized', 'locopt', 'calls', 'glbopt1', 'glbopt2', 'glbopt3', 'lvars'] },
        max_blocks: { type: 'number' }, max_instructions: { type: 'number' }, rules: { type: 'array', items: { type: 'string', enum: ['xor-self', 'sub-self'] } } }),
    {
      name: 'ig5_bindiff',
      description: 'Compare two opened binary versions by normalized instructions, CFG neighborhoods, constants and call degree. Return scored function matches and changed basic blocks with ambiguity/truncation evidence. Heuristic patch candidates, not a claim of vulnerability or semantic equivalence. Read-only.',
      parameters: { type: 'object', properties: { left: targetProperty, right: targetProperty,
        filter: { type: 'string' }, user_only: { type: 'boolean' }, limit_functions: { type: 'number', description: 'Max functions per side, default 500, max 2000' },
        threshold: { type: 'number' }, limit: { type: 'number', description: 'Maximum returned matches and changes, default 100' } },
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
        return { left: args.left, right: args.right, ...compareSemantics(left, right, args) };
      },
    },
    rpcTool('ig5_emulate', 'emulate', 'Isolated x86/x64 function CPU emulation using copied target memory and a synthetic stack. Provide integer arguments, registers and memory buffers; capture return values and memory. No native process or OS/import emulation. Approval-gated; bounded time/instruction/memory budgets.',
      { ea, name, abi: { type: 'string', enum: ['win64', 'sysv64', 'cdecl', 'stdcall'] },
        args: { type: 'array', items: { type: 'string' }, description: 'Integer arguments encoded as decimal or hex strings' },
        registers: { type: 'object', additionalProperties: { type: 'string' } },
        memory: { type: 'array', items: { type: 'object', properties: { ea, hex: { type: 'string' } }, required: ['ea', 'hex'], additionalProperties: false } },
        capture: { type: 'array', items: { type: 'object', properties: { ea, size: { type: 'number' } }, required: ['ea'], additionalProperties: false } },
        max_instructions: { type: 'number' }, timeout_ms: { type: 'number' } }),
  ];
}
