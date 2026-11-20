import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { readStableFile, hashBytes } from './analysis_artifacts.js';
import { deriveExecutableProgram } from './vm_bytecode.js';
import { prepareRoleValidation } from './vm_role_validation.js';
import { loadObservationWindows } from './vm_observation_profile.js';
import { committedBytes, evidenceReadBudget, exactReportRef } from './evidence_adapters/vm_context.js';
import { loadComparedContexts, compareVmRoles } from './vm_role_compare.js';
import { buildObservedVmCfg } from './vm_cfg.js';
import { validateFunctionContract, exactData, assessFunctionContract, boundedDataArray } from './vm_function_contract.js';
import { planningDigest } from './planning_identity.js';

const REF = { type: 'object', properties: { id: { type: 'string' }, sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' } }, required: ['id','sha256'], additionalProperties: false };
const HEX = { type: 'string', pattern: '^0x[0-9a-f]{1,16}$' };
const CONTRACT = { type: 'object', properties: {
  schema: { type: 'string', enum: ['ig5-function-contract-v1'] }, targetSha256: { type: 'string', pattern: '^[a-f0-9]{64}$' },
  entryRva: HEX, normalReturn: { type: 'string', enum: ['native-ret','bytecode-halt'] },
  input: { type: 'object', properties: { register: { type: 'string', enum: ['rcx'] }, bits: { type: 'integer', enum: [8,16,32,64] }, minimum: HEX, maximum: HEX }, required: ['register','bits','minimum','maximum'], additionalProperties: false },
  outputs: { type: 'object', properties: { returnRegister: { type: 'string', enum: ['rax'] }, memory: { type: 'array', maxItems: 16,
    items: { type: 'object', properties: { rva: HEX, bytes: { type: 'integer', minimum: 1, maximum: 256 } }, required: ['rva','bytes'], additionalProperties: false } } }, required: ['returnRegister','memory'], additionalProperties: false },
  environment: { type: 'string', enum: ['single-threaded-no-external-calls'] }, exclusions: { type: 'array', maxItems: 16, items: { type: 'string', maxLength: 256 } },
}, required: ['schema','targetSha256','entryRva','normalReturn','input','outputs','environment','exclusions'], additionalProperties: false };
export const progressionSchemas = {
  declare_contract: { type: 'object', properties: { contract: CONTRACT }, required: ['contract'], additionalProperties: false },
  role_compare: { type: 'object', properties: { context_refs: { type: 'array', minItems: 1, maxItems: 8, items: REF }, contract_ref: REF }, required: ['context_refs','contract_ref'], additionalProperties: false },
  role_validate:{type:'object',properties:{comparison_ref:REF,recording_bindings:{type:'array',minItems:1,maxItems:8,items:{type:'object',properties:{context_ref:REF,recordings:{type:'array',minItems:1,maxItems:256,items:REF}},required:['context_ref','recordings'],additionalProperties:false}}},required:['comparison_ref','recording_bindings'],additionalProperties:false},
  program: { type: 'object', properties: { comparison_ref: REF, contract_ref: REF,
    image_ref: { type:'object',properties:{path:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['path','sha256'],additionalProperties:false } },
    oneOf:[{required:['comparison_ref']},{required:['image_ref','contract_ref']}],additionalProperties:false },
  function_check: { type: 'object', properties: { program_ref: REF, sample_inputs:{type:'array',maxItems:64,items:HEX},
    recording_runs:{type:'array',maxItems:8,items:{type:'object',properties:{recordings:{type:'array',minItems:1,maxItems:256,items:REF}},required:['recordings'],additionalProperties:false}} }, required: ['program_ref'], additionalProperties: false },
};
const same = (a,b) => planningDigest(a) === planningDigest(b);
const fail = message => { throw Object.assign(new Error(message), { code: 'VM_RESEARCH_SOURCE_CHANGED' }); };
export function saveVmProgression(artifacts, mode, kind, action, result) {
  const record = artifacts.save({ kind, action, result }, { pretty: true, maxBytes: 4 * 1024 ** 2 });
  return { [mode]: { schema: result.schema ?? result.contract.schema, status: result.status ?? result.authority,
    reportId: record.id, reportSha256: artifacts.metadata(record.id).result.recordSha256,
    reportPath: path.join(artifacts.directory('records'), record.id + '.json'),
    counts: { nodes: result.nodes?.length ?? result.graph?.nodes.length ?? 0, edges: result.edges?.length ?? result.graph?.edges.length ?? 0,
      unresolved: result.unresolvedEdges?.length ?? result.graph?.unresolvedEdges.length ?? 0, relations: result.relations?.length ?? 0 },
    independence: result.independence ?? null, obligations: result.obligations ?? [], finiteTesting:result.finiteTesting ?? null,
    modelContractAccepted: result.modelContractAccepted === true, exhaustiveFiniteDomain:result.exhaustiveFiniteDomain === true,
    businessAccepted: false, nativeTargetExecuted: false, changesExecutionAuthority: false, fullReportRequired: true } };
}
function imageSnapshot(ref) {
  exactData(ref,['path','sha256']);
  if(typeof ref.path!=='string'||!path.isAbsolute(ref.path)||ref.path.includes('\0')||/^(\\\\|\/\/)/.test(ref.path)
    ||ref.path.split(/[\\/]/).includes('..')||typeof ref.sha256!=='string'||!/^[a-f0-9]{64}$/.test(ref.sha256))fail('Explicit bounded local image reference required');
  for(let p=path.dirname(path.resolve(ref.path));;p=path.dirname(p)) { const stat=fs.lstatSync(p);if(!stat.isDirectory()||stat.isSymbolicLink())fail('Linked image ancestor');if(p===path.dirname(p))break; }
  const {data}=readStableFile(ref.path,65536);if(hashBytes(data)!==ref.sha256)fail('Image SHA differs');return data;
}

/** All new entries read committed data; they cannot launch engines, debugging, solvers or arbitrary oracle code. */
export function runVmProgression(mgr, mode, input, cfg) {
  const artifacts = mgr.analysis.artifacts, budget = evidenceReadBudget(), cancelled = () => mgr.checkCancelled();
  const read = (ref, kind, action) => committedBytes(artifacts, exactReportRef(ref), kind, action, budget).record.result;
  const contract = ref => {
    const c = read(ref, 'vm-function-contract', 'declare');
    if (c?.authority !== 'caller-declared-scope' || c.businessAccepted !== false) fail('Contract declaration scope differs');
    return validateFunctionContract(c.contract);
  };
  const comparison = ref => {
    const saved = read(ref, 'vm-role-comparison', 'compare'), c = contract(saved.contractRef);
    const contexts = loadComparedContexts(artifacts, saved.sourceContexts, c.targetSha256, cancelled, budget);
    const fresh = compareVmRoles(contexts, saved.contractRef, c.targetSha256);
    if (!same(saved, fresh)) fail('Role comparison differs from audited source closure');
    return { result: fresh, contexts, contract: c };
  };
  cancelled(); let result, kind, action;
  if(mode==='role_validate')return prepareRoleValidation(mgr,cfg,input).then(request=>{
    if(!mgr.analysis.jobs?.runSettled)fail('Existing bounded data worker is required');
    return mgr.analysis.jobs.runSettled('vm-role-validation',request,mgr.scope?.getStore()?.signal);
  }).then(validation=>{cancelled();return saveVmProgression(artifacts,mode,'vm-role-validation','validate',validation);});
  if (mode === 'declare_contract') {
    exactData(input, ['contract']);
    result = { contract: validateFunctionContract(input.contract), authority: 'caller-declared-scope', businessAccepted: false };
    kind = 'vm-function-contract'; action = 'declare';
  } else if (mode === 'role_compare') {
    exactData(input, ['context_refs', 'contract_ref']); const c = contract(input.contract_ref);
    const contexts = loadComparedContexts(artifacts, input.context_refs, c.targetSha256, cancelled, budget);
    result = compareVmRoles(contexts, input.contract_ref, c.targetSha256); kind = 'vm-role-comparison'; action = 'compare';
  } else if (mode === 'program') {
    if(Object.hasOwn(input,'image_ref')) {
      exactData(input,['image_ref','contract_ref']);const c=contract(input.contract_ref),bytes=imageSnapshot(input.image_ref);
      result=deriveExecutableProgram(bytes,c);result.contractRef=input.contract_ref;
      // contractRef is a source link, not part of the independently regenerated executable semantics.
      cancelled();return saveVmProgression(artifacts,mode,'vm-executable-program','derive',result);
    }
    exactData(input, ['comparison_ref']); const c = comparison(input.comparison_ref);
    result = buildObservedVmCfg(c.contexts, input.comparison_ref, c.contract.targetSha256, c.result.contractRef, cancelled);
    kind = 'vm-observed-program'; action = 'derive';
  } else if (mode === 'function_check') {
    exactData(input,['program_ref',...['sample_inputs','recording_runs'].filter(k=>Object.hasOwn(input,k))]);exactReportRef(input.program_ref);
    if(input.sample_inputs!==undefined) {
      boundedDataArray(input.sample_inputs,64);
      if(input.sample_inputs.some(v=>typeof v!=='string'||!/^0x[0-9a-f]{1,16}$/.test(v)))fail('Hex sample inputs required');
    }
    if(input.recording_runs!==undefined)boundedDataArray(input.recording_runs,8);
    if(artifacts.metadata(input.program_ref.id).result.kind==='vm-executable-program') {
      const saved=read(input.program_ref,'vm-executable-program','derive'),c=contract(saved.contractRef);
      const {contractRef,...executable}=saved,fresh=deriveExecutableProgram(Buffer.from(saved.sourceImageHex,'hex'),c);
      if(!same(executable,fresh))fail('Executable image or semantic model changed');
      if(!mgr.analysis.jobs?.runSettled)fail('Existing bounded data worker is required');
      const files=['vm_bytecode.js','verifiers/vm_function_verify.js','verifiers/vm_function_oracle.js','verifiers/vm_recorded_function.js'];
      const implementation=()=>files.map(relativePath=>({relativePath,sha256:hashBytes(readStableFile(fileURLToPath(new URL(relativePath,import.meta.url)),1024*1024).data)}));
      const sourceFiles=implementation();
      const prepare=async()=>{
        const bindings=input.recording_runs??[];if(!Array.isArray(bindings)||bindings.length>8)fail('At most eight recording runs');
        let bytes=budget.bytes,instructions=0;const recordedRuns=[];
        for(const binding of bindings) {
          exactData(binding,['recordings']);const {windows}=await loadObservationWindows(mgr,cfg,{recordings:binding.recordings,target_sha256:c.targetSha256});
          bytes+=windows.reduce((n,w)=>n+w.data.length+(w.storeEventData?.length??0),0);instructions+=windows.reduce((n,w)=>n+w.summary.instructionCount,0);
          if(bytes>16*1024**2||instructions>50000)fail('Combined function evidence exceeds original default 16 MiB/50k budget');recordedRuns.push({windows});
        }
        return mgr.analysis.jobs.runSettled('vm-function-verify',{program:executable,contract:c,sampleInputs:input.sample_inputs ?? [],recordedRuns},mgr.scope?.getStore()?.signal);
      };
      return prepare().then(verification=>{
        cancelled();
        if(verification.schema!=='ig5-finite-function-verification-v1'||verification.targetSha256!==c.targetSha256||verification.businessAccepted!==false
          ||verification.universalProof!==false||verification.nativeTargetExecuted!==false)fail('Function verifier scope differs');
        if(!same(sourceFiles,implementation()))fail('Verifier implementation changed during verification');
        return saveVmProgression(artifacts,mode,'vm-function-assessment','assess',{...verification,programRef:input.program_ref,contractRef,
          verifierImplementation:{sourceFiles,digest:planningDigest(sourceFiles)},dataWorkerCleanupConfirmed:true});
      });
    }
    exactData(input, ['program_ref']); const saved = read(input.program_ref, 'vm-observed-program', 'derive'), c = comparison(saved.comparisonRef);
    const fresh = buildObservedVmCfg(c.contexts, saved.comparisonRef, c.contract.targetSha256, c.result.contractRef, cancelled);
    if (!same(saved, fresh)) fail('Program graph differs from audited source closure');
    result = assessFunctionContract(c.contract, fresh, input.program_ref); kind = 'vm-function-assessment'; action = 'assess';
  } else fail('Unsupported progression action');
  cancelled(); return saveVmProgression(artifacts,mode,kind,action,result);
}
