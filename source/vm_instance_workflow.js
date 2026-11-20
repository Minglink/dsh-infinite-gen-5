import fs from 'node:fs';import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {hashBytes,readStableFile} from './analysis_artifacts.js';import {committedBytes,exactReportRef} from './evidence_adapters/vm_context.js';
import {exactData,boundedDataArray} from './vm_function_contract.js';import {planningDigest} from './planning_identity.js';import {validateVmInstance,compareVmInstances,VM_INSTANCE_VERSION} from './vm_instances.js';
const refSchema={type:'object',properties:{id:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['id','sha256'],additionalProperties:false};
export const instanceSchemas={instances:{type:'object',properties:{source_refs:{type:'array',minItems:1,maxItems:8,items:{type:'object',properties:{path:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['path','sha256'],additionalProperties:false}}},required:['source_refs'],additionalProperties:false},instance_check:{type:'object',properties:{comparison_ref:refSchema},required:['comparison_ref'],additionalProperties:false}};
const fail=message=>{throw Object.assign(new Error(message),{code:'INVALID_VM_PROGRAM'});};
const identity=()=>planningDigest(['vm_instances.js','vm_instance_workflow.js','analysis_jobs.js','analysis_worker.js'].map(n=>({name:n,sha256:hashBytes(readStableFile(fileURLToPath(new URL(n,import.meta.url)),1024**2).data)})));
const loadedIdentity=identity();
function summary(artifacts,mode,kind,result){const r=artifacts.save({kind,action:mode,result},{maxBytes:4*1024**2}),reportRef={id:r.id,sha256:artifacts.metadata(r.id).result.recordSha256};return {[mode]:{schema:result.schema,version:VM_INSTANCE_VERSION,reportRef,identities:result.identities,pairs:result.pairs,checks:result.checks?.map(({transcript,...c})=>c)??null,finiteModelOnly:true,nativeTargetExecuted:false,vmRoleProved:false,businessAccepted:false,assistEnabled:false}};}
export async function runVmInstances(mgr,mode,input){
 const artifacts=mgr.analysis.artifacts;mgr.checkCancelled();const implementation=loadedIdentity;if(identity()!==implementation)fail('Loaded instance implementation changed; reload required');
 if(mode==='instances'){
  exactData(input,['source_refs']);boundedDataArray(input.source_refs,8);if(!input.source_refs.length)fail('At least one source');const sources=[];
  for(const ref of input.source_refs){exactData(ref,['path','sha256']);if(typeof ref.path!=='string'||!path.isAbsolute(ref.path)||/^(\\\\|\/\/)/.test(ref.path)||ref.path.includes('\0')||ref.path.split(/[\\/]/).includes('..')||typeof ref.sha256!=='string'||!/^[a-f0-9]{64}$/.test(ref.sha256))fail('Explicit local SHA file required');for(let p=path.dirname(ref.path);;p=path.dirname(p)){const stat=fs.lstatSync(p);if(!stat.isDirectory()||stat.isSymbolicLink())fail('Linked source ancestor');if(p===path.dirname(p))break;}
   const bytes=readStableFile(ref.path,65536).data;if(hashBytes(bytes)!==ref.sha256)fail('Instance source SHA differs');const model=validateVmInstance(JSON.parse(bytes));sources.push({sha256:ref.sha256,blob:artifacts.put(bytes),model});
  }
  const models=sources.map(s=>s.model),comparison=compareVmInstances(models);mgr.checkCancelled();if(identity()!==implementation)fail('Implementation changed');return summary(artifacts,mode,'vm-instance-comparison',{...comparison,sources,implementation});
 }
 exactData(input,['comparison_ref']);exactReportRef(input.comparison_ref);const original=committedBytes(artifacts,input.comparison_ref,'vm-instance-comparison','instances').record.result;
 if(original.implementation!==implementation||original.version!==VM_INSTANCE_VERSION)fail('Instance semantics changed; derive a new comparison');boundedDataArray(original.sources,8);let bytes=0;
 const models=original.sources.map(s=>{const raw=artifacts.read(s.blob.ref,65536).data;bytes+=raw.length;if(bytes>512*1024||hashBytes(raw)!==s.sha256||hashBytes(raw)!==s.blob.sha256)fail('Committed source differs');const m=validateVmInstance(JSON.parse(raw));if(planningDigest(m)!==planningDigest(s.model))fail('Committed model differs');return m;});
 const {sources,implementation:oldImplementation,...saved}=original;if(planningDigest(compareVmInstances(models))!==planningDigest(saved))fail('Comparison differs from source');
 const result=await mgr.analysis.jobs.runSettled('vm-instance-check',{models},mgr.scope?.getStore()?.signal);mgr.checkCancelled();committedBytes(artifacts,input.comparison_ref,'vm-instance-comparison','instances');for(const s of original.sources){if(hashBytes(artifacts.read(s.blob.ref,65536).data)!==s.sha256)fail('Source changed during check');}if(identity()!==implementation)fail('Implementation changed during check');return summary(artifacts,mode,'vm-instance-check',{...result,comparisonRef:input.comparison_ref,implementation,dataWorkerCleanupConfirmed:true});
}
