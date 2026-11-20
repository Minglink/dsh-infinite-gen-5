import path from 'node:path';
import { AnalysisArtifacts, hashBytes, readStableFile } from './analysis_artifacts.js';
import { loadObservationWindows } from './vm_observation_profile.js';
import { LiftJobs } from './lift_jobs.js';
import { runObservedDecode } from './observed_decode_jobs.js';
import { runProjection } from './projection_jobs.js';
import { mapVmFlowBytes } from './vm_flow_mapping.js';
import { classifyFetchFlow } from './vm_fetch_flow.js';
import { runFlowSemantics } from './flow_semantics_jobs.js';
const GPRS='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
export const flowProfileSchema={type:'object',properties:{
  roles_ref:{type:'object',properties:{id:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['id','sha256'],additionalProperties:false},
  target:{type:'string'},
  max_instructions:{type:'integer',minimum:1,maximum:100000},
  semantic_check:{type:'boolean'},
},required:['roles_ref','target'],additionalProperties:false};
function fields(value,allowed,required){
  if(!value||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value))
    ||Reflect.ownKeys(value).some(k=>!allowed.includes(k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(value,k),'value'))
    ||required.some(k=>!Object.hasOwn(value,k)))throw new Error('Invalid recorded flow parameters');
}
const ref = (artifacts,record) => ({id:record.id,path:path.join(artifacts.root,'records',record.id+'.json'),sha256:artifacts.metadata(record.id).result.recordSha256});
function readCore(artifacts,reply){
  const {data}=readStableFile(reply.reportPath,4*1024**2);
  if(hashBytes(data)!==reply.reportSha256)throw new Error('Flow projection report changed');
  const record=JSON.parse(data.toString('utf8'));
  if(record.kind!=='projection'||record.action!=='project')throw new Error('Flow projection report kind differs');
  return record.result;
}
export async function runVmFlowProfile(mgr,cfg,input){
  fields(input,['roles_ref','target','max_instructions','semantic_check'],['roles_ref','target']);fields(input.roles_ref,['id','sha256'],['id','sha256']);
  if(input.semantic_check!==undefined&&typeof input.semantic_check!=='boolean')throw new Error('Flow semantic_check must be Boolean');
  if(typeof input.roles_ref.id!=='string'||typeof input.roles_ref.sha256!=='string'||!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(input.roles_ref.id)||!/^[a-f0-9]{64}$/.test(input.roles_ref.sha256)
    ||typeof input.target!=='string'||!path.isAbsolute(input.target)||input.target.includes('\0'))throw new Error('Flow requires exact role report UUID/SHA and an explicit raw target path');
  const controller=new AbortController(),original=mgr.scope?.getStore()?.signal,cancel=()=>controller.abort();
  if(original?.aborted)cancel();else original?.addEventListener('abort',cancel,{once:true});
  const timer=setTimeout(cancel,Math.min(cfg.requestTimeoutMs||60000,60000)),signal=controller.signal;
  const check=()=>{mgr.checkCancelled();if(signal.aborted)throw Object.assign(new Error('Recorded flow cancelled or deadline exhausted'),{code:'ABORT_ERR'});};
  let stage='role-report';
  try{
    check();const artifacts=mgr.analysis.artifacts,metadata=artifacts.metadata(input.roles_ref.id).result;
    if(metadata.recordSha256!==input.roles_ref.sha256)throw new Error('Role report SHA-256 differs');
    const {data:roleBytes}=readStableFile(path.join(artifacts.directory('records'),input.roles_ref.id+'.json'),4*1024**2);
    if(hashBytes(roleBytes)!==input.roles_ref.sha256)throw new Error('Role report bytes changed');
    const record=JSON.parse(roleBytes.toString('utf8')),roles=record.result;
    if(record.id!==input.roles_ref.id||record.kind!=='vm-address-roles'||record.action!=='hypothesize'||roles?.schema!=='ig5-vm-address-roles-v1'
      ||roles.nativeTargetExecuted!==false||roles.vmModelProved!==false||roles.businessAccepted!==false
      ||!Array.isArray(roles.inputWindows)||!Array.isArray(roles.streamCandidates)||roles.streamCandidates.length>128)throw new Error('Flow role source identity or scope differs');
    stage='recording-validation';
    const originalInput={recordings:roles.inputWindows.map(w=>({id:w.reportId,sha256:w.reportSha256})),target_sha256:roles.targetSha256,
      ...(input.max_instructions===undefined?{}:{max_instructions:input.max_instructions})};
    const {windows}=await loadObservationWindows(mgr,cfg,originalInput);
    const seeds=roles.streamCandidates.flatMap(site=>{if(!Array.isArray(site.samples)||site.samples.length>8)throw new Error('Invalid recorded stream samples');
      return site.samples.map(sample=>({groupIndex:sample.groupIndex,recordingId:sample.recordingId,pc:site.pc,bytes:site.bytes}));}).sort((a,b)=>a.groupIndex-b.groupIndex);
    if(!seeds.length)throw new Error('No changing-address narrow-load candidate in the role report');
    const seed=seeds[0];stage='contiguous-window';
    const window=await mgr.analysis.selectVmFlow({targetSha256:roles.targetSha256,windows,maxInstructions:input.max_instructions,seed},signal);check();
    if(window?.schema!=='ig5-recorded-flow-window-v1'||window.allInputWindowsValidated!==true||window.groups?.length>128
      ||window.source?.targetSha256!==roles.targetSha256||window.source.identity.runtimeBase!==roles.identity.runtimeBase)throw new Error('Invalid recorded flow window');
    const windowRecord=artifacts.save({kind:'vm-flow-window',action:'select',sourceRole:input.roles_ref,result:window},{pretty:true,maxBytes:4*1024**2});
    mgr.lifter ||= new LiftJobs(cfg);stage='recorded-byte-decode';
    const sites=[...new Map(window.groups.flatMap(g=>g.instructions.map(i=>[i.pc+':'+i.bytes,{pc:i.pc,bytes:i.bytes}]))).values()];
    if(sites.length>128)throw new Error('Flow distinct-byte-site budget exceeded');
    const decoded=await runObservedDecode(mgr.lifter,sites,signal);check();
    const bySite=new Map(decoded.result.sites.map(row=>[row.pc+':'+row.bytes,row]));
    let terminal=-1;
    for(let i=0;i<window.groups.length;i++){
      const g=window.groups[i];if(!g.intermediateStateAvailable||g.instructions.length!==1)throw new Error('Flow has an unrecorded intermediate state');
      const d=bySite.get(g.instructions[0].pc+':'+g.instructions[0].bytes);
      if(d?.status!=='decoded')throw new Error('Flow contains a rejected instruction decode');
      if(d.controlFlow&&/^(jmp|call|ret)\b/.test(d.text)&&!d.operands.some(o=>o.kind==='immediate')){terminal=i;break;}
    }
    if(terminal<0)throw new Error('No indirect control within the original 128-site flow window');
    const groups=window.groups.slice(0,terminal+1);stage='same-file-mapping';
    const {data}=readStableFile(input.target,64*1024**2);if(hashBytes(data)!==roles.targetSha256)throw new Error('Flow raw target SHA-256 differs from the recording');
    const mapping=mapVmFlowBytes(data,window.source.identity.runtimeBase,groups);
    const snapshot=mgr.lifter.artifacts.put(data),snapshotPath=path.join(mgr.lifter.artifacts.root,'blobs',snapshot.sha256+'.bin');
    const args={target:snapshotPath,level:'project',projection_path:mapping.mapping.map(m=>m.preferred),projection_registers:GPRS,projection_decoder:'java',projection_mode:'opaque-status'};
    stage='full-state-projection';const fullReply=await runProjection(mgr.lifter,args,signal);check();
    stage='source-prefix-projection';const prefixReply=await runProjection(mgr.lifter,{...args,projection_path:args.projection_path.slice(0,1)},signal);check();
    stage='dependency-classification';const prefix=readCore(mgr.lifter.artifacts,prefixReply),full=readCore(mgr.lifter.artifacts,fullReply),dependency=classifyFetchFlow(prefix,full);
    const result={...dependency,seed,sourceRole:input.roles_ref,sourceWindow:ref(artifacts,windowRecord),mapping,
      originalTarget:{label:input.target,sha256:roles.targetSha256,bytes:data.length},immutableTargetSnapshot:snapshot,
      completeSelectedWindow:{groups:groups.length,firstGroup:groups[0].groupIndex,lastGroup:groups.at(-1).groupIndex},
      budgets:{distinctInstructionSites:sites.length,maximumDistinctSites:128,logicalInstructionsDecodedAndProjected:sites.length+groups.length+1,
        maximumLogicalInstructions:1024,requestDeadlineMs:Math.min(cfg.requestTimeoutMs||60000,60000)},
      evidence:{decoderReport:{path:decoded.reportPath,sha256:decoded.reportSha256},fullProjection:{path:fullReply.reportPath,sha256:fullReply.reportSha256},
        prefixProjection:{path:prefixReply.reportPath,sha256:prefixReply.reportSha256}}};
    if(input.semantic_check===true){
      stage='paired-state-semantic-assessment';
      if(dependency.indexedReads.length){
        const assessment=await runFlowSemantics(mgr.lifter,mgr.analysis,prefix,full,signal);check();
        result.semanticAssessment={reportPath:assessment.reportPath,reportSha256:assessment.reportSha256,
          assessmentComplete:assessment.result.assessmentComplete,hostWitnessReplayVerified:assessment.replay.hostWitnessReplayVerified,
          indexedReadsAssessed:assessment.result.indexedReadsAssessed??0,indexedReadsTotal:dependency.indexedReads.length,
          indexedReadCoverageComplete:assessment.result.indexedReadCoverageComplete??false,
          queries:assessment.result.queries.map(q=>({name:q.name,status:q.status})),
          reason:assessment.result.reason,statuses:assessment.result.assessments.map(a=>a.status)};
        result.semanticNonconstancyProved=assessment.replay.semanticNonconstancyProved;
        result.semanticNonconstancyScope=assessment.replay.semanticNonconstancyScope??'No semantic nonconstancy accepted; incomplete/unknown retained';
      }else{
        result.semanticAssessment={assessmentComplete:false,hostWitnessReplayVerified:false,status:'not-applicable-no-source-indexed-read'};
        result.semanticNonconstancyScope='No source-index-target witness accepted';
      }
      result.schema='ig5-fetch-control-assessed-v1';
      result.scope='Byte/pcode-bound selected-path ordinary IR; optional coherent source-byte mutation witnesses. No CPU/fault/code-coherence/native-reachability/VM/business proof or exclusive index mediation';
    }
    check();const saved=artifacts.save({kind:input.semantic_check===true?'vm-fetch-control-assessed':'vm-fetch-control-dependency',action:'analyze',result},{pretty:true,maxBytes:4*1024**2});
    return {flow:{schema:result.schema,status:result.status,nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,
      reportId:saved.id,reportSha256:ref(artifacts,saved).sha256,reportPath:ref(artifacts,saved).path,
      vmRoleProved:false,instructionSemanticsProved:false,semanticNonconstancyProved:result.semanticNonconstancyProved,sourceValuesReplacedByObservations:false,
      ...(input.semantic_check===true?{semanticAssessment:result.semanticAssessment,semanticNonconstancyScope:result.semanticNonconstancyScope}:{}),
      instructionCount:result.instructionCount,seed:result.seed,sourceLoad:result.sourceLoad,indexedReads:result.indexedReads,target:result.target,
      preserved:result.preserved,budgets:result.budgets,ordinaryProgramAmbiguity:result.ordinaryProgramAmbiguity,nextObligations:result.nextObligations,
      scope:result.scope}};
  }catch(error){error.message='Recorded flow stage='+stage+': '+error.message;throw error;}
  finally{clearTimeout(timer);original?.removeEventListener('abort',cancel);}
}
