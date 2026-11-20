import path from 'node:path';
import {readStableFile,hashBytes} from './analysis_artifacts.js';
import {loadObservationWindows} from './vm_observation_profile.js';
import {validateFlowRecurrenceResult} from './vm_recurrence_profile.js';
import {flowPairSelection} from './flow_pair_sampling.js';
import {mapVmFlowBytes} from './vm_flow_mapping.js';
import {LiftJobs} from './lift_jobs.js';
import {runObservedDecode} from './observed_decode_jobs.js';
import {runProjection,runRecordedProjection} from './projection_jobs.js';
import {makeRecordedCoordinateInput,needsRecordedRuntimeCoordinates} from './recorded_projection_coordinates.js';
export const handlerProfileSchema={type:'object',properties:{
  recurrences_ref:{type:'object',properties:{id:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['id','sha256'],additionalProperties:false},
  target:{type:'string'},
  max_instructions:{type:'integer',minimum:1,maximum:100000},
},required:['recurrences_ref','target'],additionalProperties:false};
const GPRS='rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const fail=m=>{throw Error('Recorded handlers: '+m);},same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function fields(v,allowed,required){
  if(!v||typeof v!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(v))
    ||Reflect.ownKeys(v).some(k=>!allowed.includes(k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value'))||required.some(k=>!Object.hasOwn(v,k)))fail('invalid parameters');
}
const recordRef=(s,r)=>({id:r.id,path:path.join(s.root,'records',r.id+'.json'),sha256:s.metadata(r.id).result.recordSha256});
function linked(ref,kind,action){
  if(typeof ref?.path!=='string'||!path.isAbsolute(ref.path)||!/^[a-f0-9]{64}$/.test(ref.sha256||''))fail('invalid linked report');
  const{data}=readStableFile(ref.path,4*1024**2);if(hashBytes(data)!==ref.sha256)fail('linked report SHA-256 differs');
  const r=JSON.parse(data);if(r.kind!==kind||r.action!==action)fail('linked report kind differs');return r.result;
}
function committed(store,ref,kind,action){
  if(typeof ref?.id!=='string'||!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(ref.id)||!/^[a-f0-9]{64}$/.test(ref.sha256||''))fail('exact committed UUID/SHA required');
  if(store.metadata(ref.id).result.recordSha256!==ref.sha256)fail('committed report SHA-256 differs');
  const file=path.join(store.directory('records'),ref.id+'.json'),{data}=readStableFile(file,4*1024**2);
  if(hashBytes(data)!==ref.sha256)fail('committed report bytes changed');const r=JSON.parse(data);
  if(r.id!==ref.id||r.kind!==kind||r.action!==action)fail('committed report identity differs');return{result:r.result,path:file};
}
export function validateHandlerAssessment(r,core,body){
  const good=r?.gprs?.filter(g=>g.status==='matched').length,known=r?.orderedStores?.filter(s=>s.valueStatus==='replayed').length;
  const roots=[...Object.values(core.registers),core.initialMemory,core.currentMemory,...core.stores.flatMap(s=>[s.address,s.value,s.beforeMemory,s.afterMemory]),
    ...(core.control.kind==='conditional'?[core.control.condition,core.control.taken,core.control.fallthrough]:[core.control.target])];
  const uint=x=>typeof x==='string'&&/^0x[0-9a-f]{1,16}$/.test(x),count=(x,max=65536)=>Number.isSafeInteger(x)&&!Object.is(x,-0)&&x>=0&&x<=max;
  if(r?.schema!=='ig5-recorded-handler-assessment-v1'||!['consistent-recorded-ordinary-state','partially-consistent-unknown-preserved'].includes(r.status)
    ||!Array.isArray(r.gprs)||r.gprs.length!==16||!same(r.gprs.map(g=>g.name),GPRS)||!Array.isArray(r.orderedStores)||r.orderedStores.length!==core.stores.length
    ||r.gprs.some(g=>g.node!==core.registers[g.name]||g.observed!==body.groups.at(-1).after.gprs[g.name]
      ||!['matched','unknown-preserved'].includes(g.status)||g.status==='matched'&&(!uint(g.computed)||BigInt(g.computed)!==BigInt(g.observed))
      ||g.status==='unknown-preserved'&&(g.computed!==null||!g.opaqueInputs?.length))
    ||r.orderedStores.some((s,i)=>s.instructionIndex!==core.stores[i].instructionIndex||s.pcodeIndex!==core.stores[i].pcodeIndex||s.bytes!==core.stores[i].size
      ||!uint(s.address)||!['replayed','unknown-preserved'].includes(s.valueStatus)||s.valueStatus==='replayed'&&!uint(s.value)
      ||s.valueStatus==='unknown-preserved'&&(s.value!==null||!s.opaqueInputs?.length))
    ||r.all16FinalGprsMatched!==(good===16)||r.allOrderedDecodedStoresReplayed!==(known===core.stores.length)
    ||r.terminalTargetMatched!==true||r.control?.target!==body.groups.at(-1).after.rip||r.control.unselectedContinuationAnalyzed!==false
    ||r.allOrdinaryStateRootsPreserved!==true||!same(r.ordinaryRootNodes,roots)||r.fullOriginalProjectionRequired!==true||!same(r.opaqueInputs,core.nondeterministicInputs)
    ||!count(r.memoryByteVisits,4096)||!count(r.postStoreKnownReadBytesNotSeededAsInitial)||!count(r.postStoreUnknownReadBytesNotSeededAsInitial)
    ||!Array.isArray(r.finiteInitialMemoryBytes)||r.finiteInitialMemoryBytes.length>4096
    ||r.status==='consistent-recorded-ordinary-state'&&(good!==16||known!==core.stores.length||r.postStoreUnknownReadBytesNotSeededAsInitial!==0)
    ||['opaqueOutputsCoordinated','unknownValuesFilledFromObservations','projectedFlagsModeledOrCompared','intermediateGprSemanticsVerified','independentCpuStoreFootprintProved',
      'nativeTargetExecuted','instructionSemanticsProved','nativeReachabilityProved','vmRoleProved','businessAccepted','wholeBinaryVerified'].some(k=>r[k]!==false))fail('worker assessment identity, completeness or scope differs');
}
export async function runVmHandlerProfile(mgr,cfg,input){
  fields(input,['recurrences_ref','target','max_instructions'],['recurrences_ref','target']);fields(input.recurrences_ref,['id','sha256'],['id','sha256']);
  if(typeof input.target!=='string'||!path.isAbsolute(input.target)||input.target.includes('\0'))fail('explicit raw target path required');
  const controller=new AbortController(),original=mgr.scope?.getStore()?.signal,cancel=()=>controller.abort();
  if(original?.aborted)cancel();else original?.addEventListener('abort',cancel,{once:true});
  const timer=setTimeout(cancel,Math.min(cfg.requestTimeoutMs||60000,60000)),signal=controller.signal;
  const check=()=>{mgr.checkCancelled();if(signal.aborted)fail('cancelled or deadline exhausted');};let stage='recurrence-source';
  try{
    check();const store=mgr.analysis.artifacts,{result:old}=committed(store,input.recurrences_ref,'vm-flow-recurrences','validate');
    if(old?.schema!=='ig5-flow-recurrences-v1')fail('recurrence schema differs');
    const sf=old.sourceFlow;
    fields(sf,['id','sha256','path'],['id','sha256','path']);
    if(typeof sf.id!=='string'||!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(sf.id)||!/^[a-f0-9]{64}$/.test(sf.sha256||''))fail('invalid original flow reference');
    const flowKind=(()=>{
      const{data}=readStableFile(path.join(store.directory('records'),sf.id+'.json'),4*1024**2);
      if(hashBytes(data)!==sf.sha256)fail('flow source SHA-256 differs');return JSON.parse(data).kind;
    })();
    if(!['vm-fetch-control-dependency','vm-fetch-control-assessed'].includes(flowKind))fail('flow source kind differs');
    const{result:flow}=committed(store,sf,flowKind,'analyze');
    const window=linked(flow.sourceWindow,'vm-flow-window','select'),full=linked(flow.evidence.fullProjection,'projection','project'),prefix=linked(flow.evidence.prefixProjection,'projection','project');
    stage='whole-recording-revalidation';
    const{windows}=await loadObservationWindows(mgr,cfg,{recordings:window.source.windows.map(w=>({id:w.reportId,sha256:w.reportSha256})),target_sha256:flow.targetSha256,
      ...(input.max_instructions===undefined?{}:{max_instructions:input.max_instructions})});check();
    const diverse=old.sampling?.strategy==='first-per-observed-source-target-pair-page',selection=flowPairSelection(diverse?'distinct-source-targets':'first4-last4',diverse?old.sampling.pairOffset:undefined);
    const request={targetSha256:flow.targetSha256,windows,maxInstructions:input.max_instructions,flow,full,prefix,sampleStrategy:selection.strategy,...(diverse?{pairOffset:selection.pairOffset}:{})};
    const recurrence=await mgr.analysis.recurVmFlow(request,signal);validateFlowRecurrenceResult(recurrence,windows,flow,selection);check();
    const{sourceFlow,sourceProjections,...previous}=old;if(!same(recurrence,previous))fail('recomputed original recurrence differs');
    stage='body-boundary-selection';const selected=await mgr.analysis.selectVmHandlers({...request,recurrence},signal);check();
    if(selected?.schema!=='ig5-recorded-handler-windows-v1'||selected.allInputWindowsValidated!==true||selected.targetSha256!==flow.targetSha256
      ||selected.bodies?.length!==recurrence.occurrences.length||selected.bodies.length>8||selected.source.identity.runtimeBase!==flow.mapping.runtimeBase
      ||selected.bodies.some((b,i)=>b.sourceOccurrence!==recurrence.occurrences[i].startGroup||b.groups.length>128||b.capturedBytes>262144))fail('worker selection differs');
    const selectionRecord=store.save({kind:'vm-handler-windows',action:'select',sourceRecurrence:input.recurrences_ref,result:selected},{pretty:true,maxBytes:4*1024**2});
    stage='same-file-mapping';const{data}=readStableFile(input.target,64*1024**2);if(hashBytes(data)!==flow.targetSha256)fail('raw target SHA-256 differs');
    const rows=[],sites=new Map();let logical=0;
    for(const b of selected.bodies){
      const row={sourceOccurrence:b.sourceOccurrence,sourceValue:b.sourceValue,observedEntry:b.observedEntry,groupCount:b.groupCount,
        nextFetchGroup:b.nextFetchGroup,completeNextBoundary:b.completeNextBoundary,status:'unverified'};rows.push(row);
      if(b.selectionStatus!=='observed-boundary'||!b.completeNextBoundary){row.reason=b.reason??'incomplete observed body';continue;}
      try{
        row.mapping=mapVmFlowBytes(data,flow.mapping.runtimeBase,b.groups);
        const added=new Map([...sites,...b.groups.map(g=>{const i=g.instructions[0];return[i.pc+':'+i.bytes,{pc:i.pc,bytes:i.bytes}];})]);
        if(added.size>128||logical+b.groups.length+added.size>1024)throw Error('shared 128-site/1024 logical instruction budget');
        for(const[k,v]of added)sites.set(k,v);logical+=b.groups.length;row.status='selected';
      }catch(e){row.reason=String(e.message).slice(0,512);}
    }
    let decoderReport=null,snapshot=null;
    if(sites.size){
      mgr.lifter||=new LiftJobs(cfg);snapshot=mgr.lifter.artifacts.put(data);
      const target=path.join(mgr.lifter.artifacts.root,'blobs',snapshot.sha256+'.bin');stage='body-byte-decode';
      const decoded=await runObservedDecode(mgr.lifter,[...sites.values()],signal);check();decoderReport={path:decoded.reportPath,sha256:decoded.reportSha256};
      const bySite=new Map(decoded.result.sites.map(s=>[s.pc+':'+s.bytes,s]));
      for(const row of rows){
        if(row.status!=='selected')continue;check();const body=selected.bodies.find(b=>b.sourceOccurrence===row.sourceOccurrence);
        try{
          const bodyDecode=body.groups.map(g=>bySite.get(g.instructions[0].pc+':'+g.instructions[0].bytes)),recorded=needsRecordedRuntimeCoordinates(bodyDecode);
          const args={target,level:'project',projection_decoder:'java',projection_mode:'opaque-status',projection_registers:GPRS,projection_path:row.mapping.mapping.map(m=>m.preferred)};
          stage='body-projection';const reply=recorded?await runRecordedProjection(mgr.lifter,args,makeRecordedCoordinateInput({targetSha256:flow.targetSha256,mapping:row.mapping,body,source:selected.source,
            recurrencesRef:input.recurrences_ref,selectionRef:recordRef(store,selectionRecord)}),signal):await runProjection(mgr.lifter,args,signal);check();
          if(recorded)row.projectionCoordinates='recorded-runtime-v1';
          row.projection={path:reply.reportPath,sha256:reply.reportSha256};const core=linked(row.projection,'projection',recorded?'project-recorded':'project');
          stage='ordinary-body-assessment';row.assessment=await mgr.analysis.assessVmHandler({core,groups:body.groups,mapping:row.mapping,
            decoded:bodyDecode},signal);check();
          validateHandlerAssessment(row.assessment,core,body);row.status=row.assessment.status;
        }catch(e){row.status='unverified';row.reason=String(e.message).slice(0,512);if(e.analysisFailure)row.analysisFailure=e.analysisFailure;}
      }
    }
    check();const counts={selectedBodies:rows.length,completeBoundaries:rows.filter(r=>r.completeNextBoundary).length,
      projectedBodies:rows.filter(r=>r.projection).length,ordinaryConsistent:rows.filter(r=>r.status==='consistent-recorded-ordinary-state').length,
      partialUnknownPreserved:rows.filter(r=>r.status==='partially-consistent-unknown-preserved').length,unverified:rows.filter(r=>r.status==='unverified').length};
    const result={schema:'ig5-recorded-handlers-v1',targetSha256:flow.targetSha256,sourceRecurrence:{...input.recurrences_ref},sourceFlow:old.sourceFlow,
      sourceSelection:recordRef(store,selectionRecord),decoderReport,originalTarget:{label:input.target,sha256:flow.targetSha256},immutableTargetSnapshot:snapshot,
      counts,bodies:rows,budgets:{distinctSites:sites.size,logicalInstructions:sites.size+logical,maximumDistinctSites:128,maximumLogicalInstructions:1024,requestDeadlineMs:60000},
      nativeTargetExecuted:false,databaseModified:false,changesExecutionAuthority:false,instructionSemanticsProved:false,vmRoleProved:false,
      wholeVmRecovered:false,businessAccepted:false,wholeBinaryVerified:false,independentInputCoverageProved:false,moduleLoadEpoch:null,memoryEpoch:null,
      nextObligations:['Recover role/context/ISA from complete ordinary body effects without manual opcode labels','Resolve unknown saved-status consumers without filling observed values',
        'Separate initialization/fixup/SMC epochs from concrete business execution','Validate complete functions across independent inputs and alternate paths'],
      scope:'Automatically selected observed dispatch-target bodies through the next exact fetch head; full ordinary GPR/RAM/ordered STORE projection, finite recorded consistency and explicit unknowns. No CPU, complete footprint, VM-role, version or business proof'};
    const saved=store.save({kind:'vm-recorded-handlers',action:'assess',result},{pretty:true,maxBytes:4*1024**2});
    return{handlers:{schema:result.schema,nativeTargetExecuted:false,businessAccepted:false,vmRoleProved:false,
      reportId:saved.id,reportSha256:recordRef(store,saved).sha256,reportPath:recordRef(store,saved).path,
      targetSha256:result.targetSha256,counts,bodies:rows.map(r=>({sourceOccurrence:r.sourceOccurrence,sourceValue:r.sourceValue,observedEntry:r.observedEntry,
      groupCount:r.groupCount,status:r.status,reason:r.reason,projection:r.projection,matchedFinalGprs:r.assessment?.gprs.filter(g=>g.status==='matched').length,
      projectionCoordinates:r.projectionCoordinates,
      orderedStores:r.assessment?.orderedStores.length,unknownStores:r.assessment?.orderedStores.filter(s=>s.valueStatus==='unknown-preserved').length,
      control:r.assessment?.control,unknownValuesFilledFromObservations:false})),budgets:result.budgets,
      instructionSemanticsProved:false,wholeVmRecovered:false,independentInputCoverageProved:false,
      nextObligations:result.nextObligations,scope:result.scope}};
  }catch(e){e.message='Recorded handlers stage='+stage+': '+e.message;throw e;}
  finally{clearTimeout(timer);original?.removeEventListener('abort',cancel);}
}
