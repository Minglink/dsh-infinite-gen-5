import path from 'node:path';
import { readStableFile,hashBytes } from './analysis_artifacts.js';
import { loadObservationWindows } from './vm_observation_profile.js';
import {flowPairSelection} from './flow_pair_sampling.js';
export const recurrenceProfileSchema={type:'object',properties:{
  flow_ref:{type:'object',properties:{id:{type:'string'},sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['id','sha256'],additionalProperties:false},
  max_instructions:{type:'integer',minimum:1,maximum:100000},
  sample_strategy:{type:'string',enum:['first4-last4','distinct-source-targets']},
  pair_offset:{type:'integer',minimum:0,maximum:255},
},required:['flow_ref'],additionalProperties:false};
const fail=m=>{throw new Error('Recorded recurrence: '+m);};
function fields(v,allowed,required){
  if(!v||typeof v!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(v))
    ||Reflect.ownKeys(v).some(k=>!allowed.includes(k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value'))||required.some(k=>!Object.hasOwn(v,k)))fail('invalid parameters');
}
function evidence(ref,kind,action){
  if(typeof ref?.path!=='string'||!path.isAbsolute(ref.path)||ref.path.includes('\0')||typeof ref.sha256!=='string'||!/^[a-f0-9]{64}$/.test(ref.sha256))fail('invalid linked report');
  const {data}=readStableFile(ref.path,4*1024**2);if(hashBytes(data)!==ref.sha256)fail('linked report SHA-256 differs');
  const r=JSON.parse(data.toString('utf8'));if(r.kind!==kind||r.action!==action)fail('linked report kind differs');return r.result;
}
export function validateFlowRecurrenceResult(result,windows,flow,selection=flowPairSelection()){
  const fields=['sourceByteEvents','completeDescriptorPaths','pathMismatches','coalescedSourceEvents','changedBytesAtSourcePc','completePathsExceedingSnapshotBudget','selectedCompletePaths','selectedOrdinaryConsistent','selectedOrdinaryUnverified'];
  const c=result?.counts,s=result?.sampling,items=result?.occurrences,n=flow.mapping.mapping.length;
  if(result?.schema!=='ig5-flow-recurrences-v1'||result.targetSha256!==flow.targetSha256||!c||!s||!Array.isArray(items)||items.length>8
    ||fields.some(k=>!Number.isSafeInteger(c[k])||Object.is(c[k],-0)||c[k]<0||c[k]>100000)
    ||s.allInputWindowsValidated!==true||s.allDescriptorPathsCompared!==true||s.maximumSelected!==8||s.maximumGroupsPerPath!==128||s.maximumSelectedLogicalGroups!==1024
    ||s.maximumCapturedBytesPerPath!==262144||s.maximumReplayMemoryVisitsPerPath!==4096||s.selectedLogicalGroups!==items.length*n
    ||s.selectionIsWholeCompletePathSet!==(c.completeDescriptorPaths===items.length)||c.selectedCompletePaths!==items.length
    ||c.selectedOrdinaryConsistent+c.selectedOrdinaryUnverified!==items.length||c.selectedOrdinaryConsistent!==items.filter(o=>o.status==='consistent-recorded-ordinary-state').length
    ||items.some(o=>!['consistent-recorded-ordinary-state','unverified'].includes(o.status)||o.groupCount!==n||!Number.isSafeInteger(o.startGroup)||o.startGroup<0||o.endGroup!==o.startGroup+n-1)
    ||new Set(items.map(o=>o.startGroup)).size!==items.length||c.completePathsExceedingSnapshotBudget>c.completeDescriptorPaths
    ||!Array.isArray(result.partialCapturedPaths)||result.partialCapturedPaths.length>1
    ||c.completeDescriptorPaths+c.pathMismatches+c.coalescedSourceEvents+result.partialCapturedPaths.length!==c.sourceByteEvents
    ||result.selectedOrdinaryStateConsistent!==(items.length>0&&c.selectedOrdinaryConsistent===items.length)
    ||JSON.stringify(result.descriptor)!==JSON.stringify(flow.mapping.mapping)
    ||!Array.isArray(result.source?.windows)||result.source.windows.length!==windows.length
    ||result.source.windows.some((w,i)=>w.reportId!==windows[i].source.reportId||w.reportSha256!==windows[i].source.reportSha256||w.traceSha256!==windows[i].summary.sha256)
    ||result.source.identity?.runtimeBase!==flow.mapping.runtimeBase||result.distinctRecordedRuns!==1
    ||['nativeTargetExecuted','changesExecutionAuthority','databaseModified','instructionSemanticsProved','vmRoleProved','businessAccepted','wholeFunctionCoverageProved','wholeVmRecovered','distinctVmInstancesProved','independentInputCoverageProved','entireRecordingOrdinaryStateVerified','intermediateGprSemanticsVerified','codeDataCoherenceProved','independentCpuStoreFootprintProved'].some(k=>result[k]!==false)
    ||result.moduleLoadEpoch!==null||result.memoryEpoch!==null)fail('worker result identity, counts or scope differs');
  const diverse=selection.strategy==='distinct-source-targets';
  if(s.strategy!==(diverse?'first-per-observed-source-target-pair-page':'first4-last4-complete-descriptor-paths'))fail('worker sampling strategy differs');
  if(!diverse){if(Object.hasOwn(result,'observedSourceTargetInventory')||Object.hasOwn(s,'pairOffset'))fail('default sampling acquired an unrequested inventory');return;}
  const inv=result.observedSourceTargetInventory,int=x=>Number.isSafeInteger(x)&&!Object.is(x,-0)&&x>=0&&x<=100000,hex=x=>typeof x==='string'&&/^0x[0-9a-f]{1,16}$/.test(x);
  if(s.pairOffset!==selection.pairOffset||inv?.schema!=='ig5-observed-source-target-inventory-v1'||inv.maximumTrackedPairs!==256
    ||!Array.isArray(inv.pairs)||inv.pairs.length>256||!int(inv.unindexedCompletePaths)||!int(inv.sourceReadUnobservedCompletePaths)
    ||inv.trackingComplete!==(inv.unindexedCompletePaths===0&&inv.sourceReadUnobservedCompletePaths===0)
    ||inv.countsAreLowerBounds!==(inv.unindexedCompletePaths>0||inv.sourceReadUnobservedCompletePaths>0)
    ||!Array.isArray(inv.unobservedExamples)||inv.unobservedExamples.length>8||inv.allCompletePathsAccountedFor!==true
    ||['inventoryIsOrdinaryStateReplay','sourceValuesAreOpcodeLabels','vmRoleProved','businessAccepted'].some(k=>inv[k]!==false)
    ||inv.pairs.some((p,i)=>!int(p.ordinal)||p.ordinal!==i||!hex(p.observedValue)||BigInt(p.observedValue)>=(1n<<BigInt(flow.sourceLoad.bytes*8))||!hex(p.target)||!int(p.completePaths)||p.completePaths<1
      ||!int(p.firstOccurrence?.startGroup)||p.firstOccurrence.endGroup!==p.firstOccurrence.startGroup+n-1
      ||i>0&&p.firstOccurrence.startGroup<=inv.pairs[i-1].firstOccurrence.startGroup
      ||!Number.isSafeInteger(p.firstOccurrence.pause)||!windows.some(w=>w.source.reportId===p.firstOccurrence.recordingId&&p.firstOccurrence.pause>=w.summary.startStopSeq&&p.firstOccurrence.pause<w.summary.endStopSeq)
      ||p.firstOccurrence.sourceRead?.status!=='observed'
      ||p.firstOccurrence.sourceRead.bytes!==flow.sourceLoad.bytes||p.firstOccurrence.sourceRead.value!==p.observedValue||!hex(p.firstOccurrence.sourceRead.address))
    ||new Set(inv.pairs.map(p=>p.observedValue+':'+p.target)).size!==inv.pairs.length
    ||inv.pairs.reduce((s,p)=>s+p.completePaths,0)+inv.unindexedCompletePaths+inv.sourceReadUnobservedCompletePaths!==c.completeDescriptorPaths
    ||inv.nextPairOffset!==(selection.pairOffset+8<inv.pairs.length?selection.pairOffset+8:null))fail('worker observed pair inventory differs');
  const expected=inv.pairs.slice(selection.pairOffset,selection.pairOffset+8);
  if(JSON.stringify(inv.selectedPairOrdinals)!==JSON.stringify(expected.map(p=>p.ordinal))||items.length!==expected.length
    ||items.some((o,i)=>o.observedPairOrdinal!==expected[i].ordinal||o.startGroup!==expected[i].firstOccurrence.startGroup||o.firstPause!==expected[i].firstOccurrence.pause
      ||o.firstRecordingId!==expected[i].firstOccurrence.recordingId
      ||o.status==='consistent-recorded-ordinary-state'&&(o.sourceValue!==expected[i].observedValue||o.target!==expected[i].target)))fail('worker diverse sample page differs');
}
export async function runVmRecurrenceProfile(mgr,cfg,input){
  fields(input,['flow_ref','max_instructions','sample_strategy','pair_offset'],['flow_ref']);fields(input.flow_ref,['id','sha256'],['id','sha256']);
  const selection=flowPairSelection(input.sample_strategy,input.pair_offset);
  if(typeof input.flow_ref.id!=='string'||!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(input.flow_ref.id)
    ||typeof input.flow_ref.sha256!=='string'||!/^[a-f0-9]{64}$/.test(input.flow_ref.sha256))fail('exact flow report UUID/SHA required');
  const controller=new AbortController(),original=mgr.scope?.getStore()?.signal,cancel=()=>controller.abort();
  if(original?.aborted)cancel();else original?.addEventListener('abort',cancel,{once:true});
  const timer=setTimeout(cancel,Math.min(cfg.requestTimeoutMs||60000,60000)),check=()=>{mgr.checkCancelled();if(controller.signal.aborted)fail('cancelled or deadline exhausted');};
  try{
    check();const artifacts=mgr.analysis.artifacts,metadata=artifacts.metadata(input.flow_ref.id).result;
    if(metadata.recordSha256!==input.flow_ref.sha256)fail('flow report SHA-256 differs');
    const {data}=readStableFile(path.join(artifacts.directory('records'),input.flow_ref.id+'.json'),4*1024**2);
    if(hashBytes(data)!==input.flow_ref.sha256)fail('flow report bytes changed');
    const record=JSON.parse(data.toString('utf8')),flow=record.result;
    const pairs={'vm-fetch-control-dependency':'ig5-fetch-control-dependency-v1','vm-fetch-control-assessed':'ig5-fetch-control-assessed-v1'};
    if(record.id!==input.flow_ref.id||record.action!=='analyze'||!Object.hasOwn(pairs,record.kind)||flow?.schema!==pairs[record.kind]
      ||['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified','vmRoleProved','instructionSemanticsProved','sourceValuesReplacedByObservations','stateReportsComposed'].some(k=>flow[k]!==false))fail('flow identity or scope differs');
    const window=evidence(flow.sourceWindow,'vm-flow-window','select'),full=evidence(flow.evidence?.fullProjection,'projection','project'),prefix=evidence(flow.evidence?.prefixProjection,'projection','project');
    if(window.source?.targetSha256!==flow.targetSha256||!Array.isArray(window.source.windows)||window.source.identity?.runtimeBase!==flow.mapping?.runtimeBase)fail('original window identity differs');
    const originalInput={recordings:window.source.windows.map(w=>({id:w.reportId,sha256:w.reportSha256})),target_sha256:flow.targetSha256,
      ...(input.max_instructions===undefined?{}:{max_instructions:input.max_instructions})};
    const {windows}=await loadObservationWindows(mgr,cfg,originalInput);check();
    const result=await mgr.analysis.recurVmFlow({targetSha256:flow.targetSha256,windows,maxInstructions:input.max_instructions,flow,full,prefix,
      sampleStrategy:selection.strategy,...(selection.strategy==='distinct-source-targets'?{pairOffset:selection.pairOffset}:{})},controller.signal);check();
    validateFlowRecurrenceResult(result,windows,flow,selection);
    result.sourceFlow={...input.flow_ref,path:path.join(artifacts.directory('records'),input.flow_ref.id+'.json')};
    result.sourceProjections={full:flow.evidence.fullProjection,prefix:flow.evidence.prefixProjection};
    const saved=artifacts.save({kind:'vm-flow-recurrences',action:'validate',result},{pretty:true,maxBytes:4*1024**2});
    return{recurrences:{schema:result.schema,nativeTargetExecuted:false,businessAccepted:false,vmRoleProved:false,
      reportId:saved.id,reportSha256:artifacts.metadata(saved.id).result.recordSha256,reportPath:path.join(artifacts.root,'records',saved.id+'.json'),
      targetSha256:result.targetSha256,counts:result.counts,sampling:result.sampling,
      selectedOrdinaryStateConsistent:result.selectedOrdinaryStateConsistent,sourceAddressInputUpdates:result.sourceAddressInputUpdates,
      indexedAddressNonSourceInputs:result.indexedAddressNonSourceInputs,selectedSourceTargetPairs:result.selectedSourceTargetPairs,partialCapturedPaths:result.partialCapturedPaths,
      ...(result.observedSourceTargetInventory?{observedSourceTargetInventory:{...result.observedSourceTargetInventory,
        pairs:result.observedSourceTargetInventory.pairs.slice(selection.pairOffset,selection.pairOffset+8),pairsTotal:result.observedSourceTargetInventory.pairs.length,
        pairsPreviewComplete:selection.pairOffset===0&&result.observedSourceTargetInventory.pairs.length<=8,previewPairOffset:selection.pairOffset,fullInventoryInReport:true}}:{}),
      changesExecutionAuthority:false,instructionSemanticsProved:false,wholeFunctionCoverageProved:false,
      intermediateGprSemanticsVerified:false,entireRecordingOrdinaryStateVerified:false,wholeVmRecovered:false,
      distinctRecordedRuns:1,distinctVmInstancesProved:false,independentInputCoverageProved:false,moduleLoadEpoch:null,memoryEpoch:null,codeDataCoherenceProved:false,
      ordinaryProgramAmbiguity:result.ordinaryProgramAmbiguity,nextObligations:result.nextObligations,scope:result.scope}};
  }finally{clearTimeout(timer);original?.removeEventListener('abort',cancel);}
}
