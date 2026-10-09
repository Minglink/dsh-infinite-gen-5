// Local, fixture-only UI preview. Uses the React already bundled with DSH; no CDN.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const asar = process.env.IG5_PREVIEW_ASAR || path.join(process.env.LOCALAPPDATA || '', 'Programs', 'DeepSeek Harness', 'resources', 'app.asar');
const fd = fs.openSync(asar, 'r');
const prefix = Buffer.alloc(16); fs.readSync(fd, prefix, 0, prefix.length, 0);
const packedHeader = Buffer.alloc(prefix.readUInt32LE(12)); fs.readSync(fd, packedHeader, 0, packedHeader.length, 16);
const header = JSON.parse(packedHeader.toString('utf8'));
const base = 8 + prefix.readUInt32LE(4);
const assetRoot = 'dsh/node_modules/@deepseek-ai/dsh-web-frontend/dist/assets';
function archiveNode(name) { let node = header; for (const part of name.split('/')) node = node.files[part]; return node; }
function archiveText(name) { const node = archiveNode(name); const bytes = Buffer.alloc(node.size); fs.readSync(fd, bytes, 0, bytes.length, base + Number(node.offset)); return bytes.toString('utf8'); }
const assetNames = Object.keys(archiveNode(assetRoot).files);
const bundleName = assetNames.find(name => /^index-.*\.js$/.test(name));
const bundle = archiveText(`${assetRoot}/${bundleName}`);
// The installed bundle's module table identifies its actual React/ReactDOM bindings.
const reactBinding = /react:([A-Za-z_$][\w$]*),/.exec(bundle)?.[1];
const domBinding = /"react-dom\/client":([A-Za-z_$][\w$]*),/.exec(bundle)?.[1];
const boot = bundle.indexOf('const fo=globalThis.dshDesktopBoot');
if (!reactBinding || !domBinding || boot < 0) throw new Error('Installed DSH frontend layout changed; cannot create an honest local preview from its React bundle.');
const runtime = bundle.slice(0, boot) + `\nexport { ${reactBinding} as React, ${domBinding} as ReactDOM };\n`;

const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>IG5 本地交互预览</title><style>
body{margin:0;background:#0d1420;color:#e2e8f0;font:14px system-ui}#preview-note{padding:12px 20px;border-bottom:1px solid #334155;background:#172033}#composer{display:block;width:calc(100% - 40px);margin:12px 20px;min-height:75px;color:#e2e8f0;background:#172033;border:1px solid #475569;border-radius:8px}#root{height:calc(100vh - 170px)}
:root{--dsw-alias-bg-layer-1:#141f30;--dsw-alias-bg-layer-2:#19273a;--dsw-alias-bg-layer-3:#0d1420;--dsw-alias-bg-module-platform:#0d1420;--dsw-alias-label-primary:#e2e8f0;--dsw-alias-label-secondary:#9caec6;--dsw-alias-label-tertiary:#6a7d99;--dsw-alias-border-l1:#23354d;--dsw-alias-border-l2:#334863;--dsw-alias-brand-primary:#69a6ff;--dsw-alias-state-error-primary:#f58c8c;--dsw-alias-state-success-primary:#67d4ab;--dsw-alias-state-warn-primary:#f6ce71}
</style></head><body><div id="preview-note">本地交互预览 · 使用内置 React 与模拟分析数据 · 不连接分析引擎，不执行写操作</div><textarea id="composer" aria-label="会话草稿预览" placeholder="结构体草稿插入后显示于此；不会发送"></textarea><div id="root"></div><script type="module">
import {React,ReactDOM} from '/runtime.js';
let plugin;
window.__ModuleLoader__={load(v){plugin=v.factory(name=>{if(name==='react')return React;throw Error(name)});}};
await import('/client.js');
const cfg={func:'decode_packet',start_ea:'0x140001000',total_blocks:6,total_edges:7,blocks:[
{id:0,start:'0x140001000',end:'0x140001010',insns:4,succs:[1,2],first:'push rbp',last:'jz 0x140001040'},
{id:1,start:'0x140001010',end:'0x140001030',insns:5,succs:[3],first:'mov eax, [rcx]',last:'jmp 0x140001060'},
{id:2,start:'0x140001040',end:'0x140001060',insns:3,succs:[3],first:'xor eax, eax',last:'jmp 0x140001060'},
{id:3,start:'0x140001060',end:'0x140001080',insns:5,succs:[3,4],first:'xor byte ptr [rdx], al',last:'jnz 0x140001060'},
{id:4,start:'0x140001080',end:'0x140001090',insns:2,succs:[5],first:'mov eax, 1',last:'jmp 0x140001090'},
{id:5,start:'0x140001090',end:'0x140001094',insns:2,succs:[],first:'pop rbp',last:'ret'}],edges:[{from:0,to:1},{from:0,to:2},{from:1,to:3},{from:2,to:3},{from:3,to:3},{from:3,to:4},{from:4,to:5}],mermaid:'flowchart TD\\n B0 --> B1\\n B0 --> B2\\n B1 --> B3\\n B2 --> B3\\n B3 --> B3\\n B3 --> B4\\n B4 --> B5'};
const target='C:\\\\fixtures\\\\sample.exe', declaration='struct Packet {\\n  unsigned int id;\\n  char payload[32];\\n};';
const variables=[{name:'key',type:'unsigned int',size:4,is_arg:true},{name:'buffer',type:'char *',size:8,is_arg:true},{name:'i',type:'int',size:4,is_arg:false}];
const code='int decode_packet(unsigned int key, char *buffer)\\n{\\n  for (int i = 0; i < 32; ++i)\\n    buffer[i] ^= key;\\n  return key != 0;\\n}';
const journal=Array.from({length:50},(_,i)=>({ts:'2026-10-09T12:'+String(i).padStart(2,'0')+':00Z',tool:i%3?'ig5_patch_bytes':'ig5_comment',args:{target,engine:i%2?'ghidra':'reverse',ea:'0x140001000'},detail:i%3?{before:'90 90',after:'CC 90',fileOffset:i}: {note:'人工审阅备注 <scr'+'ipt>仅显示文本</scr'+'ipt>'},isError:i===7}));
const config={host:{id:'win32-x64',supported:true,execution:'local-node-host'},runtimeSource:{ghidra:'bundled',x64dbg:'bundled'},engines:[{id:'reverse',available:true},{id:'ghidra',available:true,source:'bundled'},{id:'x64dbg',available:true,source:'bundled'}]};
window.__ig5Requests=[];window.__ig5Focuses=[];
window.fetch=async(url,options)=>{
 const u=new URL(url,location.href),q=u.searchParams,type=q.get('type'),engine=q.get('engine')||'reverse';let data;window.__ig5Requests.push({url:String(url),method:options&&options.method||'GET'});
 if(u.pathname==='/ig5-diag')return {ok:true,json:async()=>({ok:true})};
 if(u.pathname==='/ig5-jobs')return {ok:true,json:async()=>({config,now:Date.now(),jobs:[],sessions:['reverse','ghidra','x64dbg'].map((engine,i)=>({key:engine+':fixture',target,engine,projectId:'project_fixture',artifactId:'artifact_fixture_hash',dbRevision:i,alive:true,n_funcs:2,n_segs:5,n_imports:12,bits:64,cpu:'x86_64',file_type:'PE'}))})};
 if(u.pathname!=='/ig5-data'||(options&&options.method&&options.method!=='GET'))throw Error('preview refuses write requests');
 switch(type){
 case 'funcs': data={funcs:[{ea:'0x140001000',name:'decode_packet',size:148},{ea:'0x140002000',name:'check_header',size:40}],total:2};break;
 case 'decompile': data={ea:q.get('ea'),name:q.get('ea')==='0x140001000'?'decode_packet':'check_header',code:'/* '+engine+' fixture */\\n'+code};break;
 case 'cfg': data=cfg;break;
 case 'slice': data={variables,slice_variable:q.get('var'),slice_lines:q.get('var')?code.split('\\n').map((code,i)=>({line_no:i+1,code})).filter(x=>x.code.includes(q.get('var'))):[]};break;
 case 'calls':data={rows:[{ea:'0x140002000',name:'check_header'}]};break;
 case 'xrefs':data={rows:[{from:'0x140001000',func_ea:'0x140001000',func_name:'decode_packet'}]};break;
 case 'strings':data={strings:[{ea:'0x140003000',str:'packet-key',length:10}],total:1};break;
 case 'ir':data={kind:'ghidra-pcode',level:q.get('level'),operations:[{opcode:'INT_XOR',inputs:['key','buffer[i]'],output:'buffer[i]'}],truncated:false};break;
 case 'debug_state':data={state:'paused',runId:'run_fixture',stopSeq:4,regs:{rip:'0x7ff712341000',rax:'0x2a'},note:'模拟暂停快照；没有实际调试进程。'};break;
 case 'disasm':data={ea:q.get('ea'),rows:[{ea:q.get('ea'),bytes:'48 31 C0',text:'xor rax, rax',size:3},{ea:'0x140001003',bytes:'C3',text:'ret',size:1}],total:2};break;
 case 'struct':data=q.get('action')==='get'?{name:'Packet',size:36,decl:declaration,fields:[{offset:0,size:4,type:'unsigned int',name:'id'},{offset:4,size:32,type:'char[32]',name:'payload'}]}:{items:[{ordinal:1,name:'Packet',size:36,is_struct:true}]};break;
 case 'listing':data={rows:[]};break;
 case 'approvals':{const offset=Number(q.get('offset')||0),limit=Number(q.get('limit')||20),filtered=journal.filter(item=>item.args.engine===engine);data={rows:filtered.slice(offset,offset+limit),total:filtered.length,offset,limit};break;}
 default:data={rows:[]};
 }return {ok:true,status:200,json:async()=>({data})};
};
const inputActions={captureInsertion(){const t=document.querySelector('#composer');return {start:t.selectionStart,end:t.selectionEnd,value:t.value}},insertText(text,span){const t=document.querySelector('#composer');if(t.value!==span.value)return false;t.value=t.value.slice(0,span.start)+text+t.value.slice(span.end);return true},persistDraft(){}};
function PreviewApp(){const [viewRequest,setViewRequest]=React.useState(null);return React.createElement(plugin.__test.Workbench,{inputActions,useProjection:()=>({calls:8,errors:0}),viewRequest,openView(view,focus){window.__ig5Focuses.push({view,focus});setViewRequest({view,focus})},completeViewRequest(){setViewRequest(null)}})}
ReactDOM.createRoot(document.querySelector('#root')).render(React.createElement(PreviewApp));
window.__ig5PreviewReady=true;
</script></body></html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (req.method !== 'GET') { res.writeHead(405); res.end('Read-only preview'); return; }
  res.setHeader('cache-control', 'no-store');
  if (url.pathname === '/') { res.setHeader('content-type', 'text/html; charset=utf-8'); res.end(html); }
  else if (url.pathname === '/runtime.js') { res.setHeader('content-type', 'text/javascript; charset=utf-8'); res.end(runtime); }
  else if (url.pathname === '/client.js') { res.setHeader('content-type', 'text/javascript; charset=utf-8'); res.end(fs.readFileSync(path.join(root, 'client.js'))); }
  else if (/^\/vendor-[\w-]+\.js$/.test(url.pathname) && assetNames.includes(url.pathname.slice(1))) { res.setHeader('content-type', 'text/javascript; charset=utf-8'); res.end(archiveText(`${assetRoot}/${url.pathname.slice(1)}`)); }
  else { res.writeHead(404); res.end('Not found'); }
});
server.listen(Number(process.env.IG5_PREVIEW_PORT || 4185), '127.0.0.1', () => console.log(`IG5 fixture preview: http://127.0.0.1:${server.address().port}`));
process.on('SIGINT', () => server.close(() => { fs.closeSync(fd); process.exit(0); }));
