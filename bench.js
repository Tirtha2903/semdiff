/* Benchmark: real C functions compiled by your gcc. Measures false alarms (same source, different -O) and caught bugs (injected mutations). */
const CORPUS=[
 {n:'clamp',src:'int clamp(int x,int lo,int hi){ if(x<lo) return lo; if(x>hi) return hi; return x; }',mut:[['return lo','return lo+1'],['x>hi','x>hi+1']]},
 {n:'absdiff',src:'int absdiff(int a,int b){ return a>b ? a-b : b-a; }',mut:[['b-a','a-b'],['a-b :','a-b+1 :']]},
 {n:'sat_add',src:'int sat_add(int a,int b){ long s=(long)a+b; if(s>2147483647L) return 2147483647; if(s<-2147483648L) return -2147483647-1; return (int)s; }',mut:[['return 2147483647','return 2147483646'],['return (int)s','return (int)s+1']]},
 {n:'sum_to',src:'int sum_to(int n){ int s=0; for(int i=1;i<=n;i++) s+=i; return s; }',mut:[['i<=n','i<n'],['s+=i','s+=i*2']]},
 {n:'gcd',src:'int gcd(int a,int b){ while(b){ int t=a%b; a=b; b=t; } return a; }',mut:[['t=a%b','t=a/b'],['return a','return b']]},
 {n:'is_pow2',src:'int is_pow2(unsigned x){ return x && !(x&(x-1)); }',mut:[['x&(x-1)','x&(x+1)'],['x &&','1 &&']]},
 {n:'checked_copy',src:'int checked_copy(char*d,const char*s,unsigned n){ if(n>256) return -1; memcpy(d,s,n); return 0; }',mut:[['n>256','n>512'],['return -1','return 0']]},
 {n:'max3',src:'int max3(int a,int b,int c){ int m=a>b?a:b; return m>c?m:c; }',mut:[['m>c?m:c','m>c?c:m'],['a>b?a:b','a>b?b:a']]},
 {n:'checksum',src:'unsigned checksum(const unsigned char*p,unsigned n){ unsigned s=0; for(unsigned i=0;i<n;i++) s=s*31+p[i]; return s; }',mut:[['s*31','s*33'],['i<n','i+1<n']]},
 {n:'sign',src:'int sign(int x){ return (x>0)-(x<0); }',mut:[['(x>0)-(x<0)','(x>=0)-(x<0)'],['x<0','x<1']]},
 {n:'popcount8',src:'int popcount8(unsigned x){ int c=0; for(int i=0;i<8;i++) c+=(x>>i)&1; return c; }',mut:[['i<8','i<7'],['(x>>i)&1','(x>>i)&3']]},
 {n:'sumsq',t:'sumsq',src:'static int sq(int v){ return v*v; }\nint sumsq(int a,int b){ return sq(a)+sq(b); }',mut:[['v*v','v*v+1'],['sq(b)','sq(a)']]}];
const BCACHE={};
async function build(post,src,opt){const k=opt+'|'+src;return BCACHE[k]||(BCACHE[k]=await post(src,opt))}
async function evalCase(post,srcA,oa,srcB,ob,target){
 try{const a=await build(post,srcA,oa),b=await build(post,srcB,ob);Object.assign(RETB,a.ret,b.ret);
  const r=analyze(a.asm,b.asm),p=r.pairs.find(p=>p.a.name===target&&p.b.name===target);
  const sk=r.skipped.find(s=>s.f.name===target);
  if(sk)return{st:'skip',why:sk.why};
  if(!p)return{st:'nomatch',matched:false};
  return{st:p.same?'same':'changed',label:p.label,naive:p.naive,sem:p.sem,matched:true}}
 catch(e){return{st:'error',why:String(e.message||e).slice(0,120)}}}
async function runBench(post,progress){const rows=[];
 for(const c of CORPUS){const t=c.t||c.n,row={n:c.n,cells:[]};
  const plan=[['O0 vs O2',c.src,'0',c.src,'2','ref'],['O0 vs O3',c.src,'0',c.src,'3','ref']];
  c.mut.forEach((m,i)=>{if(!c.src.includes(m[0]))throw new Error('bad mutation in '+c.n);plan.push(['bug '+(i+1),c.src,'0',c.src.replace(m[0],m[1]),'2','mut'])});
  for(const[name,sa,oa,sb,ob,kind]of plan){const r=await evalCase(post,sa,oa,sb,ob,t);r.kind=kind;r.name=name;row.cells.push(r);if(progress)progress(row,rows)}
  rows.push(row)}
 return summarize(rows)}
function summarize(rows){const all=rows.flatMap(r=>r.cells),refs=all.filter(c=>c.kind==='ref'),muts=all.filter(c=>c.kind==='mut');
 const used=a=>a.filter(c=>c.st==='same'||c.st==='changed'),sk=a=>a.filter(c=>c.st!=='same'&&c.st!=='changed');
 const refOk=used(refs).filter(c=>c.st==='same').length,mutOk=used(muts).filter(c=>c.st==='changed').length;
 const noise=used(refs).length?Math.round(used(refs).reduce((s,c)=>s+c.naive,0)/used(refs).length):0;
 const matched=all.filter(c=>c.matched).length;
 return{rows,refTotal:used(refs).length,refSame:refOk,mutTotal:used(muts).length,mutCaught:mutOk,skipped:sk(all).length,textNoise:noise,matched,cases:all.length}}
if(typeof window!=='undefined'&&document.getElementById('go')){
 const $=id=>document.getElementById(id);let LAST=null;
 const post=(source,opt)=>fetch('/api/compile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source,opt})}).then(async r=>{const j=await r.json();if(!r.ok)throw new Error(j.error);return j});
 const cell=c=>c.st==='same'?'<td class="bt ok">same</td>':c.st==='changed'?'<td class="bt '+(c.kind==='mut'?'ok':'bad')+'">'+(c.kind==='mut'?'caught':'false alarm')+'</td>':'<td class="bt sk" title="'+esc(c.why||c.st)+'">skipped</td>';
 const draw=(rows,done)=>{$('tb').innerHTML=rows.map(r=>'<tr><td><b>'+esc(r.n)+'</b></td>'+r.cells.map(cell).join('')+'</tr>').join('')};
 $('go').onclick=async()=>{$('go').disabled=true;$('prog').textContent='Compiling and analyzing...';
  try{const S2=await runBench(post,(row,rows)=>{draw(rows.concat([row]));$('prog').textContent='Running '+row.n+'...'});LAST=S2;
   $('prog').textContent='Done.';$('sumb').innerHTML=
   `<div><b>${S2.refSame}/${S2.refTotal}</b><span>same-source builds judged same behavior</span></div><div><b>${S2.mutCaught}/${S2.mutTotal}</b><span>injected bugs caught</span></div><div><b>${S2.textNoise}%</b><span>of lines a plain text diff flags on average</span></div><div><b>${S2.refTotal-S2.refSame}</b><span>SemDiff false alarms</span></div><div><b>${S2.skipped}</b><span>cases skipped (unsupported instructions)</span></div>`;
   $('dl').hidden=false}catch(e){$('prog').textContent='Failed: '+e.message+'. Is server.py running (python3 server.py)?'}
  $('go').disabled=false};
 $('dl').onclick=()=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(LAST,(k,v)=>typeof v==='bigint'?String(v):v,2)],{type:'application/json'}));a.download='semdiff-benchmark.json';a.click()}}
