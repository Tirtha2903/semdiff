/* SemDiff engine: runs functions on many inputs, records observable behavior, matches and classifies. */
const U=x=>BigInt.asUintN(64,x),S=x=>BigInt.asIntN(64,x),hx=x=>'0x'+x.toString(16),MK=b=>(1n<<BigInt(b))-1n;
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const mix=x=>U((x*0x9E3779B97F4A7C15n+0x1234567n)^(x>>13n));
let RETB={};                                   // return width in bits per function name (0 = void), filled from C signatures
const RN={};
['ax','bx','cx','dx','si','di','bp','sp'].forEach(s=>{const b='r'+s;RN[b]=[b,64,0];RN['e'+s]=[b,32,0];RN[s]=[b,16,0]});
['a','b','c','d'].forEach(l=>RN[l+'l']=['r'+l+'x',8,0]);['si','di','bp','sp'].forEach(s=>RN[s+'l']=['r'+s,8,0]);
for(let i=8;i<16;i++){const b='r'+i;RN[b]=[b,64,0];RN[b+'d']=[b,32,0];RN[b+'w']=[b,16,0];RN[b+'b']=[b,8,0]}
const REGS=[...new Set(Object.values(RN).map(v=>v[0]))];
const PROTO={memcpy:[64,64,64],memmove:[64,64,64],memset:[64,32,64],strlen:[64],strcpy:[64,64],strcat:[64,64],strncpy:[64,64,64],strcmp:[64,64],strncmp:[64,64,64],puts:[64],printf:[64,64,64],sprintf:[64,64,64],malloc:[64],calloc:[64,64],free:[64],abs:[32],system:[64],exit:[32],putchar:[32],atoi:[64],gets:[64]};
const SINK=['memcpy','memmove','strcpy','strcat','strncpy','sprintf','system','gets'];
const DANGER=['system','exec','popen','strcpy','gets','sprintf','strcat'];
function popnd(s){s=s.trim();let bits=0;const m=s.match(/^(byte|word|dword|qword)\s+(?:ptr\s+)?(.*)$/i);
 if(m){bits={byte:8,word:16,dword:32,qword:64}[m[1].toLowerCase()];s=m[2]}
 if(s[0]==='['){const terms=[];for(const t of s.slice(1,-1).matchAll(/([+-]?)\s*([A-Za-z0-9_.]+)(?:\*(\d+))?/g)){const n=t[2],sg=t[1]==='-'?-1n:1n;
   if(RN[n])terms.push({s:sg,r:RN[n][0],k:BigInt(t[3]||1)});else if(/^\d/.test(n))terms.push({s:sg,c:BigInt(n)});else terms.push({bad:n})}
  return{t:'m',terms,bits}}
 if(RN[s])return{t:'r',b:RN[s][0],bits:RN[s][1],sh:RN[s][2]};
 if(/^-?(0x[0-9a-f]+|\d+)$/i.test(s)){const n=s[0]==='-',v=BigInt(n?s.slice(1):s);return{t:'i',v:n?-v:v}}
 return{t:'x',s}}
function parse(txt){const fns=[],prog={};let cur=null;
 for(const raw of txt.split('\n')){const l=raw.split(/[;#]/)[0].trim();if(!l)continue;
  const m=l.match(/^([A-Za-z_][\w.$]*):$/);if(m){cur={name:m[1],ins:[],lab:{},lines:[],prog};fns.push(cur);prog[cur.name]=cur;continue}
  if(!cur)continue;cur.lines.push(l);
  if(l.endsWith(':')){cur.lab[l.slice(0,-1)]=cur.ins.length;continue}
  const sp=l.search(/\s/),op=(sp<0?l:l.slice(0,sp)).toLowerCase(),rest=sp<0?'':l.slice(sp).trim();
  cur.ins.push({op,a:rest?rest.split(/,(?![^\[]*\])/).map(popnd):[]})}
 return fns}
const LIM=4000,isStack=a=>a>=0x7ffe0000n&&a<0x80000000n;
function ea(S_,o){let t=0n;for(const x of o.terms){if(x.bad)throw new Error('unsupported address '+x.bad);t+=x.s*(x.r?S_.r[x.r]*x.k:x.c)}return U(t)}
function rdm(S_,a,bits){let v=0n;for(let i=0;i<bits/8;i++){const k=U(a+BigInt(i));v|=BigInt(S_.mem.has(k)?S_.mem.get(k):Number(mix(k)&255n))<<BigInt(8*i)}return v}
function wrm(S_,a,bits,v){for(let i=0;i<bits/8;i++){const k=U(a+BigInt(i));S_.mem.set(k,Number((v>>BigInt(8*i))&255n));if(!isStack(k))S_.w.add(k)}}
function rd(S_,o,w){if(o.t==='i')return BigInt.asUintN(w,o.v);if(o.t==='r')return (S_.r[o.b]>>BigInt(o.sh))&MK(o.bits);
 if(o.t==='m')return rdm(S_,ea(S_,o),w);throw new Error('unsupported operand '+(o.s||o.t))}
function wr(S_,o,v,w){if(o.t==='r'){const m=MK(o.bits);v&=m;S_.r[o.b]=o.bits===64?v:o.bits===32?v:((S_.r[o.b]&~m&MK(64))|v)}
 else if(o.t==='m')wrm(S_,ea(S_,o),w,v);else throw new Error('unsupported destination')}
const wd=a=>{const x=a[0];if(x.t==='r'||x.bits)return x.bits;const y=a[1];return y&&y.t==='r'?y.bits:64};
function fl(S_,res,a,b,bits,k){const m=MK(bits),sg=1n<<BigInt(bits-1);res&=m;S_.z=res===0n;S_.sf=(res&sg)!==0n;
 if(k==='add'){S_.c=(a+b)>m;S_.o=((a&sg)===(b&sg))&&((res&sg)!==(a&sg))}
 else if(k==='sub'){S_.c=a<b;S_.o=((a&sg)!==(b&sg))&&((res&sg)!==(a&sg))}else{S_.c=false;S_.o=false}}
function cond(S_,c){switch(c){case 'e':case 'z':return S_.z;case 'ne':case 'nz':return !S_.z;case 's':return S_.sf;case 'ns':return !S_.sf;case 'o':return S_.o;case 'no':return !S_.o;
 case 'b':case 'c':case 'nae':return S_.c;case 'ae':case 'nb':case 'nc':return !S_.c;case 'be':case 'na':return S_.c||S_.z;case 'a':case 'nbe':return !S_.c&&!S_.z;
 case 'l':case 'nge':return S_.sf!==S_.o;case 'ge':case 'nl':return S_.sf===S_.o;case 'le':case 'ng':return S_.z||S_.sf!==S_.o;case 'g':case 'nle':return !S_.z&&S_.sf===S_.o}
 throw new Error('unsupported condition '+c)}
function trap(m){const e=new Error(m);e.trap=true;throw e}
function copyBytes(S_,d,s,n,fill){if(n>4096n){S_.to=true;return}const bs=[];for(let i=0n;i<n;i++)bs.push(fill===undefined?Number(rdm(S_,U(s+i),8)):fill);bs.forEach((b,i)=>wrm(S_,U(d+BigInt(i)),8,BigInt(b)))}
function call(S_,name,depth){const c=S_.prog[name];if(c&&depth<6){exec(S_,c,depth+1);return}
 if(name==='memcpy'||name==='memmove'||name==='memset'){const d=S_.r.rdi,n=S_.r.rdx&MK(64);S_.sinks.push(name);
  if(name==='memcpy'&&n>0n&&d!==S_.r.rsi&&(U(d-S_.r.rsi)<n||U(S_.r.rsi-d)<n)){S_.to=true;return}   // overlapping memcpy is undefined behavior: inconclusive
  if(name==='memset')copyBytes(S_,d,0n,n,Number(S_.r.rsi&255n));else copyBytes(S_,d,S_.r.rsi,n);S_.r.rax=d;return}
 if(SINK.includes(name))S_.sinks.push(name);
 const pr=PROTO[name]||[64,64,64],regs=['rdi','rsi','rdx','rcx','r8','r9'];
 S_.eff.push('call '+name+'('+pr.map((b,i)=>hx(S_.r[regs[i]]&MK(b))).join(', ')+')');S_.names.push(name);
 S_.r.rax=mix(pr.reduce((s,b,i)=>s*31n+(S_.r[regs[i]]&MK(b)),BigInt(name.length)))}
function exec(S_,fn,depth){let pc=0;
 while(pc<fn.ins.length){if(++S_.steps>LIM){S_.to=true;return}
  const {op,a}=fn.ins[pc++];let w,x,y,res,m;
  switch(op){
  case 'nop':case 'endbr64':break;
  case 'ret':return;
  case 'mov':case 'movabs':w=wd(a);wr(S_,a[0],rd(S_,a[1],w),w);break;
  case 'movzx':case 'movsx':case 'movsxd':{const sb=a[1].t==='r'?a[1].bits:(a[1].bits||32);x=rd(S_,a[1],sb);if(op!=='movzx')x=BigInt.asUintN(a[0].bits,BigInt.asIntN(sb,x));wr(S_,a[0],x,a[0].bits);break}
  case 'cdqe':S_.r.rax=U(BigInt.asIntN(32,S_.r.rax&MK(32)));break;
  case 'cdq':S_.r.rdx=(S_.r.rax&(1n<<31n))?MK(32):0n;break;
  case 'cqo':S_.r.rdx=(S_.r.rax&(1n<<63n))?MK(64):0n;break;
  case 'lea':wr(S_,a[0],ea(S_,a[1]),a[0].bits);break;
  case 'add':case 'sub':case 'cmp':w=wd(a);m=MK(w);x=rd(S_,a[0],w);y=rd(S_,a[1],w);res=(op==='add'?x+y:x-y)&m;fl(S_,res,x,y,w,op==='add'?'add':'sub');if(op!=='cmp')wr(S_,a[0],res,w);break;
  case 'and':case 'or':case 'xor':case 'test':w=wd(a);x=rd(S_,a[0],w);y=rd(S_,a[1],w);res=op==='or'?x|y:op==='xor'?x^y:x&y;fl(S_,res,x,y,w,'l');if(op!=='test')wr(S_,a[0],res,w);break;
  case 'neg':w=wd(a);x=rd(S_,a[0],w);res=(-x)&MK(w);fl(S_,res,0n,x,w,'sub');wr(S_,a[0],res,w);break;
  case 'not':w=wd(a);wr(S_,a[0],~rd(S_,a[0],w)&MK(w),w);break;
  case 'inc':case 'dec':{w=wd(a);x=rd(S_,a[0],w);const c=S_.c;res=(op==='inc'?x+1n:x-1n)&MK(w);fl(S_,res,x,1n,w,op==='inc'?'add':'sub');S_.c=c;wr(S_,a[0],res,w);break}
  case 'imul':{const d=a[0],w2=d.bits,s1=a.length===3?a[1]:d,s2=a.length===3?a[2]:a[1];x=BigInt.asIntN(w2,rd(S_,s1,w2));y=BigInt.asIntN(w2,rd(S_,s2,w2));const p=x*y;res=BigInt.asUintN(w2,p);S_.c=S_.o=p!==BigInt.asIntN(w2,res);wr(S_,d,res,w2);break}
  case 'shl':case 'sal':case 'shr':case 'sar':{w=wd(a);x=rd(S_,a[0],w);const n=(a.length<2?1n:rd(S_,a[1],8))&(w===64?63n:31n);if(n===0n)break;
   if(op==='shl'||op==='sal'){res=(x<<n)&MK(w);S_.c=((x>>(BigInt(w)-n))&1n)===1n}
   else if(op==='shr'){res=x>>n;S_.c=((x>>(n-1n))&1n)===1n}else{res=BigInt.asUintN(w,BigInt.asIntN(w,x)>>n);S_.c=((BigInt.asIntN(w,x)>>(n-1n))&1n)===1n}
   S_.z=res===0n;S_.sf=(res&(1n<<BigInt(w-1)))!==0n;S_.o=false;wr(S_,a[0],res,w);break}
  case 'idiv':case 'div':{w=wd(a);const sg=op==='idiv',W=BigInt(w);let n=(S_.r.rdx&MK(w))<<W|(S_.r.rax&MK(w)),dv=rd(S_,a[0],w);
   if(sg){n=BigInt.asIntN(w*2,n);dv=BigInt.asIntN(w,dv)}if(dv===0n)trap('divide by zero');
   const q=n/dv,r=n%dv;if(sg?(q>MK(w-1)||q<-(1n<<(W-1n))):q>MK(w))trap('divide overflow');
   S_.r.rax=BigInt.asUintN(w,q);S_.r.rdx=BigInt.asUintN(w,r);break}
  case 'push':S_.r.rsp=U(S_.r.rsp-8n);wrm(S_,S_.r.rsp,64,rd(S_,a[0],64));break;
  case 'pop':wr(S_,a[0],rdm(S_,S_.r.rsp,64),64);S_.r.rsp=U(S_.r.rsp+8n);break;
  case 'leave':S_.r.rsp=S_.r.rbp;S_.r.rbp=rdm(S_,S_.r.rsp,64);S_.r.rsp=U(S_.r.rsp+8n);break;
  case 'rep':{const o2=a[0]&&a[0].s||'',sz={b:1n,w:2n,d:4n,q:8n}[o2.slice(-1)],n=S_.r.rcx;if(!/^(movs|stos)[bwdq]$/.test(o2))throw new Error('unsupported instruction rep '+o2);
   if(n*sz>4096n){S_.to=true;return}
   if(o2[0]==='m'&&n>0n&&S_.r.rdi!==S_.r.rsi&&(U(S_.r.rdi-S_.r.rsi)<n*sz||U(S_.r.rsi-S_.r.rdi)<n*sz)){S_.to=true;return}
   if(o2[0]==='m'){const bs=[];for(let i=0n;i<n*sz;i++)bs.push(Number(rdm(S_,U(S_.r.rsi+i),8)));bs.forEach((b,i)=>wrm(S_,U(S_.r.rdi+BigInt(i)),8,BigInt(b)));S_.r.rsi=U(S_.r.rsi+n*sz)}
   else for(let i=0n;i<n;i++)wrm(S_,U(S_.r.rdi+i*sz),Number(sz)*8,S_.r.rax&MK(Number(sz)*8));
   S_.r.rdi=U(S_.r.rdi+n*sz);S_.r.rcx=0n;S_.sinks.push('memcpy');break}
  case 'call':if(a[0].t!=='x')throw new Error('unsupported indirect call');call(S_,a[0].s,depth);break;
  case 'jmp':if(a[0].t!=='x')throw new Error('unsupported indirect jump');if(a[0].s in fn.lab){pc=fn.lab[a[0].s];break}call(S_,a[0].s,depth);return;
  default:
   if(op[0]==='j'){if(cond(S_,op.slice(1))){if(!(a[0].s in fn.lab))throw new Error('unsupported jump target');pc=fn.lab[a[0].s]}}
   else if(op.startsWith('cmov')){if(cond(S_,op.slice(4)))wr(S_,a[0],rd(S_,a[1],a[0].bits),a[0].bits)}
   else if(op.startsWith('set')){wr(S_,a[0],cond(S_,op.slice(3))?1n:0n,8)}
   else throw new Error('unsupported instruction '+op)}}}
function runFn(fn,q){const S_={r:{},mem:new Map(),w:new Set(),eff:[],names:[],sinks:[],steps:0,to:false,z:false,sf:false,c:false,o:false,prog:fn.prog};
 REGS.forEach(r=>S_.r[r]=0n);S_.r.rbp=S_.r.rsp=0x7fff0000n;S_.r.rdi=q[0];S_.r.rsi=q[1];S_.r.rdx=q[2];let trapped=false;
 try{exec(S_,fn,0)}catch(e){if(e.trap){trapped=true;S_.eff.push('trap: '+e.message)}else return{bad:e.message,eff:[],names:[],sinks:[],to:false}}
 if(S_.to)return{eff:S_.eff,names:S_.names,sinks:S_.sinks,to:true};
 const ad=[...S_.w].sort((x,y)=>x<y?-1:x>y?1:0),runs=[];let cur=null;
 for(const k of ad){const b=S_.mem.get(k);if(cur&&k===cur.e+1n){cur.v.push(b);cur.e=k}else{cur={s:k,e:k,v:[b]};runs.push(cur)}}
 for(const r of runs){if(r.v.length<=8)S_.eff.push('write ['+hx(r.s)+'] = '+r.v.map(b=>b.toString(16).padStart(2,'0')).join(''));
  else{let h=2166136261;for(const b of r.v)h=Math.imul(h^b,16777619)>>>0;S_.eff.push('write ['+hx(r.s)+'..'+hx(r.e)+'] '+r.v.length+' bytes #'+h.toString(16))}}
 const rb=RETB[fn.name]!==undefined?RETB[fn.name]:64;
 if(!trapped)S_.eff.push(rb>0?'return '+hx(S_.r.rax&MK(rb)):'return');
 return{eff:S_.eff,names:S_.names,sinks:S_.sinks,to:false}}
const E=[0,1,2,100,101,257,-1].map(v=>U(BigInt(v))),probes=[],IM=0x7fffffffn,SM=[0n,1n,U(-1n)];
for(const a of E)for(const b of E)for(const c of E)probes.push([a,b,c]);
for(const x of SM)for(const y of SM){probes.push([IM,x,y]);probes.push([x,IM,y]);probes.push([x,y,IM])}
let seed=7n;const rnd=()=>{seed=U(seed*6364136223846793005n+1442695040888963407n);return seed>>20n};
for(let i=0;i<100;i++)probes.push([rnd()%200n,rnd()%200n,rnd()%300n]);
const trace=fn=>probes.map(q=>runFn(fn,q)),ok=(x,y)=>!x.to&&!y.to,same=(x,y)=>x.eff.join('|')===y.eff.join('|');
const badOf=t=>{const b=t.find(x=>x.bad);return b?b.bad:null};
const sim=(ta,tb)=>{let s=0,n=0;for(let i=0;i<ta.length;i++){if(!ok(ta[i],tb[i]))continue;n++;s+=.4*(ta[i].names.join()===tb[i].names.join())+.6*same(ta[i],tb[i])}return n?s/n:0};
function naive(a,b){const m=new Map();a.lines.forEach(l=>m.set(l,(m.get(l)||0)+1));let k=0;b.lines.forEach(l=>{if(m.get(l)>0){m.set(l,m.get(l)-1);k++}});
 return Math.round(100*(1-k/Math.max(a.lines.length,b.lines.length,1)))}
function classify(ta,tb){const idx=[];for(let i=0;i<ta.length;i++)if(ok(ta[i],tb[i])&&!same(ta[i],tb[i]))idx.push(i);
 const cost=i=>probes[i].reduce((s,v)=>s+Number(v),0);idx.sort((x,y)=>cost(x)-cost(y));
 const i=idx[0],x=ta[i],y=tb[i],cn=r=>r.names.length+r.sinks.length;let kind,why;
 if(cn(y)<cn(x)){kind='Guard added';why='B skips a call or copy on some inputs that A always performs. This is the typical shape of a bounds-check security fix.'}
 else if(cn(y)>cn(x)){kind='Guard removed or call added';why='B performs a call or copy that A did not make on these inputs.'}
 else if(x.eff.slice(0,-1).join()!==y.eff.slice(0,-1).join()){kind='Call or store argument changed';why='Same calls, but the values passed or written differ, such as a changed constant or formula.'}
 else{kind='Return value changed';why='Outside effects match, but the returned value differs.'}
 return{kind,why,idx,ex:i,x,y}}
function exploit(p){const sink=r=>r.eff.some(e=>e.startsWith('write '))||r.names.some(n=>SINK.includes(n));let best=null,bc=Infinity;
 probes.forEach(q=>{const o=runFn(p.a,q),n=runFn(p.b,q);if(!ok(o,n)||!sink(o)||sink(n))return;const c=q.reduce((s,v)=>s+Number(v),0);if(c<bc){bc=c;best=q}});
 if(!best)return null;let arg=-1,th=null;
 for(let k=0;k<3;k++){let L=null;for(const v of [1n,2n,100n,101n,256n]){if(v>=best[k])continue;const t=best.slice();t[k]=v;if(sink(runFn(p.b,t)))L=v}
  if(L===null)continue;let H=best[k];while(H-L>1n){const mid=(L+H)/2n,t=best.slice();t[k]=mid;if(sink(runFn(p.b,t)))L=mid;else H=mid}arg=k;th=L;break}
 return{input:best,arg,threshold:th}}
const SEV={'Guard added':['info','Hardening: new check added'],'Guard removed or call added':['high','Possible regression: check removed or call added'],'Call or store argument changed':['med','Logic changed'],'Return value changed':['med','Logic changed']};
function analyze(sa,sb){const t0=performance.now();const fa=parse(sa),fb=parse(sb),skipped=[];
 const prep=(fs,side)=>fs.map(f=>{const t=trace(f),b=badOf(t);if(b)skipped.push({f,side,why:b});return{f,t,b}}).filter(x=>!x.b);
 /* symbol names are only a tiebreaker when present */
 const A=prep(fa,'A'),B=prep(fb,'B'),cand=[];
 A.forEach((x,i)=>B.forEach((y,j)=>cand.push([sim(x.t,y.t)+(x.f.name===y.f.name&&!/^sub_/.test(x.f.name)?.25:0),i,j])));cand.sort((p,q)=>q[0]-p[0]);
 const ua=new Set,ub=new Set,pairs=[];
 for(const[s,i,j]of cand){if(s<.35||ua.has(i)||ub.has(j))continue;ua.add(i);ub.add(j);
  const x=A[i],y=B[j],conc=x.t.filter((t,k)=>ok(t,y.t[k])).length,diff=x.t.every((t,k)=>!ok(t,y.t[k])||same(t,y.t[k]));
  const sm=diff,c=sm?null:classify(x.t,y.t),p={a:x.f,b:y.f,same:sm,c,inc:probes.length-conc,naive:naive(x.f,y.f),
   sem:sm?0:Math.round(100*c.idx.length/Math.max(conc,1)),sev:sm?'none':SEV[c.kind][0],label:sm?'Same behavior':c.kind,note:sm?'Compiler or optimizer difference only':SEV[c.kind][1]};
  p.ex=sm?null:exploit(p);pairs.push(p)}
 const calls=f=>[...new Set(runFn(f,[0n,0n,0n]).names)];
 const rem=A.filter((_,i)=>!ua.has(i)).map(x=>({f:x.f,calls:calls(x.f)}));
 const add=B.filter((_,j)=>!ub.has(j)).map(y=>{const c=calls(y.f);return{f:y.f,calls:c,bad:c.filter(n=>DANGER.includes(n))}});
 return{pairs,rem,add,skipped,probes:probes.length,ms:performance.now()-t0}}
