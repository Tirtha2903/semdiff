const $=id=>document.getElementById(id);
const W={high:40,med:20,low:10,info:10};
let R=null;
const dl=(n,t,m)=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([t],{type:m}));a.download=n;a.click()};
const eff=l=>esc(l.join('\n')).replace(/\n/g,'<br>');
function score(r){let s=0;r.pairs.forEach(p=>s+=W[p.sev]||0);r.add.forEach(a=>s+=a.bad.length?40:10);r.rem.forEach(()=>s+=10);return Math.min(100,s)}
const exl=p=>{const e=p.ex;if(!e)return '';const v=e.input.map(x=>S(x)).join(', '),n=['rdi','rsi','rdx'];
  return `<p class="xl"><b>Exploit finder:</b> with input (${v}) the old build performs a risky copy or call that the new build refuses.${e.arg>=0?` The new build starts rejecting when ${n[e.arg]} &gt; ${e.threshold} (found by bisection).`:''}</p>`};
function render(r){
  const same=r.pairs.filter(p=>p.same).length,ch=r.pairs.length-same;
  let h=`<h2>Result</h2><div class="sum"><div><b>${same}</b><span>same behavior</span></div><div><b>${ch}</b><span>behavior changed</span></div><div><b>${r.add.length}</b><span>added</span></div><div><b>${r.rem.length}</b><span>removed</span></div><div><b>${score(r)}</b><span>risk score out of 100</span></div></div>
  <p class="mut">Analyzed in ${Math.round(r.ms)} ms on ${r.probes} inputs per function. "Same behavior" means no difference on those inputs. It is strong evidence, not a formal proof.</p>`;
  let n=-1;for(const p of r.pairs){n++;
    h+=`<div class="card"><div class="hd"><span class="nm">${esc(p.a.name)} &harr; ${esc(p.b.name)}</span><span class="badge ${p.sev}">${esc(p.label)}</span></div>
    <p class="mut">${esc(p.note)}</p>
    <div class="bar">Text diff says ${p.naive}% changed<span class="t"><i style="width:${p.naive}%;background:var(--muted)"></i></span></div>
    <div class="bar">Behavior differs on ${p.sem}% of inputs<span class="t"><i style="width:${p.sem}%;background:${p.same?'var(--ok)':'var(--warn)'}"></i></span></div>`;
    if(!p.same){const c=p.c,d=new Set(c.idx);
      h+=`<div class="mut">Divergence map: each square is one test input. Orange means A and B behave differently.</div><div class="heat">${probes.map((_,i)=>d.has(i)?'<i class="d" title="rdi, rsi, rdx = '+probes[i].map(v=>S(v)).join(', ')+'"></i>':'<i></i>').join('')}</div>
      <div class="tw"><table><tr><th></th><th>Smallest failing input (rdi, rsi, rdx) = ${probes[c.ex].map(v=>S(v)).join(', ')}</th></tr>
      <tr><td>A did</td><td>${eff(c.x.eff)}</td></tr><tr><td>B did</td><td>${eff(c.y.eff)}</td></tr></table></div>${exl(p)}<button class="btn g ask" data-n="${n}" style="margin-top:10px">Explain with Gemma 4</button><button class="btn g lift" data-n="${n}" style="margin:10px 0 0 6px">Lift to C</button><div class="ai" id="ai${n}"></div>`}
    h+=`<details><summary class="mut">Show code</summary><div class="row" style="margin-top:8px"><pre>${esc(p.a.lines.join('\n'))}</pre><pre>${esc(p.b.lines.join('\n'))}</pre></div></details></div>`}
  for(const x of r.rem)h+=`<div class="card"><div class="hd"><span class="nm">${esc(x.f.name)} (only in A)</span><span class="badge low">Removed</span></div><p class="mut">Calls: ${esc(x.calls.join(', ')||'none')}</p></div>`;
  for(const x of r.add)h+=`<div class="card"><div class="hd"><span class="nm">${esc(x.f.name)} (only in B)</span><span class="badge ${x.bad.length?'high':'low'}">Added</span></div><p class="mut">Calls: ${esc(x.calls.join(', ')||'none')}${x.bad.length?'. Security-sensitive: '+esc(x.bad.join(', '))+' deserves a manual review.':''}</p></div>`;
  for(const k of r.skipped)h+=`<div class="card"><div class="hd"><span class="nm">${esc(k.f.name)} (build ${k.side})</span><span class="badge low">Not analyzed</span></div><p class="mut">Unsupported: ${esc(k.why)}. SemDiff reports this instead of guessing.</p></div>`;
  $('out').innerHTML=h}
function go(){try{R=analyze($('a').value,$('b').value);render(R)}catch(e){$('out').innerHTML='<div class="card"><b>Could not analyze.</b><p class="mut">'+esc(String(e))+'</p></div>'}}
function mdReport(){if(!R)go();let m=`# SemDiff report\n\nRisk score: ${score(R)}/100\n\n`;
  for(const p of R.pairs){m+=`- **${p.a.name} <-> ${p.b.name}**: ${p.label}`;
    if(!p.same){const v=probes[p.c.ex].map(x=>S(x)).join(', ');m+=` (differs on ${p.sem}% of inputs; example input rdi,rsi,rdx = ${v})`}m+='\n'}
  R.add.forEach(x=>m+=`- **${x.f.name}**: added, calls ${x.calls.join(', ')||'none'}${x.bad.length?' (security-sensitive)':''}\n`);
  R.rem.forEach(x=>m+=`- **${x.f.name}**: removed\n`);return m}
function jsReport(){if(!R)go();return JSON.stringify({risk:score(R),inputsPerFunction:R.probes,
  matched:R.pairs.map(p=>({a:p.a.name,b:p.b.name,verdict:p.label,severity:p.sev,behaviorDiffPct:p.sem,
    example:p.same?null:probes[p.c.ex].map(x=>String(S(x))),aEffects:p.same?null:p.c.x.eff,bEffects:p.same?null:p.c.y.eff})),
  added:R.add.map(x=>({name:x.f.name,calls:x.calls})),removed:R.rem.map(x=>({name:x.f.name,calls:x.calls}))},null,2)}
const reset=()=>{RETB={};$('a').value=SAMPLE_A;$('b').value=SAMPLE_B;go()};
$('go').onclick=go;$('demo').onclick=reset;
$('md').onclick=()=>dl('semdiff-report.md',mdReport(),'text/markdown');
$('js').onclick=()=>dl('semdiff-report.json',jsReport(),'application/json');
$('fa').onchange=async e=>{$('a').value=await e.target.files[0].text()};
$('fb').onchange=async e=>{$('b').value=await e.target.files[0].text()};
const C1='int copy_buf(char *dst, const char *src, unsigned n) {\n  memcpy(dst, src, n);\n  return 0;\n}\n',C2='int copy_buf(char *dst, const char *src, unsigned n) {\n  if (n > 256) return -1;\n  memcpy(dst, src, n);\n  return 0;\n}\n';
$('c1').value=C1;$('c2').value=C2;
const post=(source,opt)=>fetch('/api/compile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source,opt})}).then(async r=>{const j=await r.json();if(!r.ok)throw new Error(j.error);return j});
async function compileDiff(){const st=$('cs');st.textContent='Compiling with gcc...';
 try{const[a,b]=await Promise.all([post($('c1').value,$('o1').value),post($('c2').value,$('o2').value)]);
  RETB={};Object.assign(RETB,a.ret,b.ret);$('a').value=a.asm;$('b').value=b.asm;st.textContent='Compiled with '+a.gcc+' and -O'+$('o2').value+'. The assembly is shown below.';go()}
 catch(e){st.textContent='Compile failed: '+e.message+(/fetch|Failed/i.test(e.message)?' (start the server with: python3 server.py)':'')}}
$('cc').onclick=compileDiff;
reset();
