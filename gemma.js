// Gemma 4 runs locally through Ollama (http://localhost:11434). SemDiff's engine finds the facts; Gemma only explains them.
const OLLAMA='http://localhost:11434';
const SYSTEM='You are a reverse-engineering assistant. Use ONLY the facts provided. Never invent behavior. Answer in plain English, 4 to 6 short sentences.';
async function ask(prompt){
  const r=await fetch(OLLAMA+'/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({model:$('gm').value||'gemma4:e4b',stream:false,options:{temperature:.2},
      messages:[{role:'system',content:SYSTEM},{role:'user',content:prompt}]})});
  if(!r.ok)throw new Error(await r.text());
  return (await r.json()).message.content}
async function detect(){
  const s=$('gs'),sel=$('gm');
  try{const j=await (await fetch(OLLAMA+'/api/tags')).json();
    const ms=j.models.map(m=>m.name).filter(n=>n.startsWith('gemma4'));
    if(!ms.length){s.textContent='Ollama is running but no Gemma 4 model found. Run: ollama pull gemma4:e4b';return}
    sel.innerHTML=ms.map(n=>`<option>${n}</option>`).join('');s.textContent='Gemma 4 connected (local)'}
  catch(e){s.textContent='Gemma 4 not detected. Start it with: ollama serve (the diff still works without it).'}}
function facts(p){const c=p.c;
  return `Two builds of one function were matched by behavior. Verdict from the engine: ${p.label}. Behavior differs on ${p.sem}% of ${R.probes} test inputs.
Smallest failing input (rdi, rsi, rdx): ${probes[c.ex].map(v=>S(v)).join(', ')}
Effects in old build: ${c.x.eff.join('; ')}
Effects in new build: ${c.y.eff.join('; ')}
Old assembly:\n${p.a.lines.join('\n')}\nNew assembly:\n${p.b.lines.join('\n')}`}
async function run_ai(el,prompt){el.classList.add('on');el.textContent='Gemma 4 is thinking...';
  try{el.textContent=await ask(prompt)}catch(e){el.textContent='Could not reach Gemma 4. Is Ollama running? '+e.message}}
document.addEventListener('click',e=>{
  const b=e.target.closest('.ask');
  if(b){const p=R.pairs[+b.dataset.n];
    run_ai($('ai'+b.dataset.n),facts(p)+'\n\nExplain: 1) what changed in behavior, 2) whether it looks like a security fix, a regression or a harmless change and why, 3) what a human reviewer should check next.')}
  if(e.target.id==='sum'){if(!R)go();const el=$('aisum');
    run_ai(el,'Here is a semantic diff report between two software builds:\n'+mdReport()+'\n\nWrite a short executive summary for a security reviewer: what matters most and what to review first.')}});
detect();

/* ---------- Analyst agent: Gemma 4 thinking + native function calling ---------- */
const AGENT_SYS='You are the SemDiff analyst for a binary diff. The engine is the source of truth. Always test claims with the tools (run_function, compare, find_exploit) before answering and never guess. Finish with a short answer that lists the exact inputs you tested.';
const prm=(p,req)=>({type:'object',properties:p,required:req||[]});
const BUILD={type:'string',enum:['A','B']},INT={type:'integer'};
const TOOLS=[
 {type:'function',function:{name:'list_functions',description:'List matched function pairs with engine verdicts, plus added and removed functions.',parameters:prm({})}},
 {type:'function',function:{name:'get_assembly',description:'Get the assembly of one function.',parameters:prm({build:BUILD,name:{type:'string'}},['build','name'])}},
 {type:'function',function:{name:'run_function',description:'Execute one function on concrete integer inputs (rdi, rsi, rdx). Returns calls, writes outside the stack, and the return value.',parameters:prm({build:BUILD,name:{type:'string'},rdi:INT,rsi:INT,rdx:INT},['build','name'])}},
 {type:'function',function:{name:'compare',description:'Run an old function (build A name) and its matched new counterpart on the same input and say whether behavior is identical.',parameters:prm({name:{type:'string'},rdi:INT,rsi:INT,rdx:INT},['name'])}},
 {type:'function',function:{name:'find_exploit',description:'Search for an input where the old function does a risky copy or call that the new function refuses, then bisect the exact threshold. Name is the old function (build A).',parameters:prm({name:{type:'string'}},['name'])}}];
const fnMap=()=>{const m={A:{},B:{}};R.pairs.forEach(p=>{m.A[p.a.name]=p.a;m.B[p.b.name]=p.b});R.rem.forEach(x=>m.A[x.f.name]=x.f);R.add.forEach(x=>m.B[x.f.name]=x.f);return m};
const bi=v=>{try{return U(BigInt(v??0))}catch(e){return 0n}};
function tool(n,a){const m=fnMap(),f=(m[a.build]||{})[a.name];
 if(n=='list_functions')return JSON.stringify({matched:R.pairs.map(p=>({a:p.a.name,b:p.b.name,verdict:p.label,differsOnPct:p.sem})),added:R.add.map(x=>({name:x.f.name,calls:x.calls})),removed:R.rem.map(x=>({name:x.f.name,calls:x.calls}))});
 if(n=='get_assembly')return f?f.lines.join('\n'):'unknown function';
 if(n=='run_function')return f?runFn(f,[bi(a.rdi),bi(a.rsi),bi(a.rdx)]).eff.join('; '):'unknown function';
 if(n=='compare'){const p=R.pairs.find(p=>p.a.name==a.name);if(!p)return 'no matched counterpart';
  const x=bi(a.rdi),y=bi(a.rsi),z=bi(a.rdx),ea=runFn(p.a,[x,y,z]).eff.join('; '),eb=runFn(p.b,[x,y,z]).eff.join('; ');
  return JSON.stringify({old:ea,new:eb,identical:ea===eb})}
 if(n=='find_exploit'){const p=R.pairs.find(p=>p.a.name==a.name);if(!p)return 'no matched counterpart';const e=p.ex;return e?JSON.stringify({input:e.input.map(x=>String(S(x))),argIndex:e.arg,rejectsWhenGreaterThan:e.threshold===null?null:String(e.threshold)}):'no exploit input found'}
 return 'unknown tool'}
async function agent(q){const log=$('agent');log.innerHTML='';
 const add=(c,t)=>{const d=document.createElement('div');d.className=c;d.textContent=t;log.appendChild(d)};
 add('q','You: '+q);const msgs=[{role:'system',content:AGENT_SYS},{role:'user',content:q}];
 for(let i=0;i<8;i++){
  const r=await fetch(OLLAMA+'/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({model:$('gm').value||'gemma4:e4b',stream:false,think:true,tools:TOOLS,messages:msgs,options:{temperature:.2}})});
  if(!r.ok)throw new Error(await r.text());
  const m=(await r.json()).message;msgs.push(m);
  if(m.thinking)add('think','Gemma 4 thinking: '+m.thinking.slice(0,350)+(m.thinking.length>350?'...':''));
  if(!m.tool_calls||!m.tool_calls.length){add('ans',m.content);return}
  for(const c of m.tool_calls){const a=c.function.arguments||{},out=String(tool(c.function.name,a));
   add('tool','Tool call: '+c.function.name+'('+JSON.stringify(a)+')\n-> '+out.slice(0,300));
   msgs.push({role:'tool',tool_name:c.function.name,content:out})}}
 add('ans','Stopped after 8 steps.')}
$('askagent').onclick=async()=>{if(!R)go();$('askagent').disabled=true;
 try{await agent($('aq').value)}catch(e){$('agent').innerHTML='<div class="ans">Could not reach Gemma 4. Is Ollama running with a gemma4 model? '+esc(e.message)+'</div>'}
 $('askagent').disabled=false};
document.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{$('aq').value=c.textContent;$('askagent').click()});

/* ---------- Vision: Gemma 4 reads assembly from a screenshot ---------- */
async function shot(file,target){if(!file)return;
 const b64=await new Promise(ok=>{const fr=new FileReader();fr.onload=()=>ok(fr.result.split(',')[1]);fr.readAsDataURL(file)});
 $('gs').textContent='Gemma 4 is reading the screenshot...';
 try{const r=await fetch(OLLAMA+'/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:$('gm').value||'gemma4:e4b',stream:false,options:{temperature:0},
   messages:[{role:'user',images:[b64],content:'Transcribe the assembly in this image as plain Intel-syntax x86-64 text, one instruction per line. First line must be a function header like sub_1000: and local labels like .L1: . Output only the code, no fences, no explanation.'}]})});
  const t=(await r.json()).message.content.replace(/```\w*/g,'').trim();$(target).value=t;$('gs').textContent='Screenshot imported. Check the text, then run the diff.'}
 catch(e){$('gs').textContent='Could not read the screenshot: '+e.message}}
$('sa').onchange=e=>shot(e.target.files[0],'a');$('sb').onchange=e=>shot(e.target.files[0],'b');
document.addEventListener('click',e=>{const b=e.target.closest('.lift');if(!b)return;const p=R.pairs[+b.dataset.n];
 run_ai($('ai'+b.dataset.n),'Old assembly:\n'+p.a.lines.join('\n')+'\n\nNew assembly:\n'+p.b.lines.join('\n')+'\n\nRewrite each as short C pseudocode with meaningful names (arguments are rdi, rsi, rdx). Then say in one sentence what differs. Use only what the assembly shows.')});
