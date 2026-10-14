/* Guided story: walks through the demo using real engine results. */
(()=>{const btn=document.getElementById('story');if(!btn)return;
 const ov=document.createElement('div');ov.className='ov';ov.hidden=true;
 ov.innerHTML='<div class="ovc" role="dialog" aria-label="SemDiff story"><button class="x" aria-label="Close">&times;</button><small class="st"></small><h3 class="sh"></h3><div class="sb"></div><div class="sn"><button class="btn g" id="sprev">Back</button><span class="dots"></span><button class="btn" id="snext">Next</button></div></div>';
 document.body.appendChild(ov);const q=s=>ov.querySelector(s);let i=0,steps=[];
 function build(){reset();const sm=R.pairs.find(p=>p.same),ch=R.pairs.find(p=>!p.same&&p.ex)||R.pairs.find(p=>!p.same),e=ch&&ch.ex,inp=e?e.input.map(v=>S(v)).join(', '):'';
  steps=[
  ['The problem','Two builds, mostly noise',`Build B was recompiled with different settings and patched. A plain text diff says <b>${sm.naive}%</b> of one function's instructions changed. Almost all of that is compiler noise.`],
  ['Behavior, not bytes','SemDiff runs both builds',`It executes every function on <b>${R.probes}</b> test inputs and records what is visible from outside: calls, memory writes and return values. That function behaves the same on all of them. <b>${sm.sem}% differs.</b> No false alarm.`],
  ['The real change',esc(ch.label),`<code>${esc(ch.a.name)}</code> and <code>${esc(ch.b.name)}</code> were matched by behavior alone, with no names.<br><br><b>Old build:</b> <code>${esc(ch.c.x.eff.join('; '))}</code><br><b>New build:</b> <code>${esc(ch.c.y.eff.join('; '))}</code>`],
  ['Exploit finder','The exact input that matters',e?`With input <code>(${inp})</code> the old build performs a risky copy. The new build refuses it${e.arg>=0?`, and starts rejecting when <code>${['rdi','rsi','rdx'][e.arg]} &gt; ${e.threshold}</code>. That threshold was found by bisection, not guessed.`:'.'}`:'No exploit input found for this change.'],
  ['Gemma 4','An analyst that investigates','Gemma 4 runs locally through Ollama. It thinks, calls the engine\'s tools such as <code>compare</code> and <code>find_exploit</code>, and explains the result.<br><br><button class="btn g" id="sgem">Ask Gemma 4 to explain this change</button><div class="ai" id="sai"></div>'],
  ['Your turn','Try it on real code','Close this and use <b>Compile real C code</b> to diff your own functions with your own gcc, or open the <b>Benchmark</b> page for the measured results.']]}
 function show(){const s=steps[i];q('.st').textContent='Step '+(i+1)+' of '+steps.length+'  |  '+s[0];q('.sh').innerHTML=s[1];q('.sb').innerHTML=s[2];
  q('.dots').innerHTML=steps.map((_,k)=>'<i class="'+(k===i?'on':'')+'"></i>').join('');q('#sprev').disabled=i===0;q('#snext').textContent=i===steps.length-1?'Finish':'Next';
  const g=q('#sgem');if(g)g.onclick=()=>{const p=R.pairs.find(p=>!p.same);if(typeof facts==='function')run_ai(q('#sai'),facts(p)+'\n\nExplain what changed and whether it looks like a security fix.');else q('#sai').textContent='Gemma 4 is not connected.';q('#sai').classList.add('on')}}
 const open=()=>{build();i=0;ov.hidden=false;show()},close=()=>ov.hidden=true;
 btn.onclick=open;q('.x').onclick=close;ov.addEventListener('click',e=>{if(e.target===ov)close()});
 q('#sprev').onclick=()=>{if(i>0){i--;show()}};q('#snext').onclick=()=>{if(i<steps.length-1){i++;show()}else close()};
 addEventListener('keydown',e=>{if(ov.hidden)return;if(e.key==='Escape')close();if(e.key==='ArrowRight')q('#snext').click();if(e.key==='ArrowLeft')q('#sprev').click()});
 if(/story=1/.test(location.search))setTimeout(open,400)})();
