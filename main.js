const R=analyze(SAMPLE_A,SAMPLE_B);
const $=id=>document.getElementById(id);
const ch=R.pairs.find(p=>!p.same&&p.sev==='info')||R.pairs.find(p=>!p.same),sm=R.pairs.find(p=>p.same);
if(ch){const c=ch.c,inp=probes[c.ex].map(v=>S(v)).join(', ');
 $('lv').innerHTML=`<div class="lh"><i></i>Live result from the engine, computed in your browser just now</div>
 <div class="lrow"><b>${esc(ch.a.name)} &harr; ${esc(ch.b.name)}</b><span class="badge ${ch.sev}">${esc(ch.label)}</span></div>
 <div class="lc"><div><small>Old build did</small><code>${esc(c.x.eff.join('; '))}</code></div><div><small>New build did</small><code>${esc(c.y.eff.join('; '))}</code></div></div>
 <div class="lf">Failing input (rdi, rsi, rdx): ${inp}</div>`;
 $('term').textContent=`> compare(name="${ch.a.name}", rdi=${probes[c.ex].map(v=>S(v))[0]}, rsi=${probes[c.ex].map(v=>S(v))[1]}, rdx=${probes[c.ex].map(v=>S(v))[2]})\nold: ${c.x.eff.join('; ')}\nnew: ${c.y.eff.join('; ')}\nidentical: false`}
if(sm){$('t1').textContent=sm.naive+'%';$('m1').style.width=sm.naive+'%';$('s1').textContent=sm.sem+'%';$('m2').style.width=Math.max(2,sm.sem)+'%';
 $('s2').textContent='of its behavior changed, proven equal on '+R.probes.toLocaleString()+' inputs.'}
const targets=[R.probes,Math.max(1,Math.round(R.ms)),R.pairs.length,0],suf=['','ms','',''];
const ease=x=>1-Math.pow(1-x,3);
function count(el,i){const t=targets[i],dur=1500;let t0=null;const tick=ts=>{if(t0===null)t0=ts;const p=Math.min(1,(ts-t0)/dur);el.textContent=Math.round(t*ease(p)).toLocaleString()+suf[i];if(p<1)requestAnimationFrame(tick)};requestAnimationFrame(tick)}
const io=new IntersectionObserver(es=>es.forEach(e=>{if(!e.isIntersecting)return;e.target.classList.add('in');const b=e.target.querySelector&&e.target.querySelector('b[data-i]');if(b&&!b.dataset.d){b.dataset.d=1;count(b,+b.dataset.i)}io.unobserve(e.target)}),{threshold:.15});
document.querySelectorAll('.rv').forEach((el,i)=>{el.style.transitionDelay=(i%4)*70+'ms';io.observe(el)});
