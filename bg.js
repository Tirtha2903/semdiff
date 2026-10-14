(()=>{const c=document.getElementById('bgc');if(!c)return;const x=c.getContext('2d');
const T=['mov','add','cmp','jle','call','ret','xor','lea','shl','0x100','0x7f','rdi','rax','rsi','test','imul','ja','0xff'];
const C=[[94,234,212],[139,123,255],[255,160,90]],rm=matchMedia('(prefers-reduced-motion:reduce)').matches;let W,H,P=[];
const mk=r=>{const k=Math.random();return{x:Math.random()*W,y:r?Math.random()*H:H+20,v:.15+Math.random()*.5,s:11+Math.random()*7,t:T[Math.random()*T.length|0],c:k<.06?2:k<.55?0:1,a:.3+Math.random()*.5}};
function size(){const d=Math.min(devicePixelRatio||1,2);W=innerWidth;H=innerHeight;c.width=W*d;c.height=H*d;c.style.width=W+'px';c.style.height=H+'px';x.setTransform(d,0,0,d,0,0);P=Array.from({length:Math.round(W*H/15000)},()=>mk(true))}
function draw(){x.clearRect(0,0,W,H);for(const p of P){const f=Math.sin(Math.PI*Math.min(1,Math.max(0,p.y/H))),k=C[p.c];
 x.font=p.s+'px ui-monospace,Menlo,monospace';x.fillStyle='rgba('+k+','+(p.a*f*(p.c==2?1.7:1))+')';x.fillText(p.t,p.x,p.y);
 if(!rm){p.y-=p.v;if(p.y<-20)Object.assign(p,mk(false))}}if(!rm)requestAnimationFrame(draw)}
addEventListener('resize',size);size();draw()})();
