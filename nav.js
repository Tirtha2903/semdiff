(()=>{const t=document.getElementById('top'),b=document.getElementById('burger');
const path=location.pathname,page=/app\.html/.test(path)?'app':/bench\.html/.test(path)?'bench':'index';if(page!=='index')document.body.classList.add('app');
document.querySelectorAll('#links a').forEach(a=>{if(a.dataset.p===page)a.classList.add('on');a.addEventListener('click',()=>{t.classList.remove('open');b.setAttribute('aria-expanded','false')})});
b.onclick=()=>{const o=t.classList.toggle('open');b.setAttribute('aria-expanded',String(o))};
const sc=()=>t.classList.toggle('sc',scrollY>20);addEventListener('scroll',sc,{passive:true});sc()})();
