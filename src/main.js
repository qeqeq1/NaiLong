const $=id=>document.getElementById(id);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));let groups=[],links=[],domains=[];let tab='groups';
const coll=new Intl.Collator('zh-Hans-CN');
const PAGE=10;
const exp={groups:false,domains:false};
const PIN_NJUST=['南京理工大学','南理工','NJUST'];const PIN_NUAA=['南京航空航天大学','南航','NUAA'];
const namesOf=x=>[x.school,...(x.schoolAliases||[])].map(n=>String(n??'').trim());
const pinRank=x=>{const n=namesOf(x);if(n.some(v=>PIN_NJUST.includes(v)))return 0;if(n.some(v=>PIN_NUAA.includes(v)))return 1;return 2};
const isPin=x=>pinRank(x)<2;
const hash=s=>{let h=2166136261;for(const ch of s)h=Math.imul(h^ch.charCodeAt(0),16777619);return h>>>0};
const mulberry=seed=>{let a=seed>>>0;return()=>{a=a+0x6D2B79F5|0;let t=Math.imul(a^a>>>15,1|a);t=t+Math.imul(t^t>>>7,61|t)^t;return((t^t>>>14)>>>0)/4294967296}};
const shuffle=(arr,seed)=>{const r=mulberry(hash(seed)),a=arr.slice();for(let i=a.length-1;i>0;i--){const j=Math.floor(r()*(i+1));[a[i],a[j]]=[a[j],a[i]]}return a};
const hourSeed=()=>{const d=new Date();return `${d.getFullYear()}-${d.getMonth()+1}-${d.getDate()}T${d.getHours()}`};
const cmpG=(a,b)=>coll.compare(a.school,b.school)||coll.compare(a.name,b.name);
const cmpD=(a,b)=>coll.compare(a.school,b.school)||coll.compare(a.domain,b.domain);
function ordered(list,cmp,tag){const pin=list.filter(isPin).sort((x,y)=>pinRank(x)-pinRank(y)||cmp(x,y));const rest=shuffle(list.filter(x=>!isPin(x)),hourSeed()+tag);return pin.concat(rest)}
function limit(list,kind){return exp[kind]?list:list.slice(0,PAGE)}
function updateMore(kind,total){const b=$('more-'+kind);if(!exp[kind]&&total>PAGE){b.hidden=false;b.textContent=`加载更多（剩余 ${total-PAGE} 条）`}else{b.hidden=true}}
async function init(){
  await loadGroups();exp.groups=false;exp.domains=false;
  const reset=()=>{exp.groups=false;exp.domains=false;render()};
  $('search').oninput=reset;$('type').onchange=reset;$('status').onchange=reset;
  $('close').onclick=()=>$('detail').close();
  $('more-groups').onclick=()=>{exp.groups=true;render()};
  $('more-domains').onclick=()=>{exp.domains=true;render()};
  document.querySelectorAll('.tab,.nav-tab').forEach(b=>b.onclick=()=>setTab(b.dataset.tab));
  loadLinks();loadDomains();applyTabFromUrl();
}
async function loadGroups(){try{const r=await fetch('/data/groups.json');if(!r.ok)throw Error();groups=await r.json();$('count').textContent=groups.length;$('schools').textContent=new Set(groups.map(g=>g.school)).size;render()}catch{$('cards').textContent='无法读取数据，请检查 public/data/groups.json。'}}
function applyTabFromUrl(){const t=new URLSearchParams(location.search).get('tab');if(t==='domains'||location.hash==='#domains')setTab('domains')}
function setTab(t){tab=t;exp.groups=false;exp.domains=false;document.querySelectorAll('.tab').forEach(b=>{const on=b.dataset.tab===t;b.classList.toggle('active',on);b.setAttribute('aria-selected',on)});$('panel-groups').hidden=t!=='groups';$('panel-domains').hidden=t!=='domains';render();history.replaceState(null,'',t==='domains'?'?tab=domains#directory':'#directory')}
function render(){tab==='domains'?renderDomains():renderGroups()}
function renderGroups(){const q=$('search').value.trim().toLowerCase(),t=$('type').value;const list=ordered(groups.filter(g=>(!t||g.type===t)&&[g.school,...(g.schoolAliases||[]),g.name,g.qq,g.type,g.intro,g.rules].join(' ').toLowerCase().includes(q)&&g.status==='active'),cmpG,'groups');$('cards').innerHTML=limit(list,'groups').map(g=>`<article class="card"><span class="tag">${esc(g.type)}</span>${isPin(g)?'<span class="pin">置顶</span>':''}<h3>${esc(g.name)}</h3><div class="school">${esc(g.school)}</div><div class="qq">QQ群：${esc(g.qq)}</div><p class="intro">${esc(g.intro||'暂无简介')}</p><div class="bottom"><span>正常收录</span><button data-id="${esc(g.id)}">查看详情 →</button></div></article>`).join('');$('empty').hidden=!!list.length;$('cards').querySelectorAll('[data-id]').forEach(b=>b.onclick=()=>show(groups.find(g=>g.id===b.dataset.id)));updateMore('groups',list.length)}
function show(g){$('detail-body').innerHTML=`<span class="tag">${esc(g.type)}</span><h2>${esc(g.name)}</h2><div class="detail-row"><b>学校 / 组织：</b>${esc(g.school)}</div><div class="detail-row"><b>QQ群号：</b>${esc(g.qq)}</div><div class="detail-row"><b>简介：</b>${esc(g.intro||'')}</div>${g.rules?`<div class="detail-row"><b>群规则：</b>${esc(g.rules)}</div>`:''}<div class="detail-row"><b>状态：</b>${esc(g.status)}</div><button id="copy">复制群号</button>`;$('detail').showModal();$('copy').onclick=async()=>{try{await navigator.clipboard.writeText(String(g.qq));$('copy').textContent='已复制'}catch{$('copy').textContent='请手动复制：'+g.qq}}}
function renderDomains(){const q=$('search').value.trim().toLowerCase(),s=$('status').value;const list=ordered(domains.filter(d=>(!s||d.status===s)&&(d.domain+' '+d.school).toLowerCase().includes(q)),cmpD,'domains');$('rows').innerHTML=limit(list,'domains').map(d=>`<div class="row-item"><a class="row-domain" href="https://${esc(d.domain)}" target="_blank" rel="noopener">${esc(d.domain)}</a><span class="row-school">${esc(d.school)}</span>${isPin(d)?'<span class="row-pin">置顶</span>':''}${d.status!=='running'?'<span class="row-badge">异常</span>':''}</div>`).join('');$('empty').hidden=!!list.length;updateMore('domains',list.length)}
async function loadDomains(){try{const r=await fetch('/data/domains.json');if(!r.ok)throw Error();domains=await r.json();$('dcount').textContent=domains.length;render()}catch{$('rows').textContent='域名数据加载失败。'}}
async function loadLinks(){try{const r=await fetch('/data/links.json');if(!r.ok)throw Error();links=await r.json();renderLinks()}catch{$('link-list').textContent='友链加载失败。'}}
function renderLinks(){if(!links.length){$('link-list').innerHTML='<p style="color:#999">暂无友链。</p>';return}$('link-list').innerHTML=links.map(l=>`<a class="card link-card" href="${esc(l.url)}" target="_blank" rel="noopener"><h3>${esc(l.name)}</h3>${l.desc?`<p class="intro">${esc(l.desc)}</p>`:''}<span class="link-url">${esc(l.url)}</span></a>`).join('')}
init();
