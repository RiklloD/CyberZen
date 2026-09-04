from pathlib import Path

TARGET = Path(r"G:\Mon Drive\ZHermes Agent\Bachelor Thesis\presentations\Milestone1_Knowledge_Graph.html")
OLD = TARGET.read_text(encoding='utf-8')
start = OLD.index('// ================= DATA =================')
end = OLD.index('// ================= VIS =================')
data_block = OLD[start:end]

head = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Milestone 1 — Insight Graph</title>
<style>
:root{
  --bg:#07111f; --panel:#0d1a2b; --panel2:#102238; --line:#243750;
  --text:#edf4fb; --muted:#91a2b7; --faint:#5d7087; --cyan:#22d3ee;
  --teal:#2dd4bf; --amber:#fbbf24; --violet:#a78bfa; --sky:#60a5fa;
  --green:#4ade80; --rose:#fb7185; --white:#fff;
}
*{box-sizing:border-box}
html,body{height:100%;margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Arial,sans-serif;overflow:hidden}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.24;background-image:linear-gradient(rgba(56,189,248,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(56,189,248,.04) 1px,transparent 1px);background-size:40px 40px}
#app{height:100%;display:grid;grid-template-rows:62px 1fr 46px;position:relative}
#topbar{display:flex;align-items:center;gap:16px;padding:0 22px;background:rgba(7,17,31,.94);border-bottom:1px solid var(--line);z-index:20;backdrop-filter:blur(12px)}
.brand{display:flex;align-items:center;gap:10px;min-width:270px}.brand-dot{width:10px;height:10px;border-radius:50%;background:var(--cyan);box-shadow:0 0 16px var(--cyan)}
.brand strong{font-size:15px;letter-spacing:.2px}.brand span{color:var(--cyan)}
.subtitle{font-size:11px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:430px}
.spacer{flex:1}.mode{display:flex;gap:5px;border:1px solid var(--line);padding:3px;border-radius:9px;background:#0b1727}.mode button,.small-btn{border:0;color:var(--muted);background:transparent;border-radius:6px;padding:7px 11px;font-size:11px;font-weight:700;cursor:pointer}.mode button.active{background:var(--cyan);color:#06202b}.mode button:hover:not(.active),.small-btn:hover{color:var(--text);background:#162b42}
#search{width:205px;background:#0b1727;border:1px solid var(--line);border-radius:7px;color:var(--text);padding:8px 10px;font-size:11px;outline:none}#search:focus{border-color:var(--cyan)}
#workspace{display:grid;grid-template-columns:310px minmax(480px,1fr) 310px;min-height:0;z-index:2}
.rail{background:rgba(9,22,38,.88);min-height:0;overflow:auto}.left{border-right:1px solid var(--line);padding:18px 15px}.right{border-left:1px solid var(--line);padding:18px 15px}
.eyebrow{font-size:10px;letter-spacing:1.4px;color:var(--cyan);font-weight:800;text-transform:uppercase}.rail h2{font-size:18px;line-height:1.15;margin:7px 0 6px}.rail-intro{font-size:11px;line-height:1.45;color:var(--muted);margin-bottom:14px}
.insight{border:1px solid var(--line);background:linear-gradient(135deg,rgba(16,34,56,.95),rgba(10,24,41,.95));border-radius:10px;padding:11px 11px 10px;margin:8px 0;cursor:pointer;transition:.16s;position:relative}.insight:hover{border-color:#3c6987;transform:translateY(-1px)}.insight.active{border-color:var(--cyan);box-shadow:0 0 0 1px rgba(34,211,238,.16),0 8px 22px rgba(0,0,0,.18)}.insight .num{font-size:10px;font-weight:800;color:var(--cyan);margin-bottom:4px}.insight h3{font-size:12px;margin:0 0 5px;line-height:1.25}.insight p{font-size:10.5px;color:var(--muted);line-height:1.4;margin:0}.insight .arrow{position:absolute;right:10px;top:11px;color:var(--faint)}
#graph-shell{min-width:0;position:relative;display:grid;grid-template-rows:42px 1fr;background:radial-gradient(circle at 50% 42%,rgba(14,116,144,.08),transparent 42%)}
#graph-toolbar{display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid rgba(36,55,80,.7);color:var(--muted);font-size:10px}.metric{padding:5px 8px;border:1px solid var(--line);border-radius:6px;background:rgba(13,26,43,.72)}.metric b{color:var(--text)}
#graph{min-height:0;width:100%;height:100%}
#graph-hint{position:absolute;left:14px;bottom:14px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:rgba(7,17,31,.86);font-size:10px;color:var(--muted);pointer-events:none}.hint-accent{color:var(--cyan)}
#detail h2{font-size:17px;line-height:1.18;margin:7px 0}.detail-kicker{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}.detail-copy{font-size:11px;color:var(--muted);line-height:1.5}.detail-box{border:1px solid var(--line);border-radius:9px;background:rgba(16,34,56,.7);padding:11px;margin-top:13px}.detail-box h4{font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--cyan);margin:0 0 7px}.detail-box p{font-size:11px;line-height:1.45;color:var(--text);margin:0}.tag{display:inline-block;font-size:9px;color:var(--cyan);border:1px solid rgba(34,211,238,.3);padding:3px 6px;border-radius:20px;margin:3px 4px 0 0}.node-link{font-size:10px;color:var(--muted);margin:5px 0;cursor:pointer}.node-link:hover{color:var(--cyan)}
.control-group{margin-top:17px;border-top:1px solid var(--line);padding-top:13px}.control-group h4{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin:0 0 9px}.checks{display:grid;grid-template-columns:1fr 1fr;gap:7px 5px}.checks label{font-size:10px;color:var(--muted);display:flex;gap:6px;align-items:center;cursor:pointer}.checks input{accent-color:var(--cyan)}
#footer{display:flex;align-items:center;gap:14px;padding:0 20px;background:rgba(7,17,31,.94);border-top:1px solid var(--line);font-size:10px;color:var(--muted);z-index:20}.footer-flow{display:flex;align-items:center;gap:7px}.flow-step{color:var(--text);padding:5px 8px;border-radius:5px;background:#102238;border:1px solid var(--line)}.flow-arrow{color:var(--cyan)}
#toast{position:fixed;left:50%;bottom:62px;transform:translateX(-50%);background:#102238;border:1px solid var(--cyan);color:var(--text);border-radius:8px;padding:9px 13px;font-size:11px;opacity:0;pointer-events:none;transition:.2s;z-index:40}.toast-show{opacity:1!important}
@media(max-width:1100px){#workspace{grid-template-columns:260px minmax(360px,1fr) 260px}.subtitle{display:none}#search{width:150px}}
@media(max-width:850px){#workspace{grid-template-columns:1fr} .left,.right{display:none}#topbar{padding:0 10px}.brand{min-width:auto}.brand .subbrand{display:none}}
</style>
</head>
<body>
<div id="app">
<header id="topbar">
  <div class="brand"><span class="brand-dot"></span><strong>Milestone 1 <span>Insight Graph</span></strong></div>
  <div class="subtitle">NCCR Muoniverse · deep-tech commercialization at early TRL · from evidence to design implications</div>
  <div class="spacer"></div>
  <div class="mode"><button id="insightMode" class="active">Insight map</button><button id="evidenceMode">Evidence graph</button></div>
  <input id="search" placeholder="Search concepts, sources…" aria-label="Search graph">
  <button class="small-btn" id="resetBtn">Reset</button>
</header>
<main id="workspace">
  <aside class="rail left">
    <div class="eyebrow">Thesis synthesis</div>
    <h2>What the evidence is really saying</h2>
    <p class="rail-intro">The graph is not only a bibliography. Click an insight to reveal the chain from finding → gap → design move.</p>
    <div id="insights"></div>
    <div class="control-group"><h4>Design principles</h4><div id="principles"></div></div>
  </aside>
  <section id="graph-shell">
    <div id="graph-toolbar"><div class="metric"><b id="nodeCount">—</b> visible nodes</div><div class="metric"><b id="edgeCount">—</b> visible links</div><div class="metric"><b>5</b> thesis insights</div><div class="spacer"></div><span id="modeNote">Curated conceptual map · click an insight or node</span></div>
    <div id="graph"></div>
    <div id="graph-hint"><span class="hint-accent">Drag</span> nodes · scroll to zoom · click for context</div>
  </section>
  <aside class="rail right" id="detail">
    <div class="eyebrow">Context panel</div>
    <h2 id="detailTitle">Start with an insight</h2>
    <p class="detail-copy" id="detailCopy">The central question is not “which framework wins?” It is: what support architecture lets fundamental physics move from TRL 1–3 toward a market that may not exist yet?</p>
    <div class="detail-box" id="detailBox"><h4>How to read this map</h4><p>Use <b>Insight map</b> for the argument. Use <b>Evidence graph</b> to inspect documents, sources, gaps, and Swiss actors. Click any node to see its role and neighboring evidence.</p></div>
    <div class="control-group" id="evidenceControls" style="display:none"><h4>Evidence layers</h4><div class="checks" id="checks"></div></div>
  </aside>
</main>
<footer id="footer"><span>Logic of the thesis</span><div class="footer-flow"><span class="flow-step">early-TRL physics</span><span class="flow-arrow">→</span><span class="flow-step">market + ecosystem constraints</span><span class="flow-arrow">→</span><span class="flow-step">support architecture</span><span class="flow-arrow">→</span><span class="flow-step">interviews</span></div><span class="spacer"></span><span>58 original nodes · 5 synthesis insights · 6 design moves</span></footer>
</div>
<div id="toast"></div>
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<script>
''' + data_block + r'''
// ---------- synthesis layer: explicit interpretation, not just document metadata ----------
const SYNTH_NODES = [
 {id:'core_problem',label:'EARLY-TRL PHYSICS GAP',type:'problem',meta:'The central thesis problem',desc:'Fundamental physics at TRL 1–3 has no ready-made commercialization architecture. The technology may be excellent while the market, customer, capital path, and institutional support remain unknown.'},
 {id:'constraint_market',label:'Market is the binding constraint',type:'finding',meta:'β 0.514 vs technology 0.310',desc:'Market features are the strongest predictor in the Foresight study; Cantner shows commercial exposure matters from the outset of spin-off creation.'},
 {id:'constraint_ecosystem',label:'Specialized ecosystem beats generic policy',type:'finding',meta:'Knowledge + talent > formal institutions',desc:'The regional evidence points to deep-tech knowledge, talent, infrastructure, and density as the core enabling conditions.'},
 {id:'constraint_tto',label:'TTO must be a playmaker',type:'finding',meta:'Relationship infrastructure',desc:'A TTO creates value when it builds relationships across the innovation service ecosystem, opens customer pathways, and orchestrates actors.'},
 {id:'constraint_config',label:'Support must be configured',type:'finding',meta:'No one-size-fits-all package',desc:'Incubation and intermediary evidence suggests that the combination and timing of support matters more than the presence of a generic program.'},
 {id:'constraint_time',label:'Time + capital mismatch',type:'finding',meta:'+35% time · +48% capital',desc:'Deep tech development timelines and capital needs collide with conventional VC cycles and short program horizons.'},
 {id:'architecture',label:'MUONIVERSE SUPPORT ARCHITECTURE',type:'design',meta:'Proposed synthesis',desc:'A staged, market-facing, ecosystem-orchestrated support architecture for physics ventures before a conventional market exists.'},
 {id:'design_market',label:'Market discovery from day one',type:'design',meta:'RCA/Wicked + I-Corps',desc:'Use technology-first speculative design to imagine applications, then disciplined customer discovery to narrow the opportunity space.'},
 {id:'design_tto',label:'Playmaker TTO',type:'design',meta:'Relationships + customer access',desc:'Move beyond IP transactions: orchestrate researchers, customers, infrastructure, coaches, investors, and institutional partners.'},
 {id:'design_capital',label:'Patient, staged capital',type:'design',meta:'Swiss → EU → scale',desc:'Match funding to the actual maturity curve: early validation and infrastructure, collaborative maturation, then blended finance and scale-up.'},
 {id:'design_config',label:'Configured support bundles',type:'design',meta:'Business + network + technical',desc:'Configure support around the binding constraint at each stage; avoid assuming that more mentors or more technical advice is always better.'},
 {id:'design_infra',label:'Infrastructure + talent access',type:'design',meta:'PSI · ETH · EPFL · CERN',desc:'Treat research infrastructure, specialist talent, and trusted institutional relationships as commercialization inputs, not background conditions.'},
];
const SYNTH_EDGES = [
 ['core_problem','constraint_market','reveals'],['core_problem','constraint_ecosystem','depends on'],['core_problem','constraint_tto','needs'],['core_problem','constraint_config','exposes'],['core_problem','constraint_time','collides with'],
 ['constraint_market','design_market','requires'],['constraint_ecosystem','design_infra','requires'],['constraint_tto','design_tto','becomes'],['constraint_config','design_config','requires'],['constraint_time','design_capital','requires'],
 ['design_market','architecture','feeds'],['design_tto','architecture','orchestrates'],['design_capital','architecture','funds'],['design_config','architecture','configures'],['design_infra','architecture','anchors'],
 ['architecture','fw_icorps','uses'],['architecture','fw_cvc','learns from'],['architecture','fw_inn','sequences with'],['architecture','fw_eic','sequences with'],['architecture','fw_rca','adapts'],
 ['constraint_market','th5','supported by'],['constraint_market','s5','measured by'],['constraint_market','s7','confirmed by'],['constraint_ecosystem','th1','supported by'],['constraint_ecosystem','s1','measured by'],['constraint_tto','th2','supported by'],['constraint_tto','s8','described by'],['constraint_config','th4','supported by'],['constraint_config','s2','measured by'],['constraint_time','th6','supported by'],['constraint_time','s13','measured by'],
 ['design_market','s9','evidence'],['design_tto','s8','evidence'],['design_capital','s18','evidence'],['design_capital','s20','analogue'],['design_infra','act_psi','anchored in'],['design_infra','act_cern','anchored in'],
];
const SYNTH_INSIGHTS = [
 {id:'i1',num:'01',title:'The central problem is architectural',thesis:'TRL 1–3 physics is not simply “too early for business”. It is too early for every existing support system to fit cleanly.',move:'Design question: what is the missing architecture between scientific potential and a first credible market hypothesis?',nodes:['core_problem','architecture','g2','fw_rca','fw_crl','fw_inn','fw_eic'],evidence:['Framework Assessment','EIC Work Programme','Innosuisse Start-up Coaching','NITI Aayog TCRM Matrix']},
 {id:'i2',num:'02',title:'Market before maturity',thesis:'The evidence repeatedly moves the bottleneck away from technical excellence and toward market discovery, customer exposure, and commercial embeddedness.',move:'Design move: start with speculative applications + customer discovery from day one, before demanding a conventional business plan.',nodes:['constraint_market','design_market','th5','s5','s7','fw_rca','fw_icorps'],evidence:['Capatina et al. 2024','Cantner et al. 2024','Hayter et al. 2025','Steve Blank 2023']},
 {id:'i3',num:'03',title:'The ecosystem is the venture',thesis:'Specialized knowledge, talent, research infrastructure, and trusted relationships are not context around commercialization. They are the commercialization mechanism.',move:'Design move: make PSI/ETH/EPFL/CERN access, talent, and customer pathways explicit program assets.',nodes:['constraint_ecosystem','design_infra','th1','act_psi','act_cern','act_eth','act_epfl'],evidence:['Micol et al. 2026','Swiss Deep Tech Report 2025','CERN KT material']},
 {id:'i4',num:'04',title:'Support is a configuration problem',thesis:'More support is not automatically better. Timing, fit, role, and combination matter: business advice, networks, TTO orchestration, and technical help should not be treated as interchangeable.',move:'Design move: configure a bundle around the current binding constraint and include explicit pivot/abandon gates.',nodes:['constraint_tto','constraint_config','design_tto','design_config','th2','th4','s2','s6','s8'],evidence:['Seitz et al. 2026','Denoo et al. 2024','Chen et al. 2025']},
 {id:'i5',num:'05',title:'Sequence capital around the physics curve',thesis:'Deep tech needs more time and capital than conventional startups, while programs are often shorter and stage-specific.',move:'Design move: sequence Swiss support → collaborative EU maturation → scale-up capital, with a patient-capital bridge around TRL 1–3.',nodes:['constraint_time','design_capital','fw_inn','fw_eic','fw_cvc','th6','s13','s18','s20'],evidence:['UNDP 2025','Innosuisse Impact Monitor','KOF DiD study','EIC Accelerator','CERN Venture Connect']},
];
const PRINCIPLES = [
 ['01','Start market discovery early','Technology-first imagination, followed by real customer evidence.'],
 ['02','Make the TTO a playmaker','Relationships, customer access, and orchestration—not only IP paperwork.'],
 ['03','Use dual readiness','Track technical, commercial, and market readiness together.'],
 ['04','Configure the bundle','Match advisors, networks, capital, and infrastructure to the binding constraint.'],
 ['05','Fund the real timeline','Build a patient bridge before a venture is eligible for conventional scale-up capital.'],
 ['06','Measure the missing outcomes','Track market hypotheses, customer access, pivots, failures, and time-to-next-proof.'],
];

const TYPE_COLORS = {doc:'#2dd4bf',theme:'#fbbf24',fw:'#a78bfa',gap:'#60a5fa',src:'#71839a',actor:'#4ade80',problem:'#fb7185',finding:'#38bdf8',design:'#22d3ee'};
const TYPE_BORDERS = {doc:'#0f766e',theme:'#a16207',fw:'#7c3aed',gap:'#2563eb',src:'#475569',actor:'#16a34a',problem:'#e11d48',finding:'#0284c7',design:'#0891b2'};
const TYPE_SIZES = {doc:34,theme:24,fw:24,gap:20,src:13,actor:20,problem:38,finding:29,design:31};
const TYPE_FONT = {doc:12,theme:10,fw:10,gap:9,src:8,actor:9,problem:12,finding:10,design:11};
const TYPE_NAMES = {doc:'Document',theme:'Literature theme',fw:'Framework',gap:'Research gap',src:'Source',actor:'Ecosystem actor',problem:'Core problem',finding:'Constraint',design:'Design move'};

const RAW_NODES = [...DOCS,...THEMES,...FRAMEWORKS,...GAPS,...ACTORS,...SOURCES,...SYNTH_NODES];
const RAW_EDGES = [...EDGES.map(([from,to])=>({from,to,label:'',kind:'evidence'})),...SYNTH_EDGES.map(([from,to,label])=>({from,to,label,kind:'synthesis'}))];
const NODE_INFO = Object.fromEntries(RAW_NODES.map(n=>[n.id,n]));
const EDGE_BY_NODE = {};
RAW_EDGES.forEach(e=>{(EDGE_BY_NODE[e.from]??=[]).push(e.to);(EDGE_BY_NODE[e.to]??=[]).push(e.from)});
const BASE_STYLE = {};
function nodeModel(n){
 const c=TYPE_COLORS[n.type]||'#71839a', b=TYPE_BORDERS[n.type]||'#475569';
 const model={id:n.id,label:n.label,group:n.type,title:`<b>${n.label}</b><br>${n.meta||''}`,size:TYPE_SIZES[n.type]||15,
   color:{background:c,border:b,highlight:{background:'#ffffff',border:c},hover:{background:c,border:'#ffffff'}},
   borderWidth:n.type==='src'?1:2,
   font:{color:n.type==='src'?'#9aa9ba':'#eaf3fb',size:TYPE_FONT[n.type]||9,face:'Inter'},
   shadow:{enabled:true,size:8,x:0,y:2,color:'rgba(0,0,0,.42)'}};
 BASE_STYLE[n.id]=model; return model;
}
const ALL_NODE_MODELS=RAW_NODES.map(nodeModel);
function edgeModel(e,i){return {id:'e'+i,from:e.from,to:e.to,label:e.label||'',kind:e.kind,color:{color:e.kind==='synthesis'?'#47637c':'#263c55',highlight:'#22d3ee',hover:'#60a5fa'},width:e.kind==='synthesis'?2:1,arrows:'to',font:{color:'#6f849a',size:8,face:'Inter',strokeWidth:0,align:'middle'},smooth:{type:'dynamic'}}}
const ALL_EDGE_MODELS=RAW_EDGES.map(edgeModel);
const ALL_IDS=new Set(RAW_NODES.map(n=>n.id));
const CURATED_IDS=new Set(['core_problem','constraint_market','constraint_ecosystem','constraint_tto','constraint_config','constraint_time','architecture','design_market','design_tto','design_capital','design_config','design_infra','fw_rca','fw_crl','fw_inn','fw_eic','fw_icorps','fw_cvc','g2','g4']);
const CURATED_EDGES=ALL_EDGE_MODELS.filter(e=>CURATED_IDS.has(e.from)&&CURATED_IDS.has(e.to));
const EVIDENCE_TYPES=new Set(['doc','theme','fw','gap','src','actor']);
const state={mode:'insight',activeInsight:null,visibleTypes:new Set(EVIDENCE_TYPES),query:''};
let network, nodeDS, edgeDS;

function subsetForMode(){
 if(state.mode==='insight') return {nodes:ALL_NODE_MODELS.filter(n=>CURATED_IDS.has(n.id)),edges:CURATED_EDGES};
 const ids=new Set(RAW_NODES.filter(n=>state.visibleTypes.has(n.type)).map(n=>n.id));
 return {nodes:ALL_NODE_MODELS.filter(n=>ids.has(n.id)),edges:ALL_EDGE_MODELS.filter(e=>ids.has(e.from)&&ids.has(e.to))};
}
function networkOptions(){
 const insight=state.mode==='insight';
 return {autoResize:true,layout:insight?{hierarchical:{enabled:true,direction:'LR',sortMethod:'directed',levelSeparation:155,nodeSpacing:115,treeSpacing:220,blockShifting:true,edgeMinimization:true,parentCentralization:true}}:{randomSeed:16},
   physics:insight?{enabled:false}:{solver:'forceAtlas2Based',forceAtlas2Based:{gravitationalConstant:-72,centralGravity:.012,springLength:135,springConstant:.045,damping:.62},stabilization:{iterations:220,updateInterval:20}},
   interaction:{hover:true,tooltipDelay:120,dragNodes:true,zoomView:true,hideEdgesOnDrag:true,keyboard:{enabled:true}},
   nodes:{shape:'dot',chosen:{node:(v)=>{v.borderWidth=4}},scaling:{min:10,max:42},margin:4},
   edges:{selectionWidth:2,hoverWidth:1.8},
 };
}
function setMode(mode){
 state.mode=mode; document.getElementById('insightMode').classList.toggle('active',mode==='insight'); document.getElementById('evidenceMode').classList.toggle('active',mode==='evidence');
 document.getElementById('evidenceControls').style.display=mode==='evidence'?'block':'none'; document.getElementById('modeNote').textContent=mode==='insight'?'Curated conceptual map · click an insight or node':'Full corpus · toggle evidence layers or search';
 const sub=subsetForMode(); nodeDS=new vis.DataSet(sub.nodes); edgeDS=new vis.DataSet(sub.edges); network.setData({nodes:nodeDS,edges:edgeDS}); network.setOptions(networkOptions());
 if(mode==='insight') setTimeout(()=>network.fit({animation:{duration:450,easingFunction:'easeInOutQuad'}}),160); else setTimeout(()=>network.fit({animation:{duration:500,easingFunction:'easeInOutQuad'}}),350);
 updateMetrics(); if(state.activeInsight) focusInsight(state.activeInsight);
}
function updateMetrics(){document.getElementById('nodeCount').textContent=nodeDS?nodeDS.length:0;document.getElementById('edgeCount').textContent=edgeDS?edgeDS.length:0}
function showInsight(ins){
 state.activeInsight=ins.id; document.querySelectorAll('.insight').forEach(x=>x.classList.toggle('active',x.dataset.id===ins.id));
 document.getElementById('detailTitle').textContent=ins.title; document.getElementById('detailCopy').textContent=ins.thesis;
 document.getElementById('detailBox').innerHTML=`<h4>Design implication</h4><p>${ins.move}</p><div style="margin-top:9px">${ins.evidence.map(x=>`<span class="tag">${x}</span>`).join('')}</div>`;
 focusInsight(ins.id);
}
function focusInsight(id){
 const ins=SYNTH_INSIGHTS.find(x=>x.id===id); if(!ins||!nodeDS)return;
 const focus=new Set(ins.nodes);
 const modeNodes=nodeDS.getIds();
 const updates=[];
 modeNodes.forEach(nid=>{
   const base=BASE_STYLE[nid]; const on=focus.has(nid);
   updates.push({id:nid,color:on?base.color:{background:'#1b293a',border:'#2d4055'},font:{...base.font,color:on?'#eef7ff':'#5c7086'}});
 });
 nodeDS.update(updates);
 const visibleEdges=edgeDS.getIds().map(id=>edgeDS.get(id)).filter(e=>focus.has(e.from)&&focus.has(e.to)).map(e=>e.id);
 edgeDS.update(edgeDS.getIds().map(id=>({id,color:visibleEdges.includes(id)?{color:'#22d3ee',highlight:'#ffffff'}:{color:'#172a3d',highlight:'#172a3d'},width:visibleEdges.includes(id)?2.8:.55}))); 
 network.selectNodes([...focus].filter(x=>modeNodes.includes(x)),false); network.fit({nodes:[...focus].filter(x=>modeNodes.includes(x)),animation:{duration:500,easingFunction:'easeInOutQuad'}});
}
function resetFocus(){state.activeInsight=null;document.querySelectorAll('.insight').forEach(x=>x.classList.remove('active'));document.getElementById('detailTitle').textContent='Start with an insight';document.getElementById('detailCopy').textContent='The central question is not “which framework wins?” It is: what support architecture lets fundamental physics move from TRL 1–3 toward a market that may not exist yet?';document.getElementById('detailBox').innerHTML='<h4>How to read this map</h4><p>Use <b>Insight map</b> for the argument. Use <b>Evidence graph</b> to inspect documents, sources, gaps, and Swiss actors. Click any node to see its role and neighboring evidence.</p>';setMode(state.mode)}
function selectNode(id){
 const n=NODE_INFO[id]; if(!n)return;
 const neighbors=(EDGE_BY_NODE[id]||[]).map(x=>NODE_INFO[x]).filter(Boolean).slice(0,8);
 document.getElementById('detailTitle').textContent=n.label;document.getElementById('detailCopy').textContent=n.desc||'';
 document.getElementById('detailBox').innerHTML=`<h4>${TYPE_NAMES[n.type]||n.type} · ${n.meta||''}</h4><p>Connected thinking</p><div style="margin-top:8px">${neighbors.map(x=>`<div class="node-link" data-node="${x.id}">↳ ${x.label}</div>`).join('')}</div>`;
 document.querySelectorAll('.node-link').forEach(x=>x.onclick=()=>selectNode(x.dataset.node));
 if(nodeDS.get(id))network.selectNodes([id]);
}
function search(q){state.query=q.toLowerCase().trim(); if(!nodeDS)return; const ids=nodeDS.getIds(); if(!state.query){resetNodeStyles();return;}const matches=ids.filter(id=>{const n=NODE_INFO[id];return `${n.label} ${n.meta||''} ${n.desc||''}`.toLowerCase().includes(state.query)});const update=ids.map(id=>{const base=BASE_STYLE[id];const on=matches.includes(id);return {id,color:on?base.color:{background:'#172538',border:'#253b52'},font:{...base.font,color:on?'#ffffff':'#53677d'}}});nodeDS.update(update);if(matches.length){network.selectNodes(matches);network.fit({nodes:matches,animation:{duration:400,easingFunction:'easeInOutQuad'}})}else{toast('No matching node')};}
function resetNodeStyles(){if(!nodeDS)return;nodeDS.update(nodeDS.getIds().map(id=>({id,color:BASE_STYLE[id].color,font:BASE_STYLE[id].font})));edgeDS.update(edgeDS.getIds().map(id=>({id,color:BASE_STYLE[id]?'#263c55':'#263c55',width:1})));}
function toast(msg){const el=document.getElementById('toast');el.textContent=msg;el.classList.add('toast-show');setTimeout(()=>el.classList.remove('toast-show'),1800)}
function renderInsights(){const box=document.getElementById('insights');box.innerHTML=SYNTH_INSIGHTS.map(i=>`<div class="insight" data-id="${i.id}"><div class="num">${i.num} · INSIGHT</div><span class="arrow">→</span><h3>${i.title}</h3><p>${i.thesis}</p></div>`).join('');box.querySelectorAll('.insight').forEach(el=>el.onclick=()=>showInsight(SYNTH_INSIGHTS.find(i=>i.id===el.dataset.id)));}
function renderPrinciples(){document.getElementById('principles').innerHTML=PRINCIPLES.map(p=>`<div style="display:grid;grid-template-columns:25px 1fr;gap:7px;margin:9px 0"><div style="color:var(--cyan);font-size:10px;font-weight:800">${p[0]}</div><div><div style="font-size:10.5px;color:var(--text);font-weight:700">${p[1]}</div><div style="font-size:9.5px;color:var(--muted);line-height:1.35;margin-top:2px">${p[2]}</div></div></div>`).join('')}
function renderChecks(){const labels=[['doc','Documents'],['theme','Themes'],['fw','Frameworks'],['gap','Gaps'],['actor','Actors'],['src','Sources']];document.getElementById('checks').innerHTML=labels.map(([t,l])=>`<label><input type="checkbox" data-type="${t}" checked> <span style="color:${TYPE_COLORS[t]}">●</span>${l}</label>`).join('');document.querySelectorAll('#checks input').forEach(x=>x.onchange=()=>{x.checked?state.visibleTypes.add(x.dataset.type):state.visibleTypes.delete(x.dataset.type);if(state.mode==='evidence')setMode('evidence')});}

renderInsights();renderPrinciples();renderChecks();
network=new vis.Network(document.getElementById('graph'),{nodes:new vis.DataSet([]),edges:new vis.DataSet([])},networkOptions());
network.on('click',p=>{if(p.nodes.length)selectNode(p.nodes[0]);else if(!state.activeInsight)resetFocus()});
document.getElementById('insightMode').onclick=()=>setMode('insight');document.getElementById('evidenceMode').onclick=()=>setMode('evidence');document.getElementById('resetBtn').onclick=resetFocus;document.getElementById('search').oninput=e=>search(e.target.value);
setMode('insight');
</script>
</body>
</html>
'''

# Back up the previous graph once.
backup = TARGET.with_name('Milestone1_Knowledge_Graph_previous.html')
if TARGET.exists() and not backup.exists(): TARGET.replace(backup)
TARGET.write_text(head, encoding='utf-8')
print('wrote', TARGET, 'bytes', TARGET.stat().st_size)
print('nodes in original data block retained; synthesis nodes added at runtime')
