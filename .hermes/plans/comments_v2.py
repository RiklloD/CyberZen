# Insight-layer comments, v2 (2026-08-16).
# Rule for every slide: bullet 1 = what the verified excerpt actually shows;
# bullet 2 = interpretation / tension; bullet 3 = implication or open question,
# cross-linked to related slides. No bullet restates the slide title.
# Slide numbering: LIT findings 3-13, FA findings 15-28, DC findings 30-41.

NEW_COMMENTS = {

# ---------------- LITERATURE REVIEW (slides 3-13) ----------------

("LIT", "Theme 0 · The headline finding"): [
    "What the excerpt shows: the EU's own 'earliest stage' instrument, Pathfinder, opens at the earliest stages of deep tech research — the stage is officially recognised.",
    "But recognition is not a method: Pathfinder funds research consortia, not market discovery. The gap is procedural, not conceptual.",
    "Question for interviews: who owns market discovery at TRL 1–3 in Switzerland? Cf. the Innosuisse stage slide (24) and the CRL slides (18–20).",
],

("LIT", "Theme 1 · Deep tech is ecosystem-dependent"): [
    "What the excerpt shows: the study's own abstract — specific knowledge and talent matter more for deep-tech startup emergence than formal institutions.",
    "Deep tech clusters where research infrastructure and specialised people already are; policy quality alone does not move it.",
    "Muoniverse reading: the PSI/ETH/EPFL density is the asset to build on. Open question: does that talent pool cover commercial roles, not only physics? Cf. slide 31.",
],

("LIT", "Theme 2 · TTOs: relationships, not transactions"): [
    "What the excerpt shows: Chen et al.'s term 'playmakers' — TTOs that translate science through relationships across the innovation ecosystem.",
    "Transfer behaves as an orchestration capability, not a licensing-desk function; the survival panel reaches the same conclusion independently (slide 34).",
    "Interview probe: is PSI's knowledge-transfer office resourced and measured for orchestration, or for transactions (patents, licences)?",
],

("LIT", "Theme 3 · Structured frameworks outperform ad hoc"): [
    "What the excerpt shows: Hayter et al. trace I-Corps-style programs — structured customer discovery — spreading across national systems.",
    "A standardised methodology travels, and every adopter adapts it locally: structure wins over ad hoc, but not unchanged.",
    "Design tension for Milestone 2: methodology-driven (I-Corps) vs mentor-driven (Innosuisse, slide 22). Which fits a physics NCCR?",
],

("LIT", "Theme 4 · Support must be configured, not provided"): [
    "What the excerpt shows: the moderator rows — university incubators (r = 0.118) outperform generic ones; mentoring's coefficient is slightly negative (−0.012).",
    "The variable is not support volume but configuration: who hosts it and what it connects you to. Negative mentoring reads as opportunity cost of founder time.",
    "Pairs with the advisor coefficients on slide 33 — two independent studies question 'add more mentors' as a strategy.",
],

("LIT", "Theme 5 · Market identification is the binding constraint"): [
    "What the excerpt shows: in the structural model, market features drive foresight capability hardest (path = 0.514), ahead of technology features.",
    "The mechanism is capability-building: market signals teach firms to see where the technology could go — firm-internal factors were not significant.",
    "For muon applications with no existing market, that foresight process must be organised deliberately. Cf. the flipped-Lean answer, slide 17.",
],

("LIT", "Theme 5b · Cantner: commercial from day one"): [
    "What the excerpt shows: in Cantner's panel, the commercial sphere outweighs the academic sphere from the very outset of spin-off creation.",
    "This falsifies 'research first, commercialise later' sequencing — commercial capability is built in parallel, not afterwards.",
    "Hard question for muons: what is commercial exposure when the product is 10–20 years out? A Milestone 2 interview anchor; cf. slide 41.",
],

("LIT", "Theme 5c · Denoo: business advisors help, tech advisors delay"): [
    "What the excerpt shows: each business advisor raises application readiness by ~0.23; each technology advisor lowers it by ~0.31.",
    "Counterintuitive but consistent with Theme 4: at early stages the scarce input is business framing, not more technical validation.",
    "Implication for the NCCR advisor pool: recruit advisors who have priced deep-tech markets, not more professors. Cf. slide 7.",
],

("LIT", "Theme 6 · Europe's structural barriers"): [
    "What the excerpt shows: European deep tech firms secured a fraction of US capital — €58B vs €215B over the report's window.",
    "The gap is structural — investor risk appetite and failure stigma, not just fund volume; capital alone cannot close it.",
    "Switzerland leads per capita (slide 35), but late-stage rounds still face EU-scale limits; cf. restored EIC access, slide 26.",
],

("LIT", "Theme 6b · UNDP: 35% more time, 48% more capital"): [
    "What the excerpt shows: deep tech takes on average 35% more time and 48% more capital to reach equivalent milestones.",
    "That premium is an average across all deep tech — physics ventures sit further into the tail of both distributions.",
    "Design constraint for every instrument in this deck: BRIDGE runs 12 months, VC funds 3–5 years. Cf. slides 37 and 41.",
],

("LIT", "Theme 7 · Convergence on a deep tech definition"): [
    "What the excerpt shows: twelve defining attributes structured across technology, venture and ecosystem levels — the field is converging on a definition.",
    "Convergence is what makes cross-study comparison legitimate; muon technology satisfies the technology-side attributes by construction.",
    "Use the three levels as the interview sampling frame: each level names different actors to talk to.",
],

# ---------------- FRAMEWORK ASSESSMENT (slides 15-28) ----------------

("FA", "Framework gap · The central finding"): [
    "What the excerpt shows: the EU's flagship commercial instrument, the Accelerator, requires TRL 6–8 — demonstration, not discovery.",
    "The official pipeline funds research early (Pathfinder) but starts commercial support only at TRL 5–6: the commercial gap is precisely TRL 1–3.",
    "This slide is the thesis's central finding; the rest of the deck maps what exists on each side of that gap.",
],

("FA", "RCA/Imperial · What the module actually is"): [
    "What the excerpt shows: DT Prime's official page — turning breakthrough research into investable ventures with non-dilutive funding.",
    "It is a venture builder attached to a university, not a course: governance and capital sit alongside the methodology.",
    "Benchmark question for November: could an equivalent attach to PSI? The methodology transfers; the institution does not automatically.",
],

("FA", "RCA/Imperial · Flipped Lean Startup"): [
    "What the excerpt shows: Blank's own account of adapting Lean for wicked problems — technology first, then the search for applications.",
    "The flip inverts classic lean: instead of starting from a customer problem, you start from a capability and hunt for contexts where it matters.",
    "Key open issue: what replaces customer discovery when no customer exists yet — Blank's answer is lead and extreme users.",
],

("FA", "CRL · The 9-point scale"): [
    "What the excerpt shows: CRL codified 1–9, from basic value proposition to real market competitiveness — a government found it useful enough to operationalise.",
    "Practitioner traction despite no peer-reviewed origin is itself a finding: there is real demand for a commercial axis to complement TRL.",
    "CRL 1–3 (opportunity recognition → market sizing) maps onto the thesis's target stage; read against the TRL table, slide 39.",
],

("FA", "CRL · The documentation problem"): [
    "What the excerpt shows: secondary sources describing and propagating CRL — none of them cites a primary, peer-reviewed source.",
    "Adoption by citation chain without a canonical paper: building analysis on it requires explicit methodological honesty.",
    "Thesis position: CRL is treated as a practitioner framework, not a validated instrument — stated openly in the assessment.",
],

("FA", "CRL · No published methodology"): [
    "What the excerpt shows: even NITI's motivation mirrors the thesis — TRL accounts only for technical readiness, not commercial readiness.",
    "The criticism is validated; the remedy is thin: CRL describes where you are, not what to do next — no rubric or checklist exists.",
    "Milestone 2 opening: ask actors how they actually gauge commercial readiness — a detector can be TRL 9 and CRL 1.",
],

("FA", "Innosuisse · The native framework"): [
    "What the excerpt shows: the official Start-up Coaching offer aimed at young companies — the instrument every Swiss venture touches.",
    "The design is a voucher system: flexibility and founder choice, rather than a standardised curriculum.",
    "Cf. slide 28: Switzerland chose mentor-driven over methodology-driven — a deliberate contrast for the benchmarking.",
],

("FA", "Innosuisse · Custom, not codified"): [
    "What the excerpt shows: initial coaching is a voucher (up to CHF 10,000) with which founders choose accredited coaches themselves.",
    "Demand-side design presupposes informed demand — at TRL 1–3, scientists may not yet know what support they need.",
    "Interview probe: how many accredited coaches have priced particle-physics applications? Supply of relevant expertise is the test.",
],

("FA", "Innosuisse · KOF causal evidence"): [
    "What the excerpt shows: the KOF difference-in-differences estimate — +20.7% sales on average five years after funding.",
    "Rare causal evidence in this field, and the effect grows with time — consistent with patient, compounding returns.",
    "Boundary condition: strongest for small firms working with ETH-domain partners — evidence about firms, silent on pre-founding TRL 1–3.",
],

("FA", "Innosuisse · The TRL 1–3 structural gap"): [
    "What the excerpt shows: the coaching ladder — initial, core, scale-up — where every rung presupposes an existing young company.",
    "Before founding there is no rung: the gap is stage mismatch inside a well-run system, not a missing system.",
    "With BRIDGE (slide 37): proof-of-concept money exists but runs 12 months — cf. UNDP's +35% time premium, slide 41.",
],

("FA", "EIC · The accelerator gap"): [
    "What the excerpt shows: the Accelerator's own terms — TRL 6–8, blended finance (grant + equity), single-digit success rate.",
    "For muon ventures this is a later-stage target, not an entry point; the pathway runs Pathfinder → Transition → Accelerator.",
    "Sequencing, not any single instrument, is the operative design question; cf. Swiss eligibility, slide 26.",
],

("FA", "EIC · Swiss eligibility restored Jan 2025"): [
    "What the excerpt shows: Switzerland associated to Horizon Europe 'on similar terms with EU Member States' — full eligibility restored.",
    "The EU pipeline is a real option again for Swiss ventures; recent EIC winners confirm actual uptake.",
    "Interview probe: which PSI-adjacent teams already coordinate EU consortia — capability, not just eligibility, gates access.",
],

("FA", "Candidates · CERN Venture Connect"): [
    "What the excerpt shows: CERN's Venture Connect lead among the study's expert sources — CERN is actively building a venture path for particle physics.",
    "The closest institutional sibling to Muoniverse: same science, same pre-market problem, answered with a curated, zero-equity model.",
    "November benchmarking target: what transfers from CERN's portfolio curation to a Swiss NCCR context?",
],

("FA", "Candidates · I-Corps"): [
    "What the excerpt shows: I-Corps' core as Hayter et al. document it — structured customer discovery and business model development.",
    "It is a methodology rather than an institution: adoptable without new bodies, which makes it the cheapest candidate to pilot.",
    "Open question: does a 7-week customer-discovery sprint fit muon validation cycles? Cf. flipped Lean, slide 17.",
],

# ---------------- DATA COMPENDIUM (slides 30-41) ----------------

("DC", "Data · The binding constraint"): [
    "What the excerpt shows: the coefficient hierarchy — market features 0.514 vs technology ~0.31; firm-internal features not significant.",
    "Market-side variance explains the foresight capability outcome (R² = 0.47); the internal factors managers control directly did not register.",
    "Caveat for the thesis: cross-sectional PLS-SEM, n = 110 — association, not causation. Would it replicate for physics ventures?",
],

("DC", "Data · Ecosystem: talent IRR=1.66"): [
    "What the excerpt shows: the regression table — specific knowledge and talent significant; formal institutions not, across 272 regions.",
    "The significant predictors are slow variables: research infrastructure and people accumulate over decades, not funding cycles.",
    "Swiss reading: one very strong node (PSI/ETH/EPFL) — is that concentration a leverage point or a single-point fragility?",
],

("DC", "Data · Incubation: university r=0.118"): [
    "What the excerpt shows: the moderator rows — university incubators 0.118 vs generic 0.067; incubators older than 20 years reach 0.183.",
    "Networks compound: incubator age nearly doubles the effect — evidence the real asset is accumulated relationships.",
    "A new PSI-hosted incubator starts at age zero; renting maturity through partners (CERN, ETH) may beat building it. Cf. slide 27.",
],

("DC", "Data · Advisors: +0.23 vs −0.31"): [
    "What the excerpt shows: the substitution rate — roughly four business advisors advance application readiness by one full unit.",
    "Advisor design becomes arithmetic: the question is not whether advisors help, but which type and in what ratio.",
    "Boundary condition: n = 112 ventures; the outcome is readiness, not survival. What a business advisor does pre-product is untested.",
],

("DC", "Data · TTO survival: p=0.0034"): [
    "What the excerpt shows: the playmaker mechanism — relationships within the wider university innovation-service ecosystem.",
    "Two literatures converge: Chen supplies the mechanism; the survival panel (business relationships, p = 0.0034) supplies the magnitude.",
    "Measurement implication: a TTO's KPIs could count ties built and introductions made — not only patents filed.",
],

("DC", "Data · Switzerland #1 (100 vs 33)"): [
    "What the excerpt shows: 60% of Swiss venture funding flows to deep tech — the highest share of any country.",
    "The ecosystem is deep-tech-native: capital preference, per-capita spinout value (100 vs 33 for the runner-up), top-ranked universities.",
    "Tension with slides 40–41: strength at formation — but will Swiss capital hold for 10–20-year physics timelines? An interview anchor.",
],

("DC", "Data · Innosuisse: 57% market launch"): [
    "What the excerpt shows: 57% of innovation projects reach market launch within three years of funding ending.",
    "Solid conversion — but the sample is existing firm–university R&D consortia; selection happens before the statistic.",
    "The metric counts launches, not scale — and for muon ventures the whole 3-year window is pre-market. Cf. slide 41.",
],

("DC", "Data · BRIDGE: 70% founding rate"): [
    "What the excerpt shows: around 70% of BRIDGE-supported researchers go on to found a startup — the highest conversion of any instrument.",
    "Willingness is not the bottleneck: when an instrument fits the stage, researchers do found companies.",
    "The 12-month, CHF 130K format proves the concept — and its boundary: muon validation cycles outlast the window.",
],

("DC", "Data · KOF DiD: +20.7% sales"): [
    "What the excerpt shows: the 20.7% average sales effect; within the panel it rises from +7.8% (yr 0) toward ~28% (yr 4).",
    "Compounding returns argue for patient evaluation: a short measurement window would score these projects as failures.",
    "Same boundary as slide 23: significant for small firms with ETH-domain partners; silent on the pre-founding stage this thesis targets.",
],

("DC", "Data · TRL coverage gap"): [
    "What the excerpt shows: the TRL scale itself — from 'basic principles observed' to 'proven in operations'.",
    "Nothing in the nine levels asks whether anyone would buy the technology: it measures maturity of proof, not of market.",
    "Read side-by-side with the CRL table (slide 18): together they give the thesis its two-axis readiness framing.",
],

("DC", "Data · EU vs US: €58B vs €215B"): [
    "What the excerpt shows: European deep tech secured €58B against the US €215B — with investor behaviour explaining part of the difference.",
    "Stacked on the +48% capital premium (slide 41), the distance to the same milestone is multiplicative, not additive.",
    "Switzerland's 60% deep-tech share (slide 35) is the national answer — yet Series B scale still leaks to larger pools. Interview probe.",
],

("DC", "Data · Deep tech: +35% time, +48% capital"): [
    "What the excerpt shows: the UNDP quantification — 35% more time and 48% more capital for equivalent milestones.",
    "Every instrument in this deck is shorter than the asset it supports: coaching 36 months, BRIDGE 12, VC funds 3–5 years.",
    "This number is the design constraint the thesis answers with sequencing — see the EIC pathway, slides 25–26.",
],
}
