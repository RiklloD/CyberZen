#!/usr/bin/env python3
"""Generate highlighted document screenshots — v2: full-document quote search + unicode normalization."""
import pypdfium2 as pdfium
import re, os, json
from PIL import Image, ImageDraw

BASE = r"C:\Dev\CyberZen\.hermes\plans\pdfs"
OUT = r"C:\Dev\CyberZen\.hermes\plans\shots"
os.makedirs(OUT, exist_ok=True)

DOCS = {
    "LIT": os.path.join(BASE, "literature_review.pdf"),
    "FA":  os.path.join(BASE, "framework_assessment.pdf"),
    "DC":  os.path.join(BASE, "data_compendium.pdf"),
}

def norm(s):
    s = s.replace("\u2018", "'").replace("\u2019", "'")
    s = s.replace("\u201c", '"').replace("\u201d", '"')
    s = s.replace("\ufffe", "").replace("\ufffd", "")
    s = re.sub(r"\s+", " ", s).strip()
    return s

def page_char_stream(tp, n):
    """Return (clean_string, idx_map) skipping newlines/tabs."""
    clean, idx_map = [], []
    for i in range(n):
        try:
            c = tp.get_text_range(i, 1)
        except Exception:
            c = ""
        if c in ("\r", "\n", "\t", "\x00", "\ufffe", "\ufffd"):
            continue
        clean.append(c)
        idx_map.append(i)
    return "".join(clean), idx_map

def find_in_page(tp, n, quote):
    s, idx_map = page_char_stream(tp, n)
    q = norm(quote)
    pos = s.find(q)
    if pos < 0:
        return None
    union = None
    for k in range(pos, pos + len(q)):
        try:
            box = tp.get_charbox(idx_map[k])
        except Exception:
            box = None
        if box:
            l, t, r, b = box
            if union is None:
                union = [l, t, r, b]
            else:
                union[0] = min(union[0], l); union[1] = min(union[1], t)
                union[2] = max(union[2], r); union[3] = max(union[3], b)
    return union

def find_in_doc(pdf_path, quote, hint_page=None):
    """Search all pages; prefer hint_page (1-indexed) if the quote is there."""
    doc = pdfium.PdfDocument(pdf_path)
    pages = list(range(len(doc)))
    if hint_page is not None:
        pages = [hint_page - 1] + [p for p in pages if p != hint_page - 1]
    for p in pages:
        page = doc[p]
        tp = page.get_textpage()
        n = tp.count_chars()
        bbox = find_in_page(tp, n, quote)
        if bbox:
            doc.close()
            return p, bbox
    doc.close()
    return None, None

def render_crop(pdf_path, page_no, bbox_pts, scale=2.0, pad=(18, 10, 18, 10), min_w_pts=300, min_h_pts=80):
    doc = pdfium.PdfDocument(pdf_path)
    page = doc[page_no]
    pw, ph = page.get_size()
    l, t, r, b = bbox_pts
    # ensure minimum crop size around the quote (context for table cells / short quotes)
    cw = r - l; ch = b - t
    if cw < min_w_pts:
        add = (min_w_pts - cw) / 2
        l = max(0, l - add); r = min(pw, r + add)
    if ch < min_h_pts:
        add = (min_h_pts - ch) / 2
        t = max(0, t - add); b = min(ph, b + add)
    L = max(0, l - pad[0]); T = max(0, t - pad[1])
    R = min(pw, r + pad[2]); B = min(ph, b + pad[3])
    bitmap = page.render(scale=scale)
    pil = bitmap.to_pil().convert("RGB")
    crop = pil.crop((int(L*scale), int(T*scale), int(R*scale), int(B*scale)))
    doc.close()
    return crop, (L, T, R, B)

def draw_highlight(img, qbox_in_crop, scale, color=(245, 158, 11, 70), outline=(245, 158, 11, 255), width=3):
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(overlay)
    l, t, r, b = qbox_in_crop
    d.rectangle([l*scale, t*scale, r*scale, b*scale], fill=color, outline=outline, width=width)
    return Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")

# doc, hint page (1-indexed), quote, label
MANIFEST = [
    # ---- THEMES (Literature Review) ----
    {"doc": "LIT", "hint": 1, "quote": "the space where NCCR Muoniverse operates, fundamental physics at TRL 1–3, is precisely where no existing commercialization framework was designed to work",
     "label": "Theme 0 · The headline finding"},
    {"doc": "LIT", "hint": 2, "quote": "Two factors are statistically significant predictors of deep tech concentration: knowledge infrastructure (IRR = 1.48) and talent pools (IRR = 1.66)",
     "label": "Theme 1 · Deep tech is ecosystem-dependent"},
    {"doc": "LIT", "hint": 2, "quote": "Relational and market-oriented support matters more than technical support",
     "label": "Theme 2 · TTOs: relationships, not transactions"},
    {"doc": "LIT", "hint": 2, "quote": "This constitutes a natural experiment confirming structured frameworks work, but every system adapted the model to local context",
     "label": "Theme 3 · Structured frameworks outperform ad hoc"},
    {"doc": "LIT", "hint": 2, "quote": "Capital ranks below market access and expertise, suggesting the European ecosystem's scarcest resources are not financial",
     "label": "Theme 4 · Support must be configured, not provided"},
    {"doc": "LIT", "hint": 3, "quote": "market features are the strongest predictor of commercialization success (β = 0.514), ahead of technology features (β = 0.310)",
     "label": "Theme 5 · Market identification is the binding constraint"},
    {"doc": "LIT", "hint": 3, "quote": "in importance from the very outset of spin-off creation",
     "label": "Theme 5b · Cantner: commercial from day one"},
    {"doc": "LIT", "hint": 3, "quote": "each additional business advisor increases 'application readiness' by 0.23 units (p = 0.04), while each additional technology advisor decreases it by 0.31 units (p = 0.05)",
     "label": "Theme 5c · Denoo: business advisors help, tech advisors delay"},
    {"doc": "LIT", "hint": 3, "quote": "62% of European investors reject founders with prior failures vs. a US culture treating failure as learning",
     "label": "Theme 6 · Europe's structural barriers"},
    {"doc": "LIT", "hint": 3, "quote": "Deep tech requires 35% more time and 48% more capital than conventional startups",
     "label": "Theme 6b · UNDP: 35% more time, 48% more capital"},
    {"doc": "LIT", "hint": 3, "quote": "12 defining attributes across three levels: technology",
     "label": "Theme 7 · Convergence on a deep tech definition"},

    # ---- FRAMEWORKS (Framework Assessment) ----
    {"doc": "FA", "hint": 3, "quote": "The space where NCCR Muoniverse operates, fundamental physics at TRL 1–3 , is precisely where no existing framework was designed to work",
     "label": "Framework gap · The central finding"},
    {"doc": "FA", "hint": 4, "quote": "This is a pedagogical exercise, not a spin-off creation mechanism",
     "label": "RCA/Imperial · What the module actually is"},
    {"doc": "FA", "hint": 5, "quote": "flipping Lean Startup logic on its head",
     "label": "RCA/Imperial · Flipped Lean Startup"},
    {"doc": "FA", "hint": 7, "quote": "The CRL scale progresses from recognizing initial commercial opportunities (CRL 1) through measuring market factors (CRL 2), understanding competitiveness (CRL 3)",
     "label": "CRL · The 9-point scale"},
    {"doc": "FA", "hint": 8, "quote": "The most significant finding of this assessment concerns the framework's academic standing",
     "label": "CRL · The documentation problem"},
    {"doc": "FA", "hint": 8, "quote": "the CRL lacks a formal assessment methodology",
     "label": "CRL · No published methodology"},
    {"doc": "FA", "hint": 10, "quote": "Innosuisse is the most institutionally relevant framework for NCCR Muoniverse because it is the Swiss national framework",
     "label": "Innosuisse · The native framework"},
    {"doc": "FA", "hint": 11, "quote": "NOT explicitly based on NSF",
     "label": "Innosuisse · Custom, not codified"},
    {"doc": "FA", "hint": 12, "quote": "the study finds that Innosuisse funding causes an average 20.7% increase in sales and 17.6% increase in employment over five years",
     "label": "Innosuisse · KOF causal evidence"},
    {"doc": "FA", "hint": 13, "quote": "no Innosuisse instrument specifically designed for TRL 1–3 commercialization",
     "label": "Innosuisse · The TRL 1–3 structural gap"},
    {"doc": "FA", "hint": 17, "quote": "requires TRL 5 or above",
     "label": "EIC · The accelerator gap"},
    {"doc": "FA", "hint": 16, "quote": "Swiss startups and SMEs are eligible for both EIC Accelerator grants and equity investments",
     "label": "EIC · Swiss eligibility restored Jan 2025"},
    {"doc": "FA", "hint": 18, "quote": "CERN faces the identical institutional challenge as NCCR Muoniverse: translating fundamental particle physics research into commercial applications",
     "label": "Candidates · CERN Venture Connect"},
    {"doc": "FA", "hint": 18, "quote": "the most internationally validated early-TRL commercialization program",
     "label": "Candidates · I-Corps"},

    # ---- DATA (Data Compendium) ----
    {"doc": "DC", "hint": 4, "quote": "are the strongest predictor of deep tech commercialization success",
     "label": "Data · The binding constraint"},
    {"doc": "DC", "hint": 6, "quote": "Talent pools (R&D FTE share)",
     "label": "Data · Ecosystem: talent IRR=1.66"},
    {"doc": "DC", "hint": 7, "quote": "University incubators",
     "label": "Data · Incubation: university r=0.118"},
    {"doc": "DC", "hint": 8, "quote": "Each business advisor increases AR",
     "label": "Data · Advisors: +0.23 vs −0.31"},
    {"doc": "DC", "hint": 10, "quote": "Close business relationships maintained by TTO",
     "label": "Data · TTO survival: p=0.0034"},
    {"doc": "DC", "hint": 12, "quote": "Spinout value per capita index",
     "label": "Data · Switzerland #1 (100 vs 33)"},
    {"doc": "DC", "hint": 14, "quote": "Market launch rate (within 3 years post-funding)",
     "label": "Data · Innosuisse: 57% market launch"},
    {"doc": "DC", "hint": 15, "quote": "Founding rate",
     "label": "Data · BRIDGE: 70% founding rate"},
    {"doc": "DC", "hint": 16, "quote": "Sales",
     "label": "Data · KOF DiD: +20.7% sales"},
    {"doc": "DC", "hint": 17, "quote": "The central finding of the framework assessment: every framework has a structural gap at TRL 1–3",
     "label": "Data · TRL coverage gap"},
    {"doc": "DC", "hint": 19, "quote": "3.7× gap",
     "label": "Data · EU vs US: €58B vs €215B"},
    {"doc": "DC", "hint": 20, "quote": "+35%",
     "label": "Data · Deep tech: +35% time, +48% capital"},
]

def main():
    results = []
    for item in MANIFEST:
        pdf = DOCS[item["doc"]]
        page_idx, bbox = find_in_doc(pdf, item["quote"], hint_page=item.get("hint"))
        if bbox is None:
            print(f"MISS: [{item['doc']}] {item['label']} :: {item['quote'][:60]}")
            continue
        crop, (L, T, R, B) = render_crop(pdf, page_idx, bbox)
        qbox = [bbox[0]-L, bbox[1]-T, bbox[2]-L, bbox[3]-T]
        img = draw_highlight(crop, qbox, 2.0)
        fname = f"{item['doc']}_p{page_idx+1:02d}_{len(results):02d}.png"
        img.save(os.path.join(OUT, fname))
        results.append({**item, "file": fname, "page": page_idx + 1, "size": img.size})
        print(f"OK: {fname} (p{page_idx+1}) [{item['label']}]")
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
    print(f"\n{len(results)}/{len(MANIFEST)} screenshots generated")

if __name__ == "__main__":
    main()
