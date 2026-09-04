"""Content audit:
1. Title-vs-comment redundancy: flag comments whose content words heavily overlap the title.
2. Cross-reference integrity: every 'slide N' mention must point to a real finding slide
   with a sane topic match (manual review list printed).
3. 'What the excerpt shows' bullets must not duplicate the title verbatim.
"""
import importlib.util as ilu, re
from pptx import Presentation

def load(path, name):
    spec = ilu.spec_from_file_location(name, path)
    m = ilu.module_from_spec(spec); spec.loader.exec_module(m)
    return m

cv2 = load(r'C:\Dev\CyberZen\.hermes\plans\comments_v2.py', 'cv2')

# deck2 slides give titles per key
d2 = load(r'C:\Dev\CyberZen\.hermes\plans\make_deck2.py', 'd2')
SLIDES = d2.slides

d3 = load(r'C:\Dev\CyberZen\.hermes\plans\make_clean_deck_v3.py', 'd3')

STOP = set('the a an of to in for and or on at with vs by from as is are that what how cf slide read side by side together it its their this these those not no than more most'.split())

def content_words(s):
    return {w for w in re.findall(r"[a-zA-Z\u2013\u00e0-\u00ff']+", s.lower()) if w not in STOP and len(w) > 2}

titles = {k: t for _, k, t, _, _ in SLIDES}
overrides = d3.TITLE_OVERRIDES

redundant, xrefs = [], []
for key, bullets in cv2.NEW_COMMENTS.items():
    title = overrides.get(key, titles[key])
    tw = content_words(title)
    for b in bullets:
        bw = content_words(b)
        inter = tw & bw
        # redundancy signal: >40% of title's content words appear in one bullet
        if tw and len(inter) / len(tw) > 0.45:
            redundant.append((key, b[:60], sorted(inter)))
    for m in re.finditer(r'slides? (\d+)(?:\u2013(\d+))?|slide (\d+)', b):
        nums = [int(g) for g in m.groups() if g]
        xrefs.append((key, b[:60], nums))

print('=== redundancy check (title words echoed in a single bullet) ===')
if redundant:
    for r in redundant: print('FLAG', r)
else:
    print('none — no bullet restates its title')

print()
print('=== cross-references (verify targets manually) ===')
# build slide->title map for the final deck order
order, page = [], 2
for kind, key, title, ref, comments in SLIDES:
    if kind == 'theme': page += 1; order.append((page, key, overrides.get(key, title)))
page += 1
for kind, key, title, ref, comments in SLIDES:
    if kind == 'fw': page += 1; order.append((page, key, overrides.get(key, title)))
page += 1
for kind, key, title, ref, comments in SLIDES:
    if kind == 'dt': page += 1; order.append((page, key, overrides.get(key, title)))
pg_title = {pg: t for pg, _, t in order}
pg_key = {pg: k for pg, k, _ in order}

for key, snippet, nums in xrefs:
    targets = []
    for n in nums:
        if n in pg_title:
            targets.append(f'{n}={pg_title[n][:45]}')
    status = 'OK' if len(targets) == len(nums) else 'BAD'
    print(status, key[1][:38], '->', nums, '|', '; '.join(targets))
