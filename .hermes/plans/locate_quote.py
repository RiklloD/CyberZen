#!/usr/bin/env python3
"""Locate a quote in a PDF page using per-char boxes; return union bbox in PDF points."""
import pypdfium2 as pdfium
import re, sys, json

def norm(s):
    return re.sub(r"\s+", " ", s).strip()

def get_chars(tp, n):
    """Return list of (char, (l,t,r,b)) for first n chars."""
    out = []
    for i in range(n):
        try:
            box = tp.get_charbox(i)
        except Exception:
            box = None
        c = tp.get_text_range(i, 1)
        out.append((c, box))
    return out

def find_quote(tp, n_chars, quote, start=0):
    """Search quote (normalized) in the char stream; return union bbox or None."""
    # build string of printable chars with indices, skipping \r\n but recording mapping
    chars = []
    idx_map = []  # position in clean string -> original char index
    clean = []
    for i in range(start, n_chars):
        try:
            c = tp.get_text_range(i, 1)
        except Exception:
            c = ""
        if c in ("\r", "\n", "\t"):
            continue
        chars.append(c)
        idx_map.append(i)
        clean.append(c)
    s = "".join(clean)
    q = norm(quote)
    pos = s.find(q)
    if pos < 0:
        return None
    # union of charboxes from pos to pos+len(q)
    union = None
    for k in range(pos, pos + len(q)):
        box = None
        try:
            box = tp.get_charbox(idx_map[k])
        except Exception:
            pass
        if box:
            l, t, r, b = box
            if union is None:
                union = [l, t, r, b]
            else:
                union[0] = min(union[0], l)
                union[1] = min(union[1], t)
                union[2] = max(union[2], r)
                union[3] = max(union[3], b)
    return union, s, pos

if __name__ == "__main__":
    path = sys.argv[1]
    page_no = int(sys.argv[2]) - 1
    quote = sys.argv[3]
    doc = pdfium.PdfDocument(path)
    page = doc[page_no]
    tp = page.get_textpage()
    n = tp.count_chars()
    res = find_quote(tp, n, quote)
    if res is None:
        print("NOT FOUND")
    else:
        union, s, pos = res
        print("FOUND bbox:", [round(v, 2) for v in union])
        print("page size:", [round(v, 2) for v in page.get_size()])
