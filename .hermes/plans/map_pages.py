#!/usr/bin/env python3
"""Dump per-page first lines for each PDF to map findings to pages."""
import pypdfium2 as pdfium

pdfs = {
    "LIT": r"C:\Dev\CyberZen\.hermes\plans\pdfs\literature_review.pdf",
    "FA": r"C:\Dev\CyberZen\.hermes\plans\pdfs\framework_assessment.pdf",
    "DC": r"C:\Dev\CyberZen\.hermes\plans\pdfs\data_compendium.pdf",
}

for tag, path in pdfs.items():
    doc = pdfium.PdfDocument(path)
    print(f"\n===== {tag} ({len(doc)} pages) =====")
    for i in range(len(doc)):
        page = doc[i]
        text = page.get_textpage().get_text_bounded()
        # collapse whitespace, take first 140 chars of non-empty content
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        head = " | ".join(lines[:3])[:140] if lines else "(empty)"
        print(f"p{i+1:02d}: {head}")
    doc.close()
