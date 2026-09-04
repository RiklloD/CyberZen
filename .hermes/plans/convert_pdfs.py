#!/usr/bin/env python3
"""Convert the three Milestone 1 docx files to PDF via Word COM (preserves layout)."""
import win32com.client
import os

docs = {
    r"G:\Mon Drive\ZHermes Agent\Bachelor Thesis\Milestone1_Literature_Review.docx": r"C:\Dev\CyberZen\.hermes\plans\pdfs\literature_review.pdf",
    r"G:\Mon Drive\ZHermes Agent\Bachelor Thesis\drafts\Milestone1_Framework_Assessment_V3.docx": r"C:\Dev\CyberZen\.hermes\plans\pdfs\framework_assessment.pdf",
    r"G:\Mon Drive\ZHermes Agent\Bachelor Thesis\Milestone1_Data_Compendium.docx": r"C:\Dev\CyberZen\.hermes\plans\pdfs\data_compendium.pdf",
}

os.makedirs(r"C:\Dev\CyberZen\.hermes\plans\pdfs", exist_ok=True)

word = win32com.client.DispatchEx("Word.Application")
word.Visible = False
word.DisplayAlerts = 0
try:
    for src, dst in docs.items():
        if not os.path.exists(src):
            print("MISSING:", src)
            continue
        doc = word.Documents.Open(src, ReadOnly=True)
        doc.SaveAs(dst, FileFormat=17)  # wdFormatPDF
        doc.Close(False)
        print("OK:", dst, os.path.getsize(dst), "bytes")
finally:
    word.Quit()
print("DONE")
