import win32com.client, os
src=r'G:\Mon Drive\ZHermes Agent\Bachelor Thesis\presentations\Milestone1_Findings_Deck.pptx'
dst=r'C:\Dev\CyberZen\.hermes\plans\clean_deck_verify.pdf'
ppt=win32com.client.DispatchEx('PowerPoint.Application')
ppt.Visible=1
try:
    pres=ppt.Presentations.Open(src, WithWindow=False, ReadOnly=True)
    pres.SaveAs(dst, 32)  # ppSaveAsPDF
    pres.Close()
finally:
    ppt.Quit()
print('saved',dst,os.path.getsize(dst))
