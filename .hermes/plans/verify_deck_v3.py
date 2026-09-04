import win32com.client, os
src=r'C:\Dev\CyberZen\.hermes\plans\Milestone1_Findings_Deck_accurate_v3.pptx'
dst=r'C:\Dev\CyberZen\.hermes\plans\Milestone1_Findings_Deck_accurate_v3.pdf'
ppt=win32com.client.DispatchEx('PowerPoint.Application');ppt.Visible=1
try:
    pres=ppt.Presentations.Open(src, WithWindow=False, ReadOnly=True)
    pres.SaveAs(dst,32);pres.Close()
finally:ppt.Quit()
print(dst,os.path.getsize(dst))
