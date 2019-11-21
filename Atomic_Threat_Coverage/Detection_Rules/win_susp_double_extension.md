| Title                | Suspicious Double Extension                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1193: Spearphishing Attachment](https://attack.mitre.org/techniques/T1193)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1193: Spearphishing Attachment](../Triggers/T1193.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html](https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html)</li><li>[https://twitter.com/blackorbird/status/1140519090961825792](https://twitter.com/blackorbird/status/1140519090961825792)</li></ul>  |
| Author               | Florian Roth (rule), @blu3_team (idea) |


## Detection Rules

### Sigma rule

```
title: Suspicious Double Extension
id: 1cdd9a09-06c9-4769-99ff-626e2b3991b8
description: Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable
    file in spear phishing campaigns
references:
    - https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html
    - https://twitter.com/blackorbird/status/1140519090961825792
author: Florian Roth (rule), @blu3_team (idea)
date: 2019/06/26
tags:
    - attack.initial_access
    - attack.t1193
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 
            - '*.doc.exe'
            - '*.docx.exe'
            - '*.xls.exe'
            - '*.xlsx.exe'
            - '*.ppt.exe'
            - '*.pptx.exe'
            - '*.rtf.exe'
            - '*.pdf.exe'
            - '*.txt.exe'
            - '*      .exe'
            - '*______.exe'
    condition: selection
falsepositives: 
    - Unknown
level: critical

```





### splunk
    
```
(Image="*.doc.exe" OR Image="*.docx.exe" OR Image="*.xls.exe" OR Image="*.xlsx.exe" OR Image="*.ppt.exe" OR Image="*.pptx.exe" OR Image="*.rtf.exe" OR Image="*.pdf.exe" OR Image="*.txt.exe" OR Image="*      .exe" OR Image="*______.exe")
```



