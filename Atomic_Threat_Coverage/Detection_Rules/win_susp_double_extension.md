| Title                | Suspicious Double Extension                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1193: Spearphishing Attachment](https://attack.mitre.org/techniques/T1193)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
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
description: Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns
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





### es-qs
    
```
Image.keyword:(*.doc.exe *.docx.exe *.xls.exe *.xlsx.exe *.ppt.exe *.pptx.exe *.rtf.exe *.pdf.exe *.txt.exe *\\ \\ \\ \\ \\ \\ .exe *______.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Double-Extension <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Double Extension",\n    "description": "Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns",\n    "tags": [\n      "attack.initial_access",\n      "attack.t1193"\n    ],\n    "query": "Image.keyword:(*.doc.exe *.docx.exe *.xls.exe *.xlsx.exe *.ppt.exe *.pptx.exe *.rtf.exe *.pdf.exe *.txt.exe *\\\\ \\\\ \\\\ \\\\ \\\\ \\\\ .exe *______.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "Image.keyword:(*.doc.exe *.docx.exe *.xls.exe *.xlsx.exe *.ppt.exe *.pptx.exe *.rtf.exe *.pdf.exe *.txt.exe *\\\\ \\\\ \\\\ \\\\ \\\\ \\\\ .exe *______.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Double Extension\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image:("*.doc.exe" "*.docx.exe" "*.xls.exe" "*.xlsx.exe" "*.ppt.exe" "*.pptx.exe" "*.rtf.exe" "*.pdf.exe" "*.txt.exe" "*      .exe" "*______.exe")
```


### splunk
    
```
(Image="*.doc.exe" OR Image="*.docx.exe" OR Image="*.xls.exe" OR Image="*.xlsx.exe" OR Image="*.ppt.exe" OR Image="*.pptx.exe" OR Image="*.rtf.exe" OR Image="*.pdf.exe" OR Image="*.txt.exe" OR Image="*      .exe" OR Image="*______.exe")
```


### logpoint
    
```
Image IN ["*.doc.exe", "*.docx.exe", "*.xls.exe", "*.xlsx.exe", "*.ppt.exe", "*.pptx.exe", "*.rtf.exe", "*.pdf.exe", "*.txt.exe", "*      .exe", "*______.exe"]
```


### grep
    
```
grep -P '^(?:.*.*\\.doc\\.exe|.*.*\\.docx\\.exe|.*.*\\.xls\\.exe|.*.*\\.xlsx\\.exe|.*.*\\.ppt\\.exe|.*.*\\.pptx\\.exe|.*.*\\.rtf\\.exe|.*.*\\.pdf\\.exe|.*.*\\.txt\\.exe|.*.*      \\.exe|.*.*______\\.exe)'
```



