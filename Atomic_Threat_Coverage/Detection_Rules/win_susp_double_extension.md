| Title                    | Suspicious Double Extension       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1193: Spearphishing Attachment](https://attack.mitre.org/techniques/T1193)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1193: Spearphishing Attachment](../Triggers/T1193.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html](https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html)</li><li>[https://twitter.com/blackorbird/status/1140519090961825792](https://twitter.com/blackorbird/status/1140519090961825792)</li></ul>  |
| **Author**               | Florian Roth (rule), @blu3_team (idea) |


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





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*.doc.exe" -or $_.message -match "Image.*.*.docx.exe" -or $_.message -match "Image.*.*.xls.exe" -or $_.message -match "Image.*.*.xlsx.exe" -or $_.message -match "Image.*.*.ppt.exe" -or $_.message -match "Image.*.*.pptx.exe" -or $_.message -match "Image.*.*.rtf.exe" -or $_.message -match "Image.*.*.pdf.exe" -or $_.message -match "Image.*.*.txt.exe" -or $_.message -match "Image.*.*      .exe" -or $_.message -match "Image.*.*______.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:(*.doc.exe OR *.docx.exe OR *.xls.exe OR *.xlsx.exe OR *.ppt.exe OR *.pptx.exe OR *.rtf.exe OR *.pdf.exe OR *.txt.exe OR *\ \ \ \ \ \ .exe OR *______.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1cdd9a09-06c9-4769-99ff-626e2b3991b8 <<EOF
{
  "metadata": {
    "title": "Suspicious Double Extension",
    "description": "Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns",
    "tags": [
      "attack.initial_access",
      "attack.t1193"
    ],
    "query": "winlog.event_data.Image.keyword:(*.doc.exe OR *.docx.exe OR *.xls.exe OR *.xlsx.exe OR *.ppt.exe OR *.pptx.exe OR *.rtf.exe OR *.pdf.exe OR *.txt.exe OR *\\ \\ \\ \\ \\ \\ .exe OR *______.exe)"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "winlog.event_data.Image.keyword:(*.doc.exe OR *.docx.exe OR *.xls.exe OR *.xlsx.exe OR *.ppt.exe OR *.pptx.exe OR *.rtf.exe OR *.pdf.exe OR *.txt.exe OR *\\ \\ \\ \\ \\ \\ .exe OR *______.exe)",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Suspicious Double Extension'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
Image.keyword:(*.doc.exe *.docx.exe *.xls.exe *.xlsx.exe *.ppt.exe *.pptx.exe *.rtf.exe *.pdf.exe *.txt.exe *      .exe *______.exe)
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
grep -P '^(?:.*.*\.doc\.exe|.*.*\.docx\.exe|.*.*\.xls\.exe|.*.*\.xlsx\.exe|.*.*\.ppt\.exe|.*.*\.pptx\.exe|.*.*\.rtf\.exe|.*.*\.pdf\.exe|.*.*\.txt\.exe|.*.*      \.exe|.*.*______\.exe)'
```



