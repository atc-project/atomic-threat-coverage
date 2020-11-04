| Title                    | Execution in Non-Executable Folder       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious exection from an uncommon folder |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Execution in Non-Executable Folder
id: 3dfd06d2-eaf4-4532-9555-68aca59f57c4
status: experimental
description: Detects a suspicious exection from an uncommon folder
author: Florian Roth
date: 2019/01/16
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\$Recycle.bin'
            - '*\Users\All Users\\*'
            - '*\Users\Default\\*'
            - '*\Users\Public\\*'
            - 'C:\Perflogs\\*'
            - '*\config\systemprofile\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\$Recycle.bin" -or $_.message -match "Image.*.*\\Users\\All Users\\.*" -or $_.message -match "Image.*.*\\Users\\Default\\.*" -or $_.message -match "Image.*.*\\Users\\Public\\.*" -or $_.message -match "Image.*C:\\Perflogs\\.*" -or $_.message -match "Image.*.*\\config\\systemprofile\\.*" -or $_.message -match "Image.*.*\\Windows\\Fonts\\.*" -or $_.message -match "Image.*.*\\Windows\\IME\\.*" -or $_.message -match "Image.*.*\\Windows\\addins\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:(*\\$Recycle.bin OR *\\Users\\All\ Users\\* OR *\\Users\\Default\\* OR *\\Users\\Public\\* OR C\:\\Perflogs\\* OR *\\config\\systemprofile\\* OR *\\Windows\\Fonts\\* OR *\\Windows\\IME\\* OR *\\Windows\\addins\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3dfd06d2-eaf4-4532-9555-68aca59f57c4 <<EOF
{
  "metadata": {
    "title": "Execution in Non-Executable Folder",
    "description": "Detects a suspicious exection from an uncommon folder",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036"
    ],
    "query": "winlog.event_data.Image.keyword:(*\\\\$Recycle.bin OR *\\\\Users\\\\All\\ Users\\\\* OR *\\\\Users\\\\Default\\\\* OR *\\\\Users\\\\Public\\\\* OR C\\:\\\\Perflogs\\\\* OR *\\\\config\\\\systemprofile\\\\* OR *\\\\Windows\\\\Fonts\\\\* OR *\\\\Windows\\\\IME\\\\* OR *\\\\Windows\\\\addins\\\\*)"
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
                    "query": "winlog.event_data.Image.keyword:(*\\\\$Recycle.bin OR *\\\\Users\\\\All\\ Users\\\\* OR *\\\\Users\\\\Default\\\\* OR *\\\\Users\\\\Public\\\\* OR C\\:\\\\Perflogs\\\\* OR *\\\\config\\\\systemprofile\\\\* OR *\\\\Windows\\\\Fonts\\\\* OR *\\\\Windows\\\\IME\\\\* OR *\\\\Windows\\\\addins\\\\*)",
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
        "subject": "Sigma Rule 'Execution in Non-Executable Folder'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
Image.keyword:(*\\$Recycle.bin *\\Users\\All Users\\* *\\Users\\Default\\* *\\Users\\Public\\* C\:\\Perflogs\\* *\\config\\systemprofile\\* *\\Windows\\Fonts\\* *\\Windows\\IME\\* *\\Windows\\addins\\*)
```


### splunk
    
```
(Image="*\\$Recycle.bin" OR Image="*\\Users\\All Users\\*" OR Image="*\\Users\\Default\\*" OR Image="*\\Users\\Public\\*" OR Image="C:\\Perflogs\\*" OR Image="*\\config\\systemprofile\\*" OR Image="*\\Windows\\Fonts\\*" OR Image="*\\Windows\\IME\\*" OR Image="*\\Windows\\addins\\*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
Image IN ["*\\$Recycle.bin", "*\\Users\\All Users\\*", "*\\Users\\Default\\*", "*\\Users\\Public\\*", "C:\\Perflogs\\*", "*\\config\\systemprofile\\*", "*\\Windows\\Fonts\\*", "*\\Windows\\IME\\*", "*\\Windows\\addins\\*"]
```


### grep
    
```
grep -P '^(?:.*.*\\$Recycle\.bin|.*.*\Users\All Users\\.*|.*.*\Users\Default\\.*|.*.*\Users\Public\\.*|.*C:\Perflogs\\.*|.*.*\config\systemprofile\\.*|.*.*\Windows\Fonts\\.*|.*.*\Windows\IME\\.*|.*.*\Windows\addins\\.*)'
```



