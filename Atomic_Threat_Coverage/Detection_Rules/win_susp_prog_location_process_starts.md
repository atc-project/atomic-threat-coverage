| Title                    | Suspicious Program Location Process Starts       |
|:-------------------------|:------------------|
| **Description**          | Detects programs running in suspicious files system locations |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0001_4688_windows_process_creation](../Data_Needed/DN0001_4688_windows_process_creation.md)</li><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Program Location Process Starts
id: f50bfd8b-e2a3-4c15-9373-7900b5a4c6d5
status: experimental
description: Detects programs running in suspicious files system locations
references:
    - https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2019/01/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\$Recycle.bin'
            - '*\Users\Public\\*'
            - 'C:\Perflogs\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
            - '*\Windows\debug\\*'
    condition: selection
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\$Recycle.bin" -or $_.message -match "Image.*.*\\Users\\Public\\.*" -or $_.message -match "Image.*C:\\Perflogs\\.*" -or $_.message -match "Image.*.*\\Windows\\Fonts\\.*" -or $_.message -match "Image.*.*\\Windows\\IME\\.*" -or $_.message -match "Image.*.*\\Windows\\addins\\.*" -or $_.message -match "Image.*.*\\Windows\\debug\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:(*\\$Recycle.bin OR *\\Users\\Public\\* OR C\:\\Perflogs\\* OR *\\Windows\\Fonts\\* OR *\\Windows\\IME\\* OR *\\Windows\\addins\\* OR *\\Windows\\debug\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f50bfd8b-e2a3-4c15-9373-7900b5a4c6d5 <<EOF
{
  "metadata": {
    "title": "Suspicious Program Location Process Starts",
    "description": "Detects programs running in suspicious files system locations",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036"
    ],
    "query": "winlog.event_data.Image.keyword:(*\\\\$Recycle.bin OR *\\\\Users\\\\Public\\\\* OR C\\:\\\\Perflogs\\\\* OR *\\\\Windows\\\\Fonts\\\\* OR *\\\\Windows\\\\IME\\\\* OR *\\\\Windows\\\\addins\\\\* OR *\\\\Windows\\\\debug\\\\*)"
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
                    "query": "winlog.event_data.Image.keyword:(*\\\\$Recycle.bin OR *\\\\Users\\\\Public\\\\* OR C\\:\\\\Perflogs\\\\* OR *\\\\Windows\\\\Fonts\\\\* OR *\\\\Windows\\\\IME\\\\* OR *\\\\Windows\\\\addins\\\\* OR *\\\\Windows\\\\debug\\\\*)",
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
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Suspicious Program Location Process Starts'",
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
Image.keyword:(*\\$Recycle.bin *\\Users\\Public\\* C\:\\Perflogs\\* *\\Windows\\Fonts\\* *\\Windows\\IME\\* *\\Windows\\addins\\* *\\Windows\\debug\\*)
```


### splunk
    
```
(Image="*\\$Recycle.bin" OR Image="*\\Users\\Public\\*" OR Image="C:\\Perflogs\\*" OR Image="*\\Windows\\Fonts\\*" OR Image="*\\Windows\\IME\\*" OR Image="*\\Windows\\addins\\*" OR Image="*\\Windows\\debug\\*")
```


### logpoint
    
```
(event_id="1" Image IN ["*\\$Recycle.bin", "*\\Users\\Public\\*", "C:\\Perflogs\\*", "*\\Windows\\Fonts\\*", "*\\Windows\\IME\\*", "*\\Windows\\addins\\*", "*\\Windows\\debug\\*"])
```


### grep
    
```
grep -P '^(?:.*.*\\$Recycle\.bin|.*.*\Users\Public\\.*|.*C:\Perflogs\\.*|.*.*\Windows\Fonts\\.*|.*.*\Windows\IME\\.*|.*.*\Windows\addins\\.*|.*.*\Windows\debug\\.*)'
```



