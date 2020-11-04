| Title                    | Suspicious Program Location with Network Connections       |
|:-------------------------|:------------------|
| **Description**          | Detects programs with network connections running in suspicious files system locations |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Program Location with Network Connections
id: 7b434893-c57d-4f41-908d-6a17bf1ae98f
status: experimental
description: Detects programs with network connections running in suspicious files system locations
references:
    - https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo
author: Florian Roth
date: 2017/03/19
logsource:
    product: windows
    service: sysmon
    definition: 'Use the following config to generate the necessary Event ID 3 Network Connection events'
detection:
    selection:
        EventID: 3
        Image: 
            # - '*\ProgramData\\*'  # too many false positives, e.g. with Webex for Windows
            - '*\$Recycle.bin'
            - '*\Users\All Users\\*'
            - '*\Users\Default\\*'
            - '*\Users\Public\\*'
            - '*\Users\Contacts\\*'
            - '*\Users\Searches\\*' 
            - 'C:\Perflogs\\*'
            - '*\config\systemprofile\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
    condition: selection
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and ($_.message -match "Image.*.*\\$Recycle.bin" -or $_.message -match "Image.*.*\\Users\\All Users\\.*" -or $_.message -match "Image.*.*\\Users\\Default\\.*" -or $_.message -match "Image.*.*\\Users\\Public\\.*" -or $_.message -match "Image.*.*\\Users\\Contacts\\.*" -or $_.message -match "Image.*.*\\Users\\Searches\\.*" -or $_.message -match "Image.*C:\\Perflogs\\.*" -or $_.message -match "Image.*.*\\config\\systemprofile\\.*" -or $_.message -match "Image.*.*\\Windows\\Fonts\\.*" -or $_.message -match "Image.*.*\\Windows\\IME\\.*" -or $_.message -match "Image.*.*\\Windows\\addins\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"3" AND winlog.event_data.Image.keyword:(*\\$Recycle.bin OR *\\Users\\All\ Users\\* OR *\\Users\\Default\\* OR *\\Users\\Public\\* OR *\\Users\\Contacts\\* OR *\\Users\\Searches\\* OR C\:\\Perflogs\\* OR *\\config\\systemprofile\\* OR *\\Windows\\Fonts\\* OR *\\Windows\\IME\\* OR *\\Windows\\addins\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7b434893-c57d-4f41-908d-6a17bf1ae98f <<EOF
{
  "metadata": {
    "title": "Suspicious Program Location with Network Connections",
    "description": "Detects programs with network connections running in suspicious files system locations",
    "tags": "",
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"3\" AND winlog.event_data.Image.keyword:(*\\\\$Recycle.bin OR *\\\\Users\\\\All\\ Users\\\\* OR *\\\\Users\\\\Default\\\\* OR *\\\\Users\\\\Public\\\\* OR *\\\\Users\\\\Contacts\\\\* OR *\\\\Users\\\\Searches\\\\* OR C\\:\\\\Perflogs\\\\* OR *\\\\config\\\\systemprofile\\\\* OR *\\\\Windows\\\\Fonts\\\\* OR *\\\\Windows\\\\IME\\\\* OR *\\\\Windows\\\\addins\\\\*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"3\" AND winlog.event_data.Image.keyword:(*\\\\$Recycle.bin OR *\\\\Users\\\\All\\ Users\\\\* OR *\\\\Users\\\\Default\\\\* OR *\\\\Users\\\\Public\\\\* OR *\\\\Users\\\\Contacts\\\\* OR *\\\\Users\\\\Searches\\\\* OR C\\:\\\\Perflogs\\\\* OR *\\\\config\\\\systemprofile\\\\* OR *\\\\Windows\\\\Fonts\\\\* OR *\\\\Windows\\\\IME\\\\* OR *\\\\Windows\\\\addins\\\\*))",
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
        "subject": "Sigma Rule 'Suspicious Program Location with Network Connections'",
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
(EventID:"3" AND Image.keyword:(*\\$Recycle.bin *\\Users\\All Users\\* *\\Users\\Default\\* *\\Users\\Public\\* *\\Users\\Contacts\\* *\\Users\\Searches\\* C\:\\Perflogs\\* *\\config\\systemprofile\\* *\\Windows\\Fonts\\* *\\Windows\\IME\\* *\\Windows\\addins\\*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="3" (Image="*\\$Recycle.bin" OR Image="*\\Users\\All Users\\*" OR Image="*\\Users\\Default\\*" OR Image="*\\Users\\Public\\*" OR Image="*\\Users\\Contacts\\*" OR Image="*\\Users\\Searches\\*" OR Image="C:\\Perflogs\\*" OR Image="*\\config\\systemprofile\\*" OR Image="*\\Windows\\Fonts\\*" OR Image="*\\Windows\\IME\\*" OR Image="*\\Windows\\addins\\*"))
```


### logpoint
    
```
(event_id="3" Image IN ["*\\$Recycle.bin", "*\\Users\\All Users\\*", "*\\Users\\Default\\*", "*\\Users\\Public\\*", "*\\Users\\Contacts\\*", "*\\Users\\Searches\\*", "C:\\Perflogs\\*", "*\\config\\systemprofile\\*", "*\\Windows\\Fonts\\*", "*\\Windows\\IME\\*", "*\\Windows\\addins\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*(?:.*.*\\$Recycle\.bin|.*.*\Users\All Users\\.*|.*.*\Users\Default\\.*|.*.*\Users\Public\\.*|.*.*\Users\Contacts\\.*|.*.*\Users\Searches\\.*|.*C:\Perflogs\\.*|.*.*\config\systemprofile\\.*|.*.*\Windows\Fonts\\.*|.*.*\Windows\IME\\.*|.*.*\Windows\addins\\.*)))'
```



