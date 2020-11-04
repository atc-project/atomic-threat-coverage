| Title                    | Registry Persistence via Explorer Run Key       |
|:-------------------------|:------------------|
| **Description**          | Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/](https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>capec.270</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Registry Persistence via Explorer Run Key
id: b7916c2a-fa2f-4795-9477-32b731f70f11
status: experimental
description: Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder
author: Florian Roth
date: 2018/07/18
references:
    - https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: '*\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        Details: 
            - 'C:\Windows\Temp\\*'
            - 'C:\ProgramData\\*'
            - '*\AppData\\*'
            - 'C:\$Recycle.bin\\*'
            - 'C:\Temp\\*'
            - 'C:\Users\Public\\*'
            - 'C:\Users\Default\\*'
    condition: selection
tags:
    - attack.persistence
    - attack.t1060
    - capec.270
fields:
    - Image
    - ParentImage
falsepositives:
    - Unknown
level: high


```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and $_.message -match "TargetObject.*.*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" -and ($_.message -match "Details.*C:\\Windows\\Temp\\.*" -or $_.message -match "Details.*C:\\ProgramData\\.*" -or $_.message -match "Details.*.*\\AppData\\.*" -or $_.message -match "Details.*C:\\$Recycle.bin\\.*" -or $_.message -match "Details.*C:\\Temp\\.*" -or $_.message -match "Details.*C:\\Users\\Public\\.*" -or $_.message -match "Details.*C:\\Users\\Default\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run AND winlog.event_data.Details.keyword:(C\:\\Windows\\Temp\\* OR C\:\\ProgramData\\* OR *\\AppData\\* OR C\:\\$Recycle.bin\\* OR C\:\\Temp\\* OR C\:\\Users\\Public\\* OR C\:\\Users\\Default\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b7916c2a-fa2f-4795-9477-32b731f70f11 <<EOF
{
  "metadata": {
    "title": "Registry Persistence via Explorer Run Key",
    "description": "Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder",
    "tags": [
      "attack.persistence",
      "attack.t1060",
      "capec.270"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run AND winlog.event_data.Details.keyword:(C\\:\\\\Windows\\\\Temp\\\\* OR C\\:\\\\ProgramData\\\\* OR *\\\\AppData\\\\* OR C\\:\\\\$Recycle.bin\\\\* OR C\\:\\\\Temp\\\\* OR C\\:\\\\Users\\\\Public\\\\* OR C\\:\\\\Users\\\\Default\\\\*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run AND winlog.event_data.Details.keyword:(C\\:\\\\Windows\\\\Temp\\\\* OR C\\:\\\\ProgramData\\\\* OR *\\\\AppData\\\\* OR C\\:\\\\$Recycle.bin\\\\* OR C\\:\\\\Temp\\\\* OR C\\:\\\\Users\\\\Public\\\\* OR C\\:\\\\Users\\\\Default\\\\*))",
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
        "subject": "Sigma Rule 'Registry Persistence via Explorer Run Key'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      Image = {{_source.Image}}\nParentImage = {{_source.ParentImage}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"13" AND TargetObject.keyword:*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run AND Details.keyword:(C\:\\Windows\\Temp\\* C\:\\ProgramData\\* *\\AppData\\* C\:\\$Recycle.bin\\* C\:\\Temp\\* C\:\\Users\\Public\\* C\:\\Users\\Default\\*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" TargetObject="*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" (Details="C:\\Windows\\Temp\\*" OR Details="C:\\ProgramData\\*" OR Details="*\\AppData\\*" OR Details="C:\\$Recycle.bin\\*" OR Details="C:\\Temp\\*" OR Details="C:\\Users\\Public\\*" OR Details="C:\\Users\\Default\\*")) | table Image,ParentImage
```


### logpoint
    
```
(event_id="13" TargetObject="*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" Details IN ["C:\\Windows\\Temp\\*", "C:\\ProgramData\\*", "*\\AppData\\*", "C:\\$Recycle.bin\\*", "C:\\Temp\\*", "C:\\Users\\Public\\*", "C:\\Users\\Default\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*.*\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run)(?=.*(?:.*C:\Windows\Temp\\.*|.*C:\ProgramData\\.*|.*.*\AppData\\.*|.*C:\\$Recycle\.bin\\.*|.*C:\Temp\\.*|.*C:\Users\Public\\.*|.*C:\Users\Default\\.*)))'
```



