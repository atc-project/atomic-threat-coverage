| Title                    | New RUN Key Pointing to Suspicious Folder       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious new RUN key element pointing to an executable in a suspicious folder |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Software using the AppData folders for updates</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</li></ul>  |
| **Author**               | Florian Roth, Markus Neis |


## Detection Rules

### Sigma rule

```
title: New RUN Key Pointing to Suspicious Folder
id: 02ee49e2-e294-4d0f-9278-f5b3212fc588
status: experimental
description: Detects suspicious new RUN key element pointing to an executable in a suspicious folder
references:
    - https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html
author: Florian Roth, Markus Neis
tags:
    - attack.persistence
    - attack.t1060
date: 2018/08/25
modified: 2020/02/26
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: 
            - '*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\*'
            - '*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\\*'
        Details:
            - '*C:\Windows\Temp\\*'
            - '*\AppData\\*'
            - '%AppData%\\*'
            - '*C:\$Recycle.bin\\*'
            - '*C:\Temp\\*'
            - '*C:\Users\Public\\*'
            - '%Public%\\*'
            - '*C:\Users\Default\\*'
            - '*C:\Users\Desktop\\*'
            - 'wscript*'
            - 'cscript*'
    filter:
        Details|contains:
          - '\AppData\Local\Microsoft\OneDrive\'  # OneDrive False Positives
    condition: selection and not filter
fields:
    - Image
falsepositives:
    - Software using the AppData folders for updates
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "13" -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\.*" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\.*") -and ($_.message -match "Details.*.*C:\\Windows\\Temp\\.*" -or $_.message -match "Details.*.*\\AppData\\.*" -or $_.message -match "Details.*%AppData%\\.*" -or $_.message -match "Details.*.*C:\\$Recycle.bin\\.*" -or $_.message -match "Details.*.*C:\\Temp\\.*" -or $_.message -match "Details.*.*C:\\Users\\Public\\.*" -or $_.message -match "Details.*%Public%\\.*" -or $_.message -match "Details.*.*C:\\Users\\Default\\.*" -or $_.message -match "Details.*.*C:\\Users\\Desktop\\.*" -or $_.message -match "Details.*wscript.*" -or $_.message -match "Details.*cscript.*")) -and  -not (($_.message -match "Details.*.*\\AppData\\Local\\Microsoft\\OneDrive\\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:(*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\* OR *\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*) AND winlog.event_data.Details.keyword:(*C\:\\Windows\\Temp\\* OR *\\AppData\\* OR %AppData%\\* OR *C\:\\$Recycle.bin\\* OR *C\:\\Temp\\* OR *C\:\\Users\\Public\\* OR %Public%\\* OR *C\:\\Users\\Default\\* OR *C\:\\Users\\Desktop\\* OR wscript* OR cscript*)) AND (NOT (winlog.event_data.Details.keyword:(*\\AppData\\Local\\Microsoft\\OneDrive\*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/02ee49e2-e294-4d0f-9278-f5b3212fc588 <<EOF
{
  "metadata": {
    "title": "New RUN Key Pointing to Suspicious Folder",
    "description": "Detects suspicious new RUN key element pointing to an executable in a suspicious folder",
    "tags": [
      "attack.persistence",
      "attack.t1060"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\* OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\*) AND winlog.event_data.Details.keyword:(*C\\:\\\\Windows\\\\Temp\\\\* OR *\\\\AppData\\\\* OR %AppData%\\\\* OR *C\\:\\\\$Recycle.bin\\\\* OR *C\\:\\\\Temp\\\\* OR *C\\:\\\\Users\\\\Public\\\\* OR %Public%\\\\* OR *C\\:\\\\Users\\\\Default\\\\* OR *C\\:\\\\Users\\\\Desktop\\\\* OR wscript* OR cscript*)) AND (NOT (winlog.event_data.Details.keyword:(*\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\*))))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\* OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\*) AND winlog.event_data.Details.keyword:(*C\\:\\\\Windows\\\\Temp\\\\* OR *\\\\AppData\\\\* OR %AppData%\\\\* OR *C\\:\\\\$Recycle.bin\\\\* OR *C\\:\\\\Temp\\\\* OR *C\\:\\\\Users\\\\Public\\\\* OR %Public%\\\\* OR *C\\:\\\\Users\\\\Default\\\\* OR *C\\:\\\\Users\\\\Desktop\\\\* OR wscript* OR cscript*)) AND (NOT (winlog.event_data.Details.keyword:(*\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\*))))",
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
        "subject": "Sigma Rule 'New RUN Key Pointing to Suspicious Folder'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nImage = {{_source.Image}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((EventID:"13" AND TargetObject.keyword:(*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\* *\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*) AND Details.keyword:(*C\:\\Windows\\Temp\\* *\\AppData\\* %AppData%\\* *C\:\\$Recycle.bin\\* *C\:\\Temp\\* *C\:\\Users\\Public\\* %Public%\\* *C\:\\Users\\Default\\* *C\:\\Users\\Desktop\\* wscript* cscript*)) AND (NOT (Details.keyword:(*\\AppData\\Local\\Microsoft\\OneDrive\*))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="13" (TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*") (Details="*C:\\Windows\\Temp\\*" OR Details="*\\AppData\\*" OR Details="%AppData%\\*" OR Details="*C:\\$Recycle.bin\\*" OR Details="*C:\\Temp\\*" OR Details="*C:\\Users\\Public\\*" OR Details="%Public%\\*" OR Details="*C:\\Users\\Default\\*" OR Details="*C:\\Users\\Desktop\\*" OR Details="wscript*" OR Details="cscript*")) NOT ((Details="*\\AppData\\Local\\Microsoft\\OneDrive\*"))) | table Image
```


### logpoint
    
```
((event_id="13" TargetObject IN ["*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*", "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*"] Details IN ["*C:\\Windows\\Temp\\*", "*\\AppData\\*", "%AppData%\\*", "*C:\\$Recycle.bin\\*", "*C:\\Temp\\*", "*C:\\Users\\Public\\*", "%Public%\\*", "*C:\\Users\\Default\\*", "*C:\\Users\\Desktop\\*", "wscript*", "cscript*"])  -(Details IN ["*\\AppData\\Local\\Microsoft\\OneDrive\*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*13)(?=.*(?:.*.*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\.*|.*.*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\\.*))(?=.*(?:.*.*C:\Windows\Temp\\.*|.*.*\AppData\\.*|.*%AppData%\\.*|.*.*C:\\$Recycle\.bin\\.*|.*.*C:\Temp\\.*|.*.*C:\Users\Public\\.*|.*%Public%\\.*|.*.*C:\Users\Default\\.*|.*.*C:\Users\Desktop\\.*|.*wscript.*|.*cscript.*))))(?=.*(?!.*(?:.*(?=.*(?:.*.*\AppData\Local\Microsoft\OneDrive\.*))))))'
```



