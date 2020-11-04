| Title                    | Registry Persistence Mechanisms       |
|:-------------------------|:------------------|
| **Description**          | Detects persistence registry keys |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1183: Image File Execution Options Injection](https://attack.mitre.org/techniques/T1183)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1183: Image File Execution Options Injection](../Triggers/T1183.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)</li></ul>  |
| **Author**               | Karneades |
| Other Tags           | <ul><li>car.2013-01-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Registry Persistence Mechanisms
id: 36803969-5421-41ec-b92f-8500f79c23b0
description: Detects persistence registry keys
references:
    - https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
date: 2018/04/11
author: Karneades
logsource:
    product: windows
    service: sysmon
detection:
    selection_reg1:
        EventID: 13
        TargetObject:
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\*\GlobalFlag'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\\*\ReportingMode'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\\*\MonitorProcess'
        EventType: SetValue
    condition: selection_reg1
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.defense_evasion
    - attack.t1183
    - car.2013-01-002
falsepositives:
    - unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and ($_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\.*\\GlobalFlag" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\.*\\ReportingMode" -or $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\.*\\MonitorProcess") -and $_.message -match "EventType.*SetValue") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:(*\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Image\ File\ Execution\ Options\\*\\GlobalFlag OR *\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\SilentProcessExit\\*\\ReportingMode OR *\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess) AND winlog.event_data.EventType:"SetValue")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/36803969-5421-41ec-b92f-8500f79c23b0 <<EOF
{
  "metadata": {
    "title": "Registry Persistence Mechanisms",
    "description": "Detects persistence registry keys",
    "tags": [
      "attack.privilege_escalation",
      "attack.persistence",
      "attack.defense_evasion",
      "attack.t1183",
      "car.2013-01-002"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\*\\\\GlobalFlag OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\ReportingMode OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\MonitorProcess) AND winlog.event_data.EventType:\"SetValue\")"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\*\\\\GlobalFlag OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\ReportingMode OR *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\MonitorProcess) AND winlog.event_data.EventType:\"SetValue\")",
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
        "subject": "Sigma Rule 'Registry Persistence Mechanisms'",
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
(EventID:"13" AND TargetObject.keyword:(*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\GlobalFlag *\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\ReportingMode *\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess) AND EventType:"SetValue")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\GlobalFlag" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\ReportingMode" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess") EventType="SetValue")
```


### logpoint
    
```
(event_id="13" TargetObject IN ["*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\GlobalFlag", "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\ReportingMode", "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess"] EventType="SetValue")
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\.*\GlobalFlag|.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\\.*\ReportingMode|.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\\.*\MonitorProcess))(?=.*SetValue))'
```



