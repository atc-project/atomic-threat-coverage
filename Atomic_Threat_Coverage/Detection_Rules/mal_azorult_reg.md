| Title                    | Registy Entries For Azorult Malware       |
|:-------------------------|:------------------|
| **Description**          | Detects the presence of a registry key created during Azorult execution |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.azoruit.a](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.azoruit.a)</li></ul>  |
| **Author**               | Trent Liffick |


## Detection Rules

### Sigma rule

```
title: Registy Entries For Azorult Malware
id: f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7
description: Detects the presence of a registry key created during Azorult execution
status: experimental
references:
  - https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.azoruit.a
author: Trent Liffick
date: 2020/05/08
tags:
  - attack.execution
  - attack.t1112
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 12
      - 13
    TargetObject:
      - '*SYSTEM\\*\services\localNETService'
  condition: selection
fields:
  - Image
  - TargetObject
  - TargetDetails
falsepositives:
  - unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13") -and ($_.message -match "TargetObject.*.*SYSTEM\\.*\\services\\localNETService")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:("12" OR "13") AND winlog.event_data.TargetObject.keyword:(*SYSTEM\\*\\services\\localNETService))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7 <<EOF
{
  "metadata": {
    "title": "Registy Entries For Azorult Malware",
    "description": "Detects the presence of a registry key created during Azorult execution",
    "tags": [
      "attack.execution",
      "attack.t1112"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:(\"12\" OR \"13\") AND winlog.event_data.TargetObject.keyword:(*SYSTEM\\\\*\\\\services\\\\localNETService))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:(\"12\" OR \"13\") AND winlog.event_data.TargetObject.keyword:(*SYSTEM\\\\*\\\\services\\\\localNETService))",
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
        "subject": "Sigma Rule 'Registy Entries For Azorult Malware'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n        Image = {{_source.Image}}\n TargetObject = {{_source.TargetObject}}\nTargetDetails = {{_source.TargetDetails}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:("12" "13") AND TargetObject.keyword:(*SYSTEM\\*\\services\\localNETService))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="12" OR EventCode="13") (TargetObject="*SYSTEM\\*\\services\\localNETService")) | table Image,TargetObject,TargetDetails
```


### logpoint
    
```
(event_id IN ["12", "13"] TargetObject IN ["*SYSTEM\\*\\services\\localNETService"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*12|.*13))(?=.*(?:.*.*SYSTEM\\.*\services\localNETService)))'
```



