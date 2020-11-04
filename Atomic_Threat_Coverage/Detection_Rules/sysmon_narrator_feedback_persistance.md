| Title                    | Narrator's Feedback-Hub Persistence       |
|:-------------------------|:------------------|
| **Description**          | Detects abusing Windows 10 Narrator's Feedback-Hub |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html](https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html)</li></ul>  |
| **Author**               | Dmitriy Lifanov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Narrator's Feedback-Hub Persistence
id: f663a6d9-9d1b-49b8-b2b1-0637914d199a
description: Detects abusing Windows 10 Narrator's Feedback-Hub
references:
    - https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html
tags:
    - attack.persistence
    - attack.t1060
author: Dmitriy Lifanov, oscd.community
status: experimental
date: 2019/10/25
modified: 2019/11/10
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 12
        EventType: DeleteValue
        TargetObject|endswith: '\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\DelegateExecute'
    selection2:
        EventID: 13
        TargetObject|endswith: '\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\(Default)'
    condition: 1 of them
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -and $_.message -match "EventType.*DeleteValue" -and $_.message -match "TargetObject.*.*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\DelegateExecute") -or ($_.ID -eq "13" -and $_.message -match "TargetObject.*.*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\(Default)"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND ((winlog.event_id:"12" AND winlog.event_data.EventType:"DeleteValue" AND winlog.event_data.TargetObject.keyword:*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\DelegateExecute) OR (winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\\(Default\))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f663a6d9-9d1b-49b8-b2b1-0637914d199a <<EOF
{
  "metadata": {
    "title": "Narrator's Feedback-Hub Persistence",
    "description": "Detects abusing Windows 10 Narrator's Feedback-Hub",
    "tags": [
      "attack.persistence",
      "attack.t1060"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND ((winlog.event_id:\"12\" AND winlog.event_data.EventType:\"DeleteValue\" AND winlog.event_data.TargetObject.keyword:*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\DelegateExecute) OR (winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\\\(Default\\))))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND ((winlog.event_id:\"12\" AND winlog.event_data.EventType:\"DeleteValue\" AND winlog.event_data.TargetObject.keyword:*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\DelegateExecute) OR (winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:*\\\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\\\Shell\\\\open\\\\command\\\\\\(Default\\))))",
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
        "subject": "Sigma Rule 'Narrator's Feedback-Hub Persistence'",
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
((EventID:"12" AND EventType:"DeleteValue" AND TargetObject.keyword:*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\DelegateExecute) OR (EventID:"13" AND TargetObject.keyword:*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\\(Default\)))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" ((EventCode="12" EventType="DeleteValue" TargetObject="*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\DelegateExecute") OR (EventCode="13" TargetObject="*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\(Default)")))
```


### logpoint
    
```
((event_id="12" EventType="DeleteValue" TargetObject="*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\DelegateExecute") OR (event_id="13" TargetObject="*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\(Default)"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*12)(?=.*DeleteValue)(?=.*.*\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\DelegateExecute))|.*(?:.*(?=.*13)(?=.*.*\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\\(Default\)))))'
```



