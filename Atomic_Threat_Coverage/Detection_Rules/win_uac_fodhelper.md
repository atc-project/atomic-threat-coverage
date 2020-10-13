| Title                    | Bypass UAC via Fodhelper.exe       |
|:-------------------------|:------------------|
| **Description**          | Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1548.002: Bypass User Access Control](https://attack.mitre.org/techniques/T1548/002)</li><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1548.002: Bypass User Access Control](../Triggers/T1548.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate use of fodhelper.exe utility by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/e491ce22-792f-11e9-8f5c-d46d6d62a49e.html](https://eqllib.readthedocs.io/en/latest/analytics/e491ce22-792f-11e9-8f5c-d46d6d62a49e.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1088/T1088.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1088/T1088.md)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community |


## Detection Rules

### Sigma rule

```
title: Bypass UAC via Fodhelper.exe
id: 7f741dcf-fc22-4759-87b4-9ae8376676a2
description: Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/e491ce22-792f-11e9-8f5c-d46d6d62a49e.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1088/T1088.md
tags:
    - attack.privilege_escalation
    - attack.t1548.002
    - attack.t1088      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\fodhelper.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legitimate use of fodhelper.exe utility by legitimate user
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "ParentImage.*.*\\fodhelper.exe" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.ParentImage.keyword:*\\fodhelper.exe
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7f741dcf-fc22-4759-87b4-9ae8376676a2 <<EOF
{
  "metadata": {
    "title": "Bypass UAC via Fodhelper.exe",
    "description": "Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1548.002",
      "attack.t1088"
    ],
    "query": "winlog.event_data.ParentImage.keyword:*\\\\fodhelper.exe"
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
                    "query": "winlog.event_data.ParentImage.keyword:*\\\\fodhelper.exe",
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
        "subject": "Sigma Rule 'Bypass UAC via Fodhelper.exe'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n CommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
ParentImage.keyword:*\\fodhelper.exe
```


### splunk
    
```
ParentImage="*\\fodhelper.exe" | table ComputerName,User,CommandLine
```


### logpoint
    
```
ParentImage="*\\fodhelper.exe"
```


### grep
    
```
grep -P '^.*\fodhelper\.exe'
```



