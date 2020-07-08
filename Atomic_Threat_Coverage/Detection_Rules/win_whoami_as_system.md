| Title                    | Run Whoami as SYSTEM       |
|:-------------------------|:------------------|
| **Description**          | Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1033: System Owner/User Discovery](../Triggers/T1033.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov |


## Detection Rules

### Sigma rule

```
title: Run Whoami as SYSTEM
id: 80167ada-7a12-41ed-b8e9-aa47195c66a1
status: experimental
description: Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation.
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
author: Teymur Kheirkhabarov
date: 2019/10/23
modified: 2019/11/11
tags:
    - attack.discovery
    - attack.privilege_escalation
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: 'NT AUTHORITY\SYSTEM'
        Image|endswith: '\whoami.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "User.*NT AUTHORITY\\SYSTEM" -and $_.message -match "Image.*.*\\whoami.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.User:"NT\ AUTHORITY\\SYSTEM" AND winlog.event_data.Image.keyword:*\\whoami.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/80167ada-7a12-41ed-b8e9-aa47195c66a1 <<EOF
{
  "metadata": {
    "title": "Run Whoami as SYSTEM",
    "description": "Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation.",
    "tags": [
      "attack.discovery",
      "attack.privilege_escalation",
      "attack.t1033"
    ],
    "query": "(winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\" AND winlog.event_data.Image.keyword:*\\\\whoami.exe)"
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
                    "query": "(winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\" AND winlog.event_data.Image.keyword:*\\\\whoami.exe)",
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
        "subject": "Sigma Rule 'Run Whoami as SYSTEM'",
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
(User:"NT AUTHORITY\\SYSTEM" AND Image.keyword:*\\whoami.exe)
```


### splunk
    
```
(User="NT AUTHORITY\\SYSTEM" Image="*\\whoami.exe")
```


### logpoint
    
```
(event_id="1" User="NT AUTHORITY\\SYSTEM" Image="*\\whoami.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*NT AUTHORITY\SYSTEM)(?=.*.*\whoami\.exe))'
```



